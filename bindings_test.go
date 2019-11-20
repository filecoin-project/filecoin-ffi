package go_sectorbuilder_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/stretchr/testify/assert"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
	"unsafe"

	sb "github.com/filecoin-project/go-sectorbuilder"
	"github.com/filecoin-project/go-sectorbuilder/sealed_sector_health"
	"github.com/filecoin-project/go-sectorbuilder/sealing_state"

	"github.com/stretchr/testify/require"
)

func TestSectorBuilderLifecycle(t *testing.T) {
	ticketA := sb.SealTicket{
		BlockHeight: 0,
		TicketBytes: [32]byte{5, 4, 2},
	}

	ticketB := sb.SealTicket{
		BlockHeight: 10,
		TicketBytes: [32]byte{1, 2, 3},
	}

	seedA := sb.SealSeed{
		BlockHeight: 50,
		TicketBytes: [32]byte{7, 4, 2},
	}

	seedB := sb.SealSeed{
		BlockHeight: 60,
		TicketBytes: [32]byte{9, 10, 11},
	}

	proverID := [32]byte{6, 7, 8}

	metadataDir := requireTempDirPath(t, "metadata")
	defer os.RemoveAll(metadataDir)

	sealedSectorDir := requireTempDirPath(t, "sealed-sectors")
	defer os.RemoveAll(sealedSectorDir)

	stagedSectorDir := requireTempDirPath(t, "staged-sectors")
	defer os.RemoveAll(stagedSectorDir)

	sectorCacheRootDir := requireTempDirPath(t, "sector-cache-root")
	defer os.RemoveAll(sectorCacheRootDir)

	ptr, err := sb.InitSectorBuilder(1024, 2, 0, metadataDir, proverID, sealedSectorDir, stagedSectorDir, sectorCacheRootDir, 1, 2)
	require.NoError(t, err)
	defer sb.DestroySectorBuilder(ptr)

	// verify that we've not yet sealed a sector
	sealedSectors, err := sb.GetAllSealedSectorsWithHealth(ptr)
	require.NoError(t, err)
	require.Equal(t, 0, len(sealedSectors), "expected to see zero sealed sectors")

	// compute the max user-bytes that can fit into a staged sector such that
	// bit-padding ("preprocessing") expands the file to $SECTOR_SIZE
	maxPieceSize := sb.GetMaxUserBytesPerStagedSector(1024)

	// create a piece which consumes all available space in a new, staged
	// sector
	pieceBytes := make([]byte, maxPieceSize)
	read, err := io.ReadFull(rand.Reader, pieceBytes)
	require.Equal(t, uint64(read), maxPieceSize)

	require.NoError(t, err)
	pieceFileA := requireTempFile(t, bytes.NewReader(pieceBytes), maxPieceSize)

	require.NoError(t, err)
	pieceFileB := requireTempFile(t, bytes.NewReader(pieceBytes), maxPieceSize)

	// generate piece commitment
	commP, err := sb.GeneratePieceCommitmentFromFile(pieceFileA, maxPieceSize)
	require.NoError(t, err)

	publicPieceInfoA := []sb.PublicPieceInfo{{
		Size:  maxPieceSize,
		CommP: commP,
	}}

	preComputedCommD, err := sb.GenerateDataCommitment(1024, publicPieceInfoA)
	require.NoError(t, err)

	// seek to the beginning
	_, err = pieceFileA.Seek(0, 0)
	require.NoError(t, err)

	// write a piece to a staged sector, reducing remaining space to 0
	sectorIDA, err := sb.AddPieceFromFile(ptr, "snoqualmie", maxPieceSize, pieceFileA)
	require.NoError(t, err)

	stagedSectors, err := sb.GetAllStagedSectors(ptr)
	require.NoError(t, err)
	require.Equal(t, 1, len(stagedSectors))
	stagedSector := stagedSectors[0]
	require.Equal(t, uint64(1), stagedSector.SectorID)

	// block until the sector is ready for us to begin sealing
	statusA, err := pollForSectorSealingStatus(ptr, sectorIDA, sealing_state.FullyPacked, time.Minute)
	require.NoError(t, err)

	// pre-commit sector to a ticket (in a non-blocking fashion)
	go func() {
		out, err := sb.SealPreCommit(ptr, statusA.SectorID, ticketA)
		require.NoError(t, err)
		require.Equal(t, sectorIDA, out.SectorID)
		require.Equal(t, ticketA.TicketBytes, out.Ticket.TicketBytes)
		require.True(t, bytes.Equal(preComputedCommD[:], out.CommD[:]))
	}()

	// write a second piece to a staged sector, reducing remaining space to 0
	sectorIDB, err := sb.AddPieceFromFile(ptr, "duvall", maxPieceSize, pieceFileB)
	require.NoError(t, err)

	// pre-commit second sector to a ticket too
	go func() {
		_, err := sb.SealPreCommit(ptr, sectorIDB, ticketB)
		require.NoError(t, err)
	}()

	// block until both sectors have successfully pre-committed
	statusA, err = pollForSectorSealingStatus(ptr, sectorIDA, sealing_state.PreCommitted, 30*time.Minute)
	require.NoError(t, err)

	statusB, err := pollForSectorSealingStatus(ptr, sectorIDB, sealing_state.PreCommitted, 30*time.Minute)
	require.NoError(t, err)

	// commit both sectors concurrently
	go func() {
		out, err := sb.SealCommit(ptr, sectorIDA, seedA)
		require.NoError(t, err)
		require.Equal(t, sectorIDA, out.SectorID)
		require.Equal(t, ticketA.TicketBytes, out.Ticket.TicketBytes)
		require.Equal(t, seedA.TicketBytes, out.Seed.TicketBytes)
	}()

	go func() {
		out, err := sb.SealCommit(ptr, sectorIDB, seedB)
		require.NoError(t, err)
		require.Equal(t, sectorIDB, out.SectorID)
	}()

	// block until both sectors have finished sealing (successfully)
	statusA, err = pollForSectorSealingStatus(ptr, sectorIDA, sealing_state.Committed, 30*time.Minute)
	require.NoError(t, err)

	statusB, err = pollForSectorSealingStatus(ptr, sectorIDB, sealing_state.Committed, 30*time.Minute)
	require.NoError(t, err)

	// verify that we used the tickets and seeds we'd intended to use
	require.Equal(t, ticketA.TicketBytes, statusA.Ticket.TicketBytes)
	require.Equal(t, ticketB.TicketBytes, statusB.Ticket.TicketBytes)
	require.Equal(t, seedA.TicketBytes, statusA.Seed.TicketBytes)
	require.Equal(t, seedB.TicketBytes, statusB.Seed.TicketBytes)

	// verify the seal proof
	isValid, err := sb.VerifySeal(1024, statusA.CommR, statusA.CommD, proverID, ticketA.TicketBytes, seedA.TicketBytes, sectorIDA, statusA.Proof)
	require.NoError(t, err)
	require.True(t, isValid)

	// enforces sort ordering of SectorInfo tuples
	sectorInfo := sb.NewSortedSectorInfo(sb.SectorInfo{
		SectorID: statusA.SectorID,
		CommR:    statusA.CommR,
	})

	candidates, err := sb.GenerateCandidates(ptr, sectorInfo, [32]byte{}, []uint64{})
	require.NoError(t, err)

	// generate a PoSt
	proofs, err := sb.GeneratePoSt(ptr, sectorInfo, [32]byte{}, candidates)
	require.NoError(t, err)

	// verify the PoSt
	isValid, err = sb.VerifyPoSt(1024, sectorInfo, [32]byte{}, proofs, candidates, proverID)
	require.NoError(t, err)
	require.True(t, isValid)

	sealedSectors, err = sb.GetAllSealedSectorsWithHealth(ptr)
	require.NoError(t, err)
	require.Equal(t, 2, len(sealedSectors), "expected to see two sealed sectors")
	for _, sealedSector := range sealedSectors {
		require.Equal(t, sealed_sector_health.Ok, sealedSector.Health)
	}

	// both sealed sectors contain the same data, so either will suffice
	require.Equal(t, commP, sealedSectors[0].CommD)

	// unseal the sector and retrieve the client's piece, verifying that the
	// retrieved bytes match what we originally wrote to the staged sector
	unsealedPieceBytes, err := sb.ReadPieceFromSealedSector(ptr, "snoqualmie")
	require.NoError(t, err)
	require.Equal(t, pieceBytes, unsealedPieceBytes)
}

func TestStandaloneSealing(t *testing.T) {
	sectorSize := uint64(1024)
	poRepProofPartitions := uint8(2)

	ticket := sb.SealTicket{
		BlockHeight: 0,
		TicketBytes: [32]byte{5, 4, 2},
	}

	seed := sb.SealSeed{
		BlockHeight: 50,
		TicketBytes: [32]byte{7, 4, 2},
	}

	proverID := [32]byte{6, 7, 8}

	// initialize a sector builder
	metadataDir := requireTempDirPath(t, "metadata")
	defer os.RemoveAll(metadataDir)

	sealedSectorsDir := requireTempDirPath(t, "sealed-sectors")
	defer os.RemoveAll(sealedSectorsDir)

	stagedSectorsDir := requireTempDirPath(t, "staged-sectors")
	defer os.RemoveAll(stagedSectorsDir)

	sectorCacheRootDir := requireTempDirPath(t, "sector-cache-root-dir")
	defer os.RemoveAll(sectorCacheRootDir)

	ptr, err := sb.InitSectorBuilder(1024, 2, 0, metadataDir, proverID, sealedSectorsDir, stagedSectorsDir, sectorCacheRootDir, 1, 1)
	require.NoError(t, err)
	defer sb.DestroySectorBuilder(ptr)

	sectorID, err := sb.AcquireSectorId(ptr)
	require.NoError(t, err)

	sectorCacheDirPath := requireTempDirPath(t, "sector-cache-dir")
	defer os.RemoveAll(sectorCacheDirPath)

	stagedSectorFile := requireTempFile(t, bytes.NewReader([]byte{}), 0)
	defer stagedSectorFile.Close()

	sealedSectorFile := requireTempFile(t, bytes.NewReader([]byte{}), 0)
	defer sealedSectorFile.Close()

	unsealOutputFile := requireTempFile(t, bytes.NewReader([]byte{}), 0)
	defer unsealOutputFile.Close()

	// some rando bytes
	someBytes := make([]byte, 1016)
	_, err = io.ReadFull(rand.Reader, someBytes)
	require.NoError(t, err)

	// write first piece
	require.NoError(t, err)
	pieceFileA := requireTempFile(t, bytes.NewReader(someBytes[0:127]), 127)

	commPA, err := sb.GeneratePieceCommitmentFromFile(pieceFileA, 127)
	require.NoError(t, err)

	// seek back to head (generating piece commitment moves offset)
	_, err = pieceFileA.Seek(0, 0)
	require.NoError(t, err)

	// write the first piece using the alignment-free function
	n, commP, err := sb.StandaloneWriteWithoutAlignment(pieceFileA, 127, stagedSectorFile)
	require.NoError(t, err)
	require.Equal(t, int(n), 127)
	require.Equal(t, commP, commPA)

	// write second piece + alignment
	require.NoError(t, err)
	pieceFileB := requireTempFile(t, bytes.NewReader(someBytes[0:508]), 508)

	commPB, err := sb.GeneratePieceCommitmentFromFile(pieceFileB, 508)
	require.NoError(t, err)

	// seek back to head
	_, err = pieceFileB.Seek(0, 0)
	require.NoError(t, err)

	// second piece relies on the alignment-computing version
	left, tot, commP, err := sb.StandaloneWriteWithAlignment(pieceFileB, 508, stagedSectorFile, []uint64{127})
	require.NoError(t, err)
	require.Equal(t, int(left), 381)
	require.Equal(t, int(tot), 889)
	require.Equal(t, commP, commPB)

	publicPieces := []sb.PublicPieceInfo{{
		Size:  127,
		CommP: commPA,
	}, {
		Size:  508,
		CommP: commPB,
	}}

	privatePieces := make([]sb.PieceMetadata, len(publicPieces))
	for i, v := range publicPieces {
		privatePieces[i] = sb.PieceMetadata{
			Key:   hex.EncodeToString(v.CommP[:]),
			Size:  v.Size,
			CommP: v.CommP,
		}
	}

	// pre-commit the sector
	output, err := sb.StandaloneSealPreCommit(sectorSize, poRepProofPartitions, sectorCacheDirPath, stagedSectorFile.Name(), sealedSectorFile.Name(), sectorID, proverID, ticket.TicketBytes, publicPieces)
	require.NoError(t, err)

	// commit the sector
	proof, err := sb.StandaloneSealCommit(sectorSize, poRepProofPartitions, sectorCacheDirPath, sectorID, proverID, ticket.TicketBytes, seed.TicketBytes, publicPieces, output)
	require.NoError(t, err)

	// verify the 'ole proofy
	isValid, err := sb.VerifySeal(sectorSize, output.CommR, output.CommD, proverID, ticket.TicketBytes, seed.TicketBytes, sectorID, proof)
	require.NoError(t, err)
	require.True(t, isValid, "proof wasn't valid")

	// unseal and verify that things went as we planned
	require.NoError(t, sb.StandaloneUnseal(sectorSize, poRepProofPartitions, sectorCacheDirPath, sealedSectorFile.Name(), unsealOutputFile.Name(), sectorID, proverID, ticket.TicketBytes, output.CommD))
	contents, err := ioutil.ReadFile(unsealOutputFile.Name())
	require.NoError(t, err)

	// unsealed sector includes a bunch of alignment NUL-bytes
	alignment := make([]byte, 381)

	// verify that we unsealed what we expected to unseal
	require.Equal(t, someBytes[0:127], contents[0:127])
	require.Equal(t, alignment, contents[127:508])
	require.Equal(t, someBytes[0:508], contents[508:1016])

	// verify that the sector builder owns no sealed sectors
	var sealedSectorPaths []string
	require.NoError(t, filepath.Walk(sealedSectorsDir, visit(&sealedSectorPaths)))
	assert.Equal(t, 1, len(sealedSectorPaths), sealedSectorPaths)

	// no sector cache dirs, either
	var sectorCacheDirPaths []string
	require.NoError(t, filepath.Walk(sectorCacheRootDir, visit(&sectorCacheDirPaths)))
	assert.Equal(t, 1, len(sectorCacheDirPaths), sectorCacheDirPaths)

	// import the sealed sector
	err = sb.ImportSealedSector(ptr, sectorID, sectorCacheDirPath, sealedSectorFile.Name(), ticket, seed, output.CommR, output.CommD, output.CommC, output.CommRLast, proof, privatePieces)
	require.NoError(t, err)

	// it should now have a sealed sector!
	var sealedSectorPathsB []string
	require.NoError(t, filepath.Walk(sealedSectorsDir, visit(&sealedSectorPathsB)))
	assert.Equal(t, 2, len(sealedSectorPathsB), sealedSectorPathsB)

	// it should now have a cache dir and a bunch of goodies in the cache
	var sectorCacheDirPathsB []string
	require.NoError(t, filepath.Walk(sectorCacheRootDir, visit(&sectorCacheDirPathsB)))
	assert.Less(t, 2, len(sectorCacheDirPathsB), sectorCacheDirPathsB)

	// verify that it shows up in sealed sector list
	metadata, err := sb.GetAllSealedSectorsWithHealth(ptr)
	require.NoError(t, err)
	require.Equal(t, 1, len(metadata))
	require.Equal(t, output.CommD, metadata[0].CommD)
	require.Equal(t, output.CommR, metadata[0].CommR)
}

func TestJsonMarshalSymmetry(t *testing.T) {
	for i := 0; i < 100; i++ {
		xs := make([]sb.SectorInfo, 10)
		for j := 0; j < 10; j++ {
			var x sb.SectorInfo
			_, err := io.ReadFull(rand.Reader, x.CommR[:])
			require.NoError(t, err)

			n, err := rand.Int(rand.Reader, big.NewInt(500))
			require.NoError(t, err)
			x.SectorID = n.Uint64()
			xs[j] = x
		}
		toSerialize := sb.NewSortedSectorInfo(xs...)

		serialized, err := toSerialize.MarshalJSON()
		require.NoError(t, err)

		var fromSerialized sb.SortedSectorInfo
		err = fromSerialized.UnmarshalJSON(serialized)
		require.NoError(t, err)

		require.Equal(t, toSerialize, fromSerialized)
	}
}

func pollForSectorSealingStatus(ptr unsafe.Pointer, sectorID uint64, targetState sealing_state.State, timeout time.Duration) (status sb.SectorSealingStatus, retErr error) {
	timeoutCh := time.After(timeout)
	lastState := sealing_state.Unknown

	tick := time.Tick(1 * time.Second)

	for {
		select {
		case <-timeoutCh:
			retErr = fmt.Errorf("timed out waiting for sector hit desired state (last state: %s)", lastState)
			return
		case <-tick:
			sealingStatus, err := sb.GetSectorSealingStatusByID(ptr, sectorID)
			if err != nil {
				retErr = err
				return
			}

			lastState = sealingStatus.State

			if sealingStatus.State == targetState {
				status = sealingStatus
				return
			} else if sealingStatus.State == sealing_state.Failed {
				retErr = errors.New(sealingStatus.SealErrorMsg)
				return
			}
		}
	}
}

func requireTempFile(t *testing.T, fileContentsReader io.Reader, size uint64) *os.File {
	file, err := ioutil.TempFile("", "")
	require.NoError(t, err)

	written, err := io.Copy(file, fileContentsReader)
	require.NoError(t, err)
	// check that we wrote everything
	require.Equal(t, int(size), int(written))

	require.NoError(t, file.Sync())

	// seek to the beginning
	_, err = file.Seek(0, 0)
	require.NoError(t, err)

	return file
}

func requireTempDirPath(t *testing.T, prefix string) string {
	dir, err := ioutil.TempDir("", prefix)
	require.NoError(t, err)

	return dir
}

func visit(paths *[]string) filepath.WalkFunc {
	return func(path string, info os.FileInfo, err error) error {
		if err != nil {
			panic(err)
		}
		*paths = append(*paths, path)
		return nil
	}
}
