package go_sectorbuilder_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"io/ioutil"
	"math/big"
	"os"
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
		TicketBytes: [32]byte{},
	}

	ticketB := sb.SealTicket{
		BlockHeight: 10,
		TicketBytes: [32]byte{1, 2, 3},
	}

	proverID := [32]byte{6, 7, 8}

	metadataDir := requireTempDirPath(t)
	defer require.NoError(t, os.Remove(metadataDir))

	sealedSectorDir := requireTempDirPath(t)
	defer require.NoError(t, os.Remove(sealedSectorDir))

	stagedSectorDir := requireTempDirPath(t)
	defer require.NoError(t, os.Remove(stagedSectorDir))

	ptr, err := sb.InitSectorBuilder(1024, 2, 1, 0, metadataDir, proverID, sealedSectorDir, stagedSectorDir, 1)
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
	statusA, err := pollForSectorSealingStatus(ptr, sectorIDA, sealing_state.ReadyForSealing, time.Minute)
	require.NoError(t, err)

	// seal all staged sectors
	go func() {
		// blocks until sealing has completed
		meta, err := sb.SealAllStagedSectors(ptr, ticketA)
		require.NoError(t, err)
		require.Equal(t, 1, len(meta))
		require.Equal(t, 1, len(meta[0].Pieces), "expected to see the one piece we added")
		require.Equal(t, stagedSector.SectorID, meta[0].SectorID)
	}()

	// block until the sector begins to seal
	_, err = pollForSectorSealingStatus(ptr, sectorIDA, sealing_state.Sealing, 15*time.Second)
	require.NoError(t, err)

	// write a second piece to a staged sector, reducing remaining space to 0
	sectorIDB, err := sb.AddPieceFromFile(ptr, "duvall", maxPieceSize, pieceFileB)
	require.NoError(t, err)

	go func() {
		meta, err := sb.SealSector(ptr, sectorIDB, ticketB)
		require.NoError(t, err)
		require.Equal(t, sectorIDB, meta.SectorID)
	}()

	// block until both sectors have successfully sealed
	statusA, err = pollForSectorSealingStatus(ptr, sectorIDA, sealing_state.Sealed, 30*time.Minute)
	require.NoError(t, err)
	require.Equal(t, ticketA, statusA.Ticket)

	statusB, err := pollForSectorSealingStatus(ptr, sectorIDB, sealing_state.Sealed, 30*time.Minute)
	require.NoError(t, err)
	require.Equal(t, ticketB, statusB.Ticket)

	// verify the seal proof
	isValid, err := sb.VerifySeal(1024, statusA.CommR, statusA.CommD, proverID, ticketA.TicketBytes, sectorIDA, statusA.Proof)
	require.NoError(t, err)
	require.True(t, isValid)

	// verify the piece inclusion proof
	isValid, err = sb.VerifyPieceInclusionProof(1024, maxPieceSize, commP, statusA.CommD, statusA.Pieces[0].InclusionProof)
	require.NoError(t, err)
	require.True(t, isValid)

	// enforces sort ordering of SectorInfo tuples
	sectorInfo := sb.NewSortedSectorInfo(sb.SectorInfo{
		SectorID: statusA.SectorID,
		CommR:    statusA.CommR,
	})

	// generate a PoSt
	proofs, err := sb.GeneratePoSt(ptr, sectorInfo, [32]byte{}, []uint64{})
	require.NoError(t, err)

	// verify the PoSt
	isValid, err = sb.VerifyPoSt(1024, sectorInfo, [32]byte{}, proofs, []uint64{})
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

	tick := time.Tick(5 * time.Second)

	for {
		select {
		case <-timeoutCh:
			retErr = errors.New("timed out waiting for sector to finish sealing")
			return
		case <-tick:
			sealingStatus, err := sb.GetSectorSealingStatusByID(ptr, sectorID)
			if err != nil {
				retErr = err
				return
			}

			if sealingStatus.State == targetState {
				status = sealingStatus
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
	require.Equal(t, uint64(written), size)

	require.NoError(t, file.Sync())

	// seek to the beginning
	_, err = file.Seek(0, 0)
	require.NoError(t, err)

	return file
}

func requireTempDirPath(t *testing.T) string {
	dir, err := ioutil.TempDir("", "")
	require.NoError(t, err)

	return dir
}
