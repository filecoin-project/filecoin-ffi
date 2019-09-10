package go_sectorbuilder_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"io/ioutil"
	"os"
	"testing"
	"time"
	"unsafe"

	sb "github.com/filecoin-project/go-sectorbuilder"

	"github.com/stretchr/testify/require"
)

func TestSectorBuilderLifecycle(t *testing.T) {
	metadataDir := requireTempDirPath(t)
	defer require.NoError(t, os.Remove(metadataDir))

	sealedSectorDir := requireTempDirPath(t)
	defer require.NoError(t, os.Remove(sealedSectorDir))

	stagedSectorDir := requireTempDirPath(t)
	defer require.NoError(t, os.Remove(stagedSectorDir))

	ptr, err := sb.InitSectorBuilder(1024, 2, 1, 0, metadataDir, [31]byte{}, sealedSectorDir, stagedSectorDir, 1)
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
	_, err = io.ReadFull(rand.Reader, pieceBytes)
	require.NoError(t, err)
	piecePath := requireTempFilePath(t, bytes.NewReader(pieceBytes))

	// generate piece commitment
	commP, err := sb.GeneratePieceCommitment(piecePath, maxPieceSize)
	require.NoError(t, err)

	// write a piece to a staged sector, reducing remaining space to 0 and
	// triggering the seal job
	sectorID, err := sb.AddPiece(ptr, "snoqualmie", maxPieceSize, piecePath)
	require.NoError(t, err)

	stagedSectors, err := sb.GetAllStagedSectors(ptr)
	require.NoError(t, err)
	require.Equal(t, 1, len(stagedSectors))
	stagedSector := stagedSectors[0]
	require.Equal(t, uint64(1), stagedSector.SectorID)

	// block until Groth parameter cache is (lazily) hydrated and sector has
	// been sealed (or timeout)
	status, err := pollForSectorSealingStatus(ptr, sectorID, 0, time.Minute*30)
	require.NoError(t, err)
	require.Equal(t, 1, len(status.Pieces), "expected to see the one piece we added")

	// verify the seal proof
	isValid, err := sb.VerifySeal(1024, status.CommR, status.CommD, status.CommRStar, [31]byte{}, sectorID, status.Proof)
	require.NoError(t, err)
	require.True(t, isValid)

	// verify the piece inclusion proof
	isValid, err = sb.VerifyPieceInclusionProof(1024, maxPieceSize, commP, status.CommD, status.Pieces[0].InclusionProof)
	require.NoError(t, err)
	require.True(t, isValid)

	// enforces sort ordering of SectorInfo tuples
	sectorInfo := sb.NewSortedSectorInfo(sb.SectorInfo{
		SectorID: status.SectorID,
		CommR:    status.CommR,
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
	require.Equal(t, 1, len(sealedSectors), "expected to see one sealed sector")
	sealedSector := sealedSectors[0]
	require.Equal(t, uint64(1), sealedSector.SectorID)
	require.Equal(t, 1, len(sealedSector.Pieces))
	require.Equal(t, sb.Ok, sealedSector.Health)
	// the piece is the size of the sector, so its piece commitment should be the
	// data commitment
	require.Equal(t, commP, sealedSector.CommD)

	// unseal the sector and retrieve the client's piece, verifying that the
	// retrieved bytes match what we originally wrote to the staged sector
	unsealedPieceBytes, err := sb.ReadPieceFromSealedSector(ptr, "snoqualmie")
	require.NoError(t, err)
	require.Equal(t, pieceBytes, unsealedPieceBytes)
}

func pollForSectorSealingStatus(ptr unsafe.Pointer, sectorID uint64, sealStatusCode uint8, timeout time.Duration) (status sb.SectorSealingStatus, retErr error) {
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

			if sealingStatus.SealStatusCode == sealStatusCode {
				status = sealingStatus
				return
			}
		}
	}
}

func requireTempFilePath(t *testing.T, fileContentsReader io.Reader) string {
	file, err := ioutil.TempFile("", "")
	require.NoError(t, err)

	_, err = io.Copy(file, fileContentsReader)
	require.NoError(t, err)

	return file.Name()
}

func requireTempDirPath(t *testing.T) string {
	dir, err := ioutil.TempDir("", "")
	require.NoError(t, err)

	return dir
}
