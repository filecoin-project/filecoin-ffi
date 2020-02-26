package ffi

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	commcid "github.com/filecoin-project/go-fil-commcid"

	"github.com/filecoin-project/specs-actors/actors/abi"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProofsLifecycle(t *testing.T) {
	challengeCount := uint64(2)
	minerID := abi.ActorID(42)
	randomness := [32]byte{9, 9, 9}
	sealProofType := abi.RegisteredProof_StackedDRG2KiBSeal
	postProofType := abi.RegisteredProof_StackedDRG2KiBPoSt
	sectorNum := abi.SectorNumber(42)

	ticket := abi.SealRandomness{5, 4, 2}

	seed := abi.InteractiveSealRandomness{7, 4, 2}

	// initialize a sector builder
	metadataDir := requireTempDirPath(t, "metadata")
	defer os.RemoveAll(metadataDir)

	sealedSectorsDir := requireTempDirPath(t, "sealed-sectors")
	defer os.RemoveAll(sealedSectorsDir)

	stagedSectorsDir := requireTempDirPath(t, "staged-sectors")
	defer os.RemoveAll(stagedSectorsDir)

	sectorCacheRootDir := requireTempDirPath(t, "sector-cache-root-dir")
	defer os.RemoveAll(sectorCacheRootDir)

	sectorCacheDirPath := requireTempDirPath(t, "sector-cache-dir")
	defer os.RemoveAll(sectorCacheDirPath)

	stagedSectorFile := requireTempFile(t, bytes.NewReader([]byte{}), 0)
	defer stagedSectorFile.Close()

	sealedSectorFile := requireTempFile(t, bytes.NewReader([]byte{}), 0)
	defer sealedSectorFile.Close()

	unsealOutputFileA := requireTempFile(t, bytes.NewReader([]byte{}), 0)
	defer unsealOutputFileA.Close()

	unsealOutputFileB := requireTempFile(t, bytes.NewReader([]byte{}), 0)
	defer unsealOutputFileB.Close()

	unsealOutputFileC := requireTempFile(t, bytes.NewReader([]byte{}), 0)
	defer unsealOutputFileC.Close()

	unsealOutputFileD := requireTempFile(t, bytes.NewReader([]byte{}), 0)
	defer unsealOutputFileD.Close()

	// some rando bytes
	someBytes := make([]byte, abi.PaddedPieceSize(2048).Unpadded())
	_, err := io.ReadFull(rand.Reader, someBytes)
	require.NoError(t, err)

	// write first piece
	pieceFileA := requireTempFile(t, bytes.NewReader(someBytes[0:127]), 127)

	pieceCIDA, err := GeneratePieceCIDFromFile(sealProofType, pieceFileA, 127)
	require.NoError(t, err)

	// seek back to head (generating piece commitment moves offset)
	_, err = pieceFileA.Seek(0, 0)
	require.NoError(t, err)

	// write the first piece using the alignment-free function
	n, pieceCID, err := WriteWithoutAlignment(sealProofType, pieceFileA, 127, stagedSectorFile)
	require.NoError(t, err)
	require.Equal(t, int(n), 127)
	require.Equal(t, pieceCID, pieceCIDA)

	// write second piece + alignment
	require.NoError(t, err)
	pieceFileB := requireTempFile(t, bytes.NewReader(someBytes[0:1016]), 1016)

	pieceCIDB, err := GeneratePieceCIDFromFile(sealProofType, pieceFileB, 1016)
	require.NoError(t, err)

	// seek back to head
	_, err = pieceFileB.Seek(0, 0)
	require.NoError(t, err)

	// second piece relies on the alignment-computing version
	left, tot, pieceCID, err := WriteWithAlignment(sealProofType, pieceFileB, 1016, stagedSectorFile, []abi.UnpaddedPieceSize{127})
	require.NoError(t, err)
	require.Equal(t, 889, int(left))
	require.Equal(t, 1905, int(tot))
	require.Equal(t, pieceCID, pieceCIDB)

	publicPieces := []abi.PieceInfo{{
		Size:     abi.UnpaddedPieceSize(127).Padded(),
		PieceCID: pieceCIDA,
	}, {
		Size:     abi.UnpaddedPieceSize(1016).Padded(),
		PieceCID: pieceCIDB,
	}}

	preGeneratedUnsealedCID, err := GenerateUnsealedCID(sealProofType, publicPieces)
	require.NoError(t, err)

	// pre-commit the sector
	sealPreCommitPhase1Output, err := SealPreCommitPhase1(sealProofType, sectorCacheDirPath, stagedSectorFile.Name(), sealedSectorFile.Name(), sectorNum, minerID, ticket, publicPieces)
	require.NoError(t, err)

	sealedCID, unsealedCID, err := SealPreCommitPhase2(sealPreCommitPhase1Output, sectorCacheDirPath, sealedSectorFile.Name())
	require.NoError(t, err)

	require.Equal(t, unsealedCID, preGeneratedUnsealedCID, "prover and verifier should agree on data commitment")

	// commit the sector
	sealCommitPhase1Output, err := SealCommitPhase1(sealProofType, sealedCID, unsealedCID, sectorCacheDirPath, sealedSectorFile.Name(), sectorNum, minerID, ticket, seed, publicPieces)
	require.NoError(t, err)

	proof, err := SealCommitPhase2(sealCommitPhase1Output, sectorNum, minerID)
	require.NoError(t, err)

	// verify the 'ole proofy
	isValid, err := VerifySeal(abi.SealVerifyInfo{
		SectorID: abi.SectorID{
			Miner:  minerID,
			Number: sectorNum,
		},
		OnChain: abi.OnChainSealVerifyInfo{
			SealedCID:        sealedCID,
			InteractiveEpoch: abi.ChainEpoch(42),
			RegisteredProof:  sealProofType,
			Proof:            proof,
			DealIDs:          []abi.DealID{},
			SectorNumber:     sectorNum,
			SealRandEpoch:    abi.ChainEpoch(42),
		},
		Randomness:            ticket,
		InteractiveRandomness: seed,
		UnsealedCID:           unsealedCID,
	})
	require.NoError(t, err)
	require.True(t, isValid, "proof wasn't valid")

	// unseal the entire sector and verify that things went as we planned
	require.NoError(t, Unseal(sealProofType, sectorCacheDirPath, sealedSectorFile.Name(), unsealOutputFileA.Name(), sectorNum, minerID, ticket, unsealedCID))
	contents, err := ioutil.ReadFile(unsealOutputFileA.Name())
	require.NoError(t, err)

	// unsealed sector includes a bunch of alignment NUL-bytes
	alignment := make([]byte, 889)

	// verify that we unsealed what we expected to unseal
	require.Equal(t, someBytes[0:127], contents[0:127])
	require.Equal(t, alignment, contents[127:1016])
	require.Equal(t, someBytes[0:1016], contents[1016:2032])

	// unseal just the first piece
	err = UnsealRange(sealProofType, sectorCacheDirPath, sealedSectorFile.Name(), unsealOutputFileB.Name(), sectorNum, minerID, ticket, unsealedCID, 0, 127)
	require.NoError(t, err)
	contentsB, err := ioutil.ReadFile(unsealOutputFileB.Name())
	require.NoError(t, err)
	require.Equal(t, 127, len(contentsB))
	require.Equal(t, someBytes[0:127], contentsB[0:127])

	// unseal just the second piece
	err = UnsealRange(sealProofType, sectorCacheDirPath, sealedSectorFile.Name(), unsealOutputFileC.Name(), sectorNum, minerID, ticket, unsealedCID, 1016, 1016)
	require.NoError(t, err)
	contentsC, err := ioutil.ReadFile(unsealOutputFileC.Name())
	require.NoError(t, err)
	require.Equal(t, 1016, len(contentsC))
	require.Equal(t, someBytes[0:1016], contentsC[0:1016])

	// verify that the sector builder owns no sealed sectors
	var sealedSectorPaths []string
	require.NoError(t, filepath.Walk(sealedSectorsDir, visit(&sealedSectorPaths)))
	assert.Equal(t, 1, len(sealedSectorPaths), sealedSectorPaths)

	// no sector cache dirs, either
	var sectorCacheDirPaths []string
	require.NoError(t, filepath.Walk(sectorCacheRootDir, visit(&sectorCacheDirPaths)))
	assert.Equal(t, 1, len(sectorCacheDirPaths), sectorCacheDirPaths)

	// generate a PoSt over the proving set before importing, just to exercise
	// the new API
	privateInfo := NewSortedPrivateSectorInfo(PrivateSectorInfo{
		SectorInfo: abi.SectorInfo{
			SectorNumber: sectorNum,
			SealedCID:    sealedCID,
		},
		CacheDirPath:     sectorCacheDirPath,
		PoStProofType:    postProofType,
		SealedSectorPath: sealedSectorFile.Name(),
	})

	eligibleSectors := []abi.SectorInfo{{
		RegisteredProof: sealProofType,
		SectorNumber:    sectorNum,
		SealedCID:       sealedCID,
	}}

	candidatesWithTicketsA, err := GenerateCandidates(minerID, randomness[:], challengeCount, privateInfo)
	require.NoError(t, err)

	candidatesA := make([]abi.PoStCandidate, len(candidatesWithTicketsA))
	for idx := range candidatesWithTicketsA {
		candidatesA[idx] = candidatesWithTicketsA[idx].Candidate
	}

	// finalize the ticket, but don't do anything with the results (simply
	// exercise the API)
	_, err = FinalizeTicket(candidatesA[0].PartialTicket)
	require.NoError(t, err)

	proofs, err := GeneratePoSt(minerID, privateInfo, randomness[:], candidatesA)
	require.NoError(t, err)

	isValid, err = VerifyPoSt(abi.PoStVerifyInfo{
		Randomness:      randomness[:],
		Candidates:      candidatesA,
		Proofs:          proofs,
		EligibleSectors: eligibleSectors,
		Prover:          minerID,
		ChallengeCount:  challengeCount,
	})
	require.NoError(t, err)
	require.True(t, isValid, "VerifyPoSt rejected the (standalone) proof as invalid")
}

func TestJsonMarshalSymmetry(t *testing.T) {
	for i := 0; i < 100; i++ {
		xs := make([]publicSectorInfo, 10)
		for j := 0; j < 10; j++ {
			var x publicSectorInfo
			var commR [32]byte
			_, err := io.ReadFull(rand.Reader, commR[:])
			require.NoError(t, err)

			x.SealedCID = commcid.ReplicaCommitmentV1ToCID(commR[:])

			n, err := rand.Int(rand.Reader, big.NewInt(500))
			require.NoError(t, err)
			x.SectorNum = abi.SectorNumber(n.Uint64())
			xs[j] = x
		}
		toSerialize := newSortedPublicSectorInfo(xs...)

		serialized, err := toSerialize.MarshalJSON()
		require.NoError(t, err)

		var fromSerialized SortedPublicSectorInfo
		err = fromSerialized.UnmarshalJSON(serialized)
		require.NoError(t, err)

		require.Equal(t, toSerialize, fromSerialized)
	}
}

func TestGetGPUDevicesDoesNotProduceAnError(t *testing.T) {
	devices, err := GetGPUDevices()
	require.NoError(t, err)
	fmt.Printf("devices: %+v\n", devices) // clutters up test output, but useful
}

func TestRegisteredSealProofFunctions(t *testing.T) {
	sealTypes := []abi.RegisteredProof{
		abi.RegisteredProof_StackedDRG8MiBSeal,
		abi.RegisteredProof_StackedDRG2KiBSeal,
		abi.RegisteredProof_StackedDRG512MiBSeal,
		abi.RegisteredProof_StackedDRG32GiBSeal,
	}

	for _, st := range sealTypes {
		v, err := GetSealVersion(st)
		assert.NoError(t, err)
		assert.True(t, len(v) > 0)
	}
}

func TestRegisteredPoStProofFunctions(t *testing.T) {
	postTypes := []abi.RegisteredProof{
		abi.RegisteredProof_StackedDRG8MiBPoSt,
		abi.RegisteredProof_StackedDRG2KiBPoSt,
		abi.RegisteredProof_StackedDRG512MiBPoSt,
		abi.RegisteredProof_StackedDRG32GiBPoSt,
	}

	for _, pt := range postTypes {
		v, err := GetPoStVersion(pt)
		assert.NoError(t, err)
		assert.True(t, len(v) > 0)
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
