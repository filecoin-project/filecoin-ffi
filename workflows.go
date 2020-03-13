//+build cgo

package ffi

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/filecoin-project/specs-actors/actors/abi"
)

func WorkflowProofsLifecycle(t TestHelper) {
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
	t.RequireNoError(err)

	// write first piece
	pieceFileA := requireTempFile(t, bytes.NewReader(someBytes[0:127]), 127)

	pieceCIDA, err := GeneratePieceCIDFromFile(sealProofType, pieceFileA, 127)
	t.RequireNoError(err)

	// seek back to head (generating piece commitment moves offset)
	_, err = pieceFileA.Seek(0, 0)
	t.RequireNoError(err)

	// write the first piece using the alignment-free function
	n, pieceCID, err := WriteWithoutAlignment(sealProofType, pieceFileA, 127, stagedSectorFile)
	t.RequireNoError(err)
	t.AssertEqual(int(n), 127)
	t.AssertTrue(pieceCID.Equals(pieceCIDA))

	// write second piece + alignment
	t.RequireNoError(err)
	pieceFileB := requireTempFile(t, bytes.NewReader(someBytes[0:1016]), 1016)

	pieceCIDB, err := GeneratePieceCIDFromFile(sealProofType, pieceFileB, 1016)
	t.RequireNoError(err)

	// seek back to head
	_, err = pieceFileB.Seek(0, 0)
	t.RequireNoError(err)

	// second piece relies on the alignment-computing version
	left, tot, pieceCID, err := WriteWithAlignment(sealProofType, pieceFileB, 1016, stagedSectorFile, []abi.UnpaddedPieceSize{127})
	t.RequireNoError(err)
	t.AssertEqual(889, int(left))
	t.AssertEqual(1905, int(tot))
	t.AssertTrue(pieceCID.Equals(pieceCIDB))

	publicPieces := []abi.PieceInfo{{
		Size:     abi.UnpaddedPieceSize(127).Padded(),
		PieceCID: pieceCIDA,
	}, {
		Size:     abi.UnpaddedPieceSize(1016).Padded(),
		PieceCID: pieceCIDB,
	}}

	preGeneratedUnsealedCID, err := GenerateUnsealedCID(sealProofType, publicPieces)
	t.RequireNoError(err)

	// pre-commit the sector
	sealPreCommitPhase1Output, err := SealPreCommitPhase1(sealProofType, sectorCacheDirPath, stagedSectorFile.Name(), sealedSectorFile.Name(), sectorNum, minerID, ticket, publicPieces)
	t.RequireNoError(err)

	sealedCID, unsealedCID, err := SealPreCommitPhase2(sealPreCommitPhase1Output, sectorCacheDirPath, sealedSectorFile.Name())
	t.RequireNoError(err)

	t.AssertTrue(unsealedCID.Equals(preGeneratedUnsealedCID), "prover and verifier should agree on data commitment")

	// commit the sector
	sealCommitPhase1Output, err := SealCommitPhase1(sealProofType, sealedCID, unsealedCID, sectorCacheDirPath, sealedSectorFile.Name(), sectorNum, minerID, ticket, seed, publicPieces)
	t.RequireNoError(err)

	proof, err := SealCommitPhase2(sealCommitPhase1Output, sectorNum, minerID)
	t.RequireNoError(err)

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
	t.RequireNoError(err)
	t.RequireTrue(isValid, "proof wasn't valid")

	// unseal the entire sector and verify that things went as we planned
	t.RequireNoError(Unseal(sealProofType, sectorCacheDirPath, sealedSectorFile.Name(), unsealOutputFileA.Name(), sectorNum, minerID, ticket, unsealedCID))
	contents, err := ioutil.ReadFile(unsealOutputFileA.Name())
	t.RequireNoError(err)

	// unsealed sector includes a bunch of alignment NUL-bytes
	alignment := make([]byte, 889)

	// verify that we unsealed what we expected to unseal
	t.AssertTrue(bytes.Equal(someBytes[0:127], contents[0:127]), "bytes aren't equal")
	t.AssertTrue(bytes.Equal(alignment, contents[127:1016]), "bytes aren't equal")
	t.AssertTrue(bytes.Equal(someBytes[0:1016], contents[1016:2032]), "bytes aren't equal")

	// unseal just the first piece
	err = UnsealRange(sealProofType, sectorCacheDirPath, sealedSectorFile.Name(), unsealOutputFileB.Name(), sectorNum, minerID, ticket, unsealedCID, 0, 127)
	t.RequireNoError(err)
	contentsB, err := ioutil.ReadFile(unsealOutputFileB.Name())
	t.RequireNoError(err)
	t.AssertEqual(127, len(contentsB))
	t.AssertTrue(bytes.Equal(someBytes[0:127], contentsB[0:127]), "bytes aren't equal")

	// unseal just the second piece
	err = UnsealRange(sealProofType, sectorCacheDirPath, sealedSectorFile.Name(), unsealOutputFileC.Name(), sectorNum, minerID, ticket, unsealedCID, 1016, 1016)
	t.RequireNoError(err)
	contentsC, err := ioutil.ReadFile(unsealOutputFileC.Name())
	t.RequireNoError(err)
	t.AssertEqual(1016, len(contentsC))
	t.AssertTrue(bytes.Equal(someBytes[0:1016], contentsC[0:1016]), "bytes aren't equal")

	// verify that the sector builder owns no sealed sectors
	var sealedSectorPaths []string
	t.RequireNoError(filepath.Walk(sealedSectorsDir, visit(&sealedSectorPaths)))
	t.AssertEqual(1, len(sealedSectorPaths), sealedSectorPaths)

	// no sector cache dirs, either
	var sectorCacheDirPaths []string
	t.RequireNoError(filepath.Walk(sectorCacheRootDir, visit(&sectorCacheDirPaths)))
	t.AssertEqual(1, len(sectorCacheDirPaths), sectorCacheDirPaths)

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
	t.RequireNoError(err)

	candidatesA := make([]abi.PoStCandidate, len(candidatesWithTicketsA))
	for idx := range candidatesWithTicketsA {
		candidatesA[idx] = candidatesWithTicketsA[idx].Candidate
	}

	// finalize the ticket, but don't do anything with the results (simply
	// exercise the API)
	_, err = FinalizeTicket(candidatesA[0].PartialTicket)
	t.RequireNoError(err)

	proofs, err := GeneratePoSt(minerID, privateInfo, randomness[:], candidatesA)
	t.RequireNoError(err)

	isValid, err = VerifyPoSt(abi.PoStVerifyInfo{
		Randomness:      randomness[:],
		Candidates:      candidatesA,
		Proofs:          proofs,
		EligibleSectors: eligibleSectors,
		Prover:          minerID,
		ChallengeCount:  challengeCount,
	})
	t.RequireNoError(err)
	t.AssertTrue(isValid, "VerifyPoSt rejected the (standalone) proof as invalid")
}

func WorkflowGetGPUDevicesDoesNotProduceAnError(t TestHelper) {
	devices, err := GetGPUDevices()
	t.RequireNoError(err)
	fmt.Printf("devices: %+v\n", devices) // clutters up test output, but useful
}

func WorkflowRegisteredSealProofFunctions(t TestHelper) {
	sealTypes := []abi.RegisteredProof{
		abi.RegisteredProof_StackedDRG8MiBSeal,
		abi.RegisteredProof_StackedDRG2KiBSeal,
		abi.RegisteredProof_StackedDRG512MiBSeal,
		abi.RegisteredProof_StackedDRG32GiBSeal,
	}

	for _, st := range sealTypes {
		v, err := GetSealVersion(st)
		t.AssertNoError(err)
		t.AssertTrue(len(v) > 0)
	}
}

func WorkflowRegisteredPoStProofFunctions(t TestHelper) {
	postTypes := []abi.RegisteredProof{
		abi.RegisteredProof_StackedDRG8MiBPoSt,
		abi.RegisteredProof_StackedDRG2KiBPoSt,
		abi.RegisteredProof_StackedDRG512MiBPoSt,
		abi.RegisteredProof_StackedDRG32GiBPoSt,
	}

	for _, pt := range postTypes {
		v, err := GetPoStVersion(pt)
		t.AssertNoError(err)
		t.AssertTrue(len(v) > 0)
	}
}

func requireTempFile(t TestHelper, fileContentsReader io.Reader, size uint64) *os.File {
	file, err := ioutil.TempFile("", "")
	t.RequireNoError(err)

	written, err := io.Copy(file, fileContentsReader)
	t.RequireNoError(err)
	// check that we wrote everything
	t.RequireEqual(int(size), int(written))

	t.RequireNoError(file.Sync())

	// seek to the beginning
	_, err = file.Seek(0, 0)
	t.RequireNoError(err)

	return file
}

func requireTempDirPath(t TestHelper, prefix string) string {
	dir, err := ioutil.TempDir("", prefix)
	t.RequireNoError(err)

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

type TestHelper interface {
	AssertEqual(expected, actual interface{}, msgAndArgs ...interface{}) bool
	AssertNoError(err error, msgAndArgs ...interface{}) bool
	AssertTrue(value bool, msgAndArgs ...interface{}) bool
	RequireEqual(expected interface{}, actual interface{}, msgAndArgs ...interface{})
	RequireNoError(err error, msgAndArgs ...interface{})
	RequireTrue(value bool, msgAndArgs ...interface{})
}
