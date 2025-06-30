//go:build darwin && arm64 && cgo && !ffi_source

package ffi

import (
	"os"

	. "github.com/filecoin-project/filecoin-ffi/types"
	"github.com/filecoin-project/go-state-types/abi"
	"github.com/filecoin-project/go-state-types/proof"
	"github.com/ipfs/go-cid"

	"github.com/filecoin-project/filecoin-ffi/prebuilt/darwin-arm64"
)

// VerifySeal returns true if the sealing operation from which its inputs were
// derived was valid, and false if not.
func VerifySeal(info proof.SealVerifyInfo) (bool, error) {
	return prebuilt.VerifySeal(info)
}

func VerifyAggregateSeals(aggregate proof.AggregateSealVerifyProofAndInfos) (bool, error) {
	return prebuilt.VerifyAggregateSeals(aggregate)
}

// VerifyWinningPoSt returns true if the Winning PoSt-generation operation from which its
// inputs were derived was valid, and false if not.
func VerifyWinningPoSt(info proof.WinningPoStVerifyInfo) (bool, error) {
	return prebuilt.VerifyWinningPoSt(info)
}

// VerifyWindowPoSt returns true if the Winning PoSt-generation operation from which its
// inputs were derived was valid, and false if not.
func VerifyWindowPoSt(info proof.WindowPoStVerifyInfo) (bool, error) {
	return prebuilt.VerifyWindowPoSt(info)
}

// GeneratePieceCommitment produces a piece commitment for the provided data
// stored at a given path.
func GeneratePieceCID(proofType abi.RegisteredSealProof, piecePath string, pieceSize abi.UnpaddedPieceSize) (cid.Cid, error) {
	return prebuilt.GeneratePieceCID(proofType, piecePath, pieceSize)
}

// GenerateDataCommitment produces a commitment for the sector containing the
// provided pieces.
func GenerateUnsealedCID(proofType abi.RegisteredSealProof, pieces []abi.PieceInfo) (cid.Cid, error) {
	return prebuilt.GenerateUnsealedCID(proofType, pieces)
}

// GeneratePieceCIDFromFile produces a piece CID for the provided data stored in a given file.
func GeneratePieceCIDFromFile(proofType abi.RegisteredSealProof, pieceFile *os.File, pieceSize abi.UnpaddedPieceSize) (cid.Cid, error) {
	return prebuilt.GeneratePieceCIDFromFile(proofType, pieceFile, pieceSize)
}

// WriteWithAlignment
func WriteWithAlignment(
	proofType abi.RegisteredSealProof,
	pieceFile *os.File,
	pieceBytes abi.UnpaddedPieceSize,
	stagedSectorFile *os.File,
	existingPieceSizes []abi.UnpaddedPieceSize,
) (leftAlignment, total abi.UnpaddedPieceSize, pieceCID cid.Cid, retErr error) {
	return prebuilt.WriteWithAlignment(proofType, pieceFile, pieceBytes, stagedSectorFile, existingPieceSizes)
}

// WriteWithoutAlignment
func WriteWithoutAlignment(
	proofType abi.RegisteredSealProof,
	pieceFile *os.File,
	pieceBytes abi.UnpaddedPieceSize,
	stagedSectorFile *os.File,
) (abi.UnpaddedPieceSize, cid.Cid, error) {
	return prebuilt.WriteWithoutAlignment(proofType, pieceFile, pieceBytes, stagedSectorFile)
}

// SealPreCommitPhase1
func SealPreCommitPhase1(
	proofType abi.RegisteredSealProof,
	cacheDirPath string,
	stagedSectorPath string,
	sealedSectorPath string,
	sectorNum abi.SectorNumber,
	minerID abi.ActorID,
	ticket abi.SealRandomness,
	pieces []abi.PieceInfo,
) (phase1Output []byte, err error) {
	return prebuilt.SealPreCommitPhase1(proofType, cacheDirPath, stagedSectorPath, sealedSectorPath, sectorNum, minerID, ticket, pieces)
}

// SealPreCommitPhase2
func SealPreCommitPhase2(
	phase1Output []byte,
	cacheDirPath string,
	sealedSectorPath string,
) (sealedCID cid.Cid, unsealedCID cid.Cid, err error) {
	return prebuilt.SealPreCommitPhase2(phase1Output, cacheDirPath, sealedSectorPath)
}

// SealCommitPhase1
func SealCommitPhase1(
	proofType abi.RegisteredSealProof,
	sealedCID cid.Cid,
	unsealedCID cid.Cid,
	cacheDirPath string,
	sealedSectorPath string,
	sectorNum abi.SectorNumber,
	minerID abi.ActorID,
	ticket abi.SealRandomness,
	seed abi.InteractiveSealRandomness,
	pieces []abi.PieceInfo,
) (phase1Output []byte, err error) {
	return prebuilt.SealCommitPhase1(proofType, sealedCID, unsealedCID, cacheDirPath, sealedSectorPath, sectorNum, minerID, ticket, seed, pieces)
}

// SealCommitPhase2
func SealCommitPhase2(
	phase1Output []byte,
	sectorNum abi.SectorNumber,
	minerID abi.ActorID,
) ([]byte, error) {

	return prebuilt.SealCommitPhase2(phase1Output, sectorNum, minerID)
}

// SealCommitPhase2CircuitProofs runs a non-interactive proof and returns the circuit proof bytes
// rather than the aggregated proof bytes. This is used to aggregate multiple non-interactive
// proofs as the aggregated single proof outputs can't further be aggregated.
func SealCommitPhase2CircuitProofs(phase1Output []byte, sectorNum abi.SectorNumber) ([]byte, error) {
	return prebuilt.SealCommitPhase2CircuitProofs(phase1Output, sectorNum)
}

func AggregateSealProofs(aggregateInfo proof.AggregateSealVerifyProofAndInfos, proofs [][]byte) (out []byte, err error) {
	return prebuilt.AggregateSealProofs(aggregateInfo, proofs)
}

// Unseal
func Unseal(
	proofType abi.RegisteredSealProof,
	cacheDirPath string,
	sealedSector *os.File,
	unsealOutput *os.File,
	sectorNum abi.SectorNumber,
	minerID abi.ActorID,
	ticket abi.SealRandomness,
	unsealedCID cid.Cid,
) error {
	return prebuilt.Unseal(proofType, cacheDirPath, sealedSector, unsealOutput, sectorNum, minerID, ticket, unsealedCID)
}

// UnsealRange
func UnsealRange(
	proofType abi.RegisteredSealProof,
	cacheDirPath string,
	sealedSector *os.File,
	unsealOutput *os.File,
	sectorNum abi.SectorNumber,
	minerID abi.ActorID,
	ticket abi.SealRandomness,
	unsealedCID cid.Cid,
	unpaddedByteIndex uint64,
	unpaddedBytesAmount uint64,
) error {
	return prebuilt.UnsealRange(proofType, cacheDirPath, sealedSector, unsealOutput, sectorNum, minerID, ticket, unsealedCID, unpaddedByteIndex, unpaddedBytesAmount)
}

func GenerateSDR(
	proofType abi.RegisteredSealProof,
	cacheDirPath string,
	replicaId [32]byte,
) (err error) {
	return prebuilt.GenerateSDR(proofType, cacheDirPath, replicaId)
}

// GenerateWinningPoStSectorChallenge
func GenerateWinningPoStSectorChallenge(
	proofType abi.RegisteredPoStProof,
	minerID abi.ActorID,
	randomness abi.PoStRandomness,
	eligibleSectorsLen uint64,
) ([]uint64, error) {
	return prebuilt.GenerateWinningPoStSectorChallenge(proofType, minerID, randomness, eligibleSectorsLen)
}

// GenerateWinningPoSt
func GenerateWinningPoSt(
	minerID abi.ActorID,
	privateSectorInfo SortedPrivateSectorInfo,
	randomness abi.PoStRandomness,
) ([]proof.PoStProof, error) {
	return prebuilt.GenerateWinningPoSt(minerID, privateSectorInfo, randomness)
}

// GenerateWindowPoSt
func GenerateWindowPoSt(
	minerID abi.ActorID,
	privateSectorInfo SortedPrivateSectorInfo,
	randomness abi.PoStRandomness,
) ([]proof.PoStProof, []abi.SectorNumber, error) {
	return prebuilt.GenerateWindowPoSt(minerID, privateSectorInfo, randomness)
}

// GetGPUDevices produces a slice of strings, each representing the name of a
// detected GPU device.
func GetGPUDevices() ([]string, error) {
	return prebuilt.GetGPUDevices()
}

// GetSealVersion
func GetSealVersion(proofType abi.RegisteredSealProof) (string, error) {
	return prebuilt.GetSealVersion(proofType)
}

// GetPoStVersion
func GetPoStVersion(proofType abi.RegisteredPoStProof) (string, error) {
	return prebuilt.GetPoStVersion(proofType)
}

func GetNumPartitionForFallbackPost(proofType abi.RegisteredPoStProof, numSectors uint) (uint, error) {

	return prebuilt.GetNumPartitionForFallbackPost(proofType, numSectors)
}

// ClearCache
func ClearCache(sectorSize uint64, cacheDirPath string) error {
	return prebuilt.ClearCache(sectorSize, cacheDirPath)
}

// ClearSyntheticProofs
func ClearSyntheticProofs(sectorSize uint64, cacheDirPath string) error {
	return prebuilt.ClearSyntheticProofs(sectorSize, cacheDirPath)
}

func GenerateSynthProofs(
	proofType abi.RegisteredSealProof,
	sealedCID, unsealedCID cid.Cid,
	cacheDirPath, replicaPath string,
	sector_id abi.SectorNumber,
	minerID abi.ActorID,
	ticket []byte,
	pieces []abi.PieceInfo,
) error {
	return prebuilt.GenerateSynthProofs(proofType, sealedCID, unsealedCID, cacheDirPath, replicaPath, sector_id, minerID, ticket, pieces)
}

func FauxRep(proofType abi.RegisteredSealProof, cacheDirPath string, sealedSectorPath string) (cid.Cid, error) {
	return prebuilt.FauxRep(proofType, cacheDirPath, sealedSectorPath)
}

func FauxRep2(proofType abi.RegisteredSealProof, cacheDirPath string, existingPAuxPath string) (cid.Cid, error) {
	return prebuilt.FauxRep2(proofType, cacheDirPath, existingPAuxPath)
}
