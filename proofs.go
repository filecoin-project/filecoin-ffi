//go:build cgo
// +build cgo

package ffi

// #cgo LDFLAGS: ${SRCDIR}/libfilcrypto.a
// #cgo pkg-config: ${SRCDIR}/filcrypto.pc
// #include "./filcrypto.h"
import "C"
import (
	"os"
	"runtime"
	"unsafe"

	"github.com/ipfs/go-cid"
	"github.com/pkg/errors"
	"golang.org/x/xerrors"

	"github.com/filecoin-project/go-address"
	commcid "github.com/filecoin-project/go-fil-commcid"
	"github.com/filecoin-project/go-state-types/abi"
	proof5 "github.com/filecoin-project/specs-actors/v5/actors/runtime/proof"

	"github.com/filecoin-project/filecoin-ffi/cgo"
)

// VerifySeal returns true if the sealing operation from which its inputs were
// derived was valid, and false if not.
func VerifySeal(info proof5.SealVerifyInfo) (bool, error) {
	sp, err := toFilRegisteredSealProof(info.SealProof)
	if err != nil {
		return false, err
	}

	commR, err := to32ByteCommR(info.SealedCID)
	if err != nil {
		return false, err
	}

	commD, err := to32ByteCommD(info.UnsealedCID)
	if err != nil {
		return false, err
	}

	proverID, err := toProverID(info.Miner)
	if err != nil {
		return false, err
	}

	randomness := cgo.AsByteArray32(info.Randomness)
	interactiveRandomness := cgo.AsByteArray32(info.InteractiveRandomness)

	return cgo.VerifySeal(sp, &commR, &commD, &proverID, &randomness, &interactiveRandomness, uint64(info.SectorID.Number), cgo.AsSliceRefUint8(info.Proof))
}

func VerifyAggregateSeals(aggregate proof5.AggregateSealVerifyProofAndInfos) (bool, error) {
	if len(aggregate.Infos) == 0 {
		return false, xerrors.New("no seal verify infos")
	}

	// TODO: assuming this needs to be the same for all sectors, potentially makes sense to put in AggregateSealVerifyProofAndInfos
	spt := aggregate.SealProof
	inputs := make([]cgo.AggregationInputs, len(aggregate.Infos))

	for i, info := range aggregate.Infos {
		commR, err := to32ByteCommR(info.SealedCID)
		if err != nil {
			return false, err
		}

		commD, err := to32ByteCommD(info.UnsealedCID)
		if err != nil {
			return false, err
		}

		inputs[i] = cgo.NewAggregationInputs(
			commR,
			commD,
			uint64(info.Number),
			cgo.AsByteArray32(info.Randomness),
			cgo.AsByteArray32(info.InteractiveRandomness),
		)
	}

	sp, err := toFilRegisteredSealProof(spt)
	if err != nil {
		return false, err
	}

	proverID, err := toProverID(aggregate.Miner)
	if err != nil {
		return false, err
	}

	rap, err := toFilRegisteredAggregationProof(aggregate.AggregateProof)
	if err != nil {
		return false, err
	}

	return cgo.VerifyAggregateSealProof(sp, rap, &proverID, cgo.AsSliceRefUint8(aggregate.Proof), cgo.AsSliceRefAggregationInputs(inputs))
}

// VerifyWinningPoSt returns true if the Winning PoSt-generation operation from which its
// inputs were derived was valid, and false if not.
func VerifyWinningPoSt(info proof5.WinningPoStVerifyInfo) (bool, error) {
	filPublicReplicaInfos, err := toFilPublicReplicaInfos(info.ChallengedSectors, "winning")
	if err != nil {
		return false, errors.Wrap(err, "failed to create public replica info array for FFI")
	}

	filPoStProofs, err := toFilPoStProofs(info.Proofs)
	if err != nil {
		return false, errors.Wrap(err, "failed to create PoSt proofs array for FFI")
	}

	proverID, err := toProverID(info.Prover)
	if err != nil {
		return false, err
	}
	randomness := cgo.AsByteArray32(info.Randomness)

	return cgo.VerifyWinningPoSt(
		&randomness,
		cgo.AsSliceRefPublicReplicaInfo(filPublicReplicaInfos),
		cgo.AsSliceRefPoStProof(filPoStProofs),
		&proverID,
	)
}

// VerifyWindowPoSt returns true if the Winning PoSt-generation operation from which its
// inputs were derived was valid, and false if not.
func VerifyWindowPoSt(info proof5.WindowPoStVerifyInfo) (bool, error) {
	filPublicReplicaInfos, err := toFilPublicReplicaInfos(info.ChallengedSectors, "window")
	if err != nil {
		return false, errors.Wrap(err, "failed to create public replica info array for FFI")
	}

	filPoStProofs, err := toFilPoStProofs(info.Proofs)
	if err != nil {
		return false, errors.Wrap(err, "failed to create PoSt proofs array for FFI")
	}

	proverID, err := toProverID(info.Prover)
	if err != nil {
		return false, err
	}

	randomness := cgo.AsByteArray32(info.Randomness)

	return cgo.VerifyWindowPoSt(
		&randomness,
		cgo.AsSliceRefPublicReplicaInfo(filPublicReplicaInfos),
		cgo.AsSliceRefPoStProof(filPoStProofs),
		&proverID,
	)
}

// GeneratePieceCommitment produces a piece commitment for the provided data
// stored at a given path.
func GeneratePieceCID(proofType abi.RegisteredSealProof, piecePath string, pieceSize abi.UnpaddedPieceSize) (cid.Cid, error) {
	pieceFile, err := os.Open(piecePath)
	if err != nil {
		return cid.Undef, err
	}

	pcd, err := GeneratePieceCIDFromFile(proofType, pieceFile, pieceSize)
	if err != nil {
		return cid.Undef, pieceFile.Close()
	}

	return pcd, pieceFile.Close()
}

// GenerateDataCommitment produces a commitment for the sector containing the
// provided pieces.
func GenerateUnsealedCID(proofType abi.RegisteredSealProof, pieces []abi.PieceInfo) (cid.Cid, error) {
	sp, err := toFilRegisteredSealProof(proofType)
	if err != nil {
		return cid.Undef, err
	}

	filPublicPieceInfos, err := toFilPublicPieceInfos(pieces)
	if err != nil {
		return cid.Undef, err
	}

	resp, err := cgo.GenerateDataCommitment(sp, cgo.AsSliceRefPublicPieceInfo(filPublicPieceInfos))
	if err != nil {
		return cid.Undef, err
	}

	return commcid.DataCommitmentV1ToCID(resp)
}

// GeneratePieceCIDFromFile produces a piece CID for the provided data stored in a given file.
func GeneratePieceCIDFromFile(proofType abi.RegisteredSealProof, pieceFile *os.File, pieceSize abi.UnpaddedPieceSize) (cid.Cid, error) {
	sp, err := toFilRegisteredSealProof(proofType)
	if err != nil {
		return cid.Undef, err
	}

	pieceFd := pieceFile.Fd()
	defer runtime.KeepAlive(pieceFile)

	resp, err := cgo.GeneratePieceCommitment(sp, int32(pieceFd), uint64(pieceSize))
	if err != nil {
		return cid.Undef, err
	}

	return commcid.PieceCommitmentV1ToCID(resp)
}

// WriteWithAlignment
func WriteWithAlignment(
	proofType abi.RegisteredSealProof,
	pieceFile *os.File,
	pieceBytes abi.UnpaddedPieceSize,
	stagedSectorFile *os.File,
	existingPieceSizes []abi.UnpaddedPieceSize,
) (leftAlignment, total abi.UnpaddedPieceSize, pieceCID cid.Cid, retErr error) {
	sp, err := toFilRegisteredSealProof(proofType)
	if err != nil {
		return 0, 0, cid.Undef, err
	}

	pieceFd := pieceFile.Fd()
	defer runtime.KeepAlive(pieceFile)

	stagedSectorFd := stagedSectorFile.Fd()
	defer runtime.KeepAlive(stagedSectorFile)

	filExistingPieceSizes := toFilExistingPieceSizes(existingPieceSizes)

	leftAlignmentUnpadded, totalWriteUnpadded, commPRaw, err := cgo.WriteWithAlignment(sp, int32(pieceFd), uint64(pieceBytes), int32(stagedSectorFd), cgo.AsSliceRefUint64(filExistingPieceSizes))
	if err != nil {
		return 0, 0, cid.Undef, err
	}

	commP, errCommpSize := commcid.PieceCommitmentV1ToCID(commPRaw)
	if errCommpSize != nil {
		return 0, 0, cid.Undef, errCommpSize
	}

	return abi.UnpaddedPieceSize(leftAlignmentUnpadded), abi.UnpaddedPieceSize(totalWriteUnpadded), commP, nil
}

// WriteWithoutAlignment
func WriteWithoutAlignment(
	proofType abi.RegisteredSealProof,
	pieceFile *os.File,
	pieceBytes abi.UnpaddedPieceSize,
	stagedSectorFile *os.File,
) (abi.UnpaddedPieceSize, cid.Cid, error) {
	sp, err := toFilRegisteredSealProof(proofType)
	if err != nil {
		return 0, cid.Undef, err
	}

	pieceFd := pieceFile.Fd()
	defer runtime.KeepAlive(pieceFile)

	stagedSectorFd := stagedSectorFile.Fd()
	defer runtime.KeepAlive(stagedSectorFile)

	totalWriteUnpadded, commPRaw, err := cgo.WriteWithoutAlignment(sp, int32(pieceFd), uint64(pieceBytes), int32(stagedSectorFd))
	if err != nil {
		return 0, cid.Undef, err
	}

	commP, errCommpSize := commcid.PieceCommitmentV1ToCID(commPRaw)
	if errCommpSize != nil {
		return 0, cid.Undef, errCommpSize
	}

	return abi.UnpaddedPieceSize(totalWriteUnpadded), commP, nil
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
	sp, err := toFilRegisteredSealProof(proofType)
	if err != nil {
		return nil, err
	}

	proverID, err := toProverID(minerID)
	if err != nil {
		return nil, err
	}

	filPublicPieceInfos, err := toFilPublicPieceInfos(pieces)
	if err != nil {
		return nil, err
	}

	ticketBytes := cgo.AsByteArray32(ticket)
	return cgo.SealPreCommitPhase1(
		sp,
		cgo.AsSliceRefUint8([]byte(cacheDirPath)),
		cgo.AsSliceRefUint8([]byte(stagedSectorPath)),
		cgo.AsSliceRefUint8([]byte(sealedSectorPath)),
		uint64(sectorNum),
		&proverID,
		&ticketBytes,
		cgo.AsSliceRefPublicPieceInfo(filPublicPieceInfos),
	)
}

// SealPreCommitPhase2
func SealPreCommitPhase2(
	phase1Output []byte,
	cacheDirPath string,
	sealedSectorPath string,
) (sealedCID cid.Cid, unsealedCID cid.Cid, err error) {
	commRRaw, commDRaw, err := cgo.SealPreCommitPhase2(
		cgo.AsSliceRefUint8(phase1Output),
		cgo.AsSliceRefUint8([]byte(cacheDirPath)),
		cgo.AsSliceRefUint8([]byte(sealedSectorPath)),
	)
	if err != nil {
		return cid.Undef, cid.Undef, err
	}
	commR, errCommrSize := commcid.ReplicaCommitmentV1ToCID(commRRaw)
	if errCommrSize != nil {
		return cid.Undef, cid.Undef, errCommrSize
	}
	commD, errCommdSize := commcid.DataCommitmentV1ToCID(commDRaw)
	if errCommdSize != nil {
		return cid.Undef, cid.Undef, errCommdSize
	}

	return commR, commD, nil
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
	sp, err := toFilRegisteredSealProof(proofType)
	if err != nil {
		return nil, err
	}

	proverID, err := toProverID(minerID)
	if err != nil {
		return nil, err
	}

	commR, err := to32ByteCommR(sealedCID)
	if err != nil {
		return nil, err
	}

	commD, err := to32ByteCommD(unsealedCID)
	if err != nil {
		return nil, err
	}

	filPublicPieceInfos, err := toFilPublicPieceInfos(pieces)
	if err != nil {
		return nil, err
	}
	ticketBytes := cgo.AsByteArray32(ticket)
	seedBytes := cgo.AsByteArray32(seed)

	return cgo.SealCommitPhase1(
		sp,
		&commR,
		&commD,
		cgo.AsSliceRefUint8([]byte(cacheDirPath)),
		cgo.AsSliceRefUint8([]byte(sealedSectorPath)),
		uint64(sectorNum),
		&proverID,
		&ticketBytes,
		&seedBytes,
		cgo.AsSliceRefPublicPieceInfo(filPublicPieceInfos),
	)
}

// SealCommitPhase2
func SealCommitPhase2(
	phase1Output []byte,
	sectorNum abi.SectorNumber,
	minerID abi.ActorID,
) ([]byte, error) {
	proverID, err := toProverID(minerID)
	if err != nil {
		return nil, err
	}

	return cgo.SealCommitPhase2(cgo.AsSliceRefUint8(phase1Output), uint64(sectorNum), &proverID)
}

// TODO AggregateSealProofs it only needs InteractiveRandomness out of the aggregateInfo.Infos
func AggregateSealProofs(aggregateInfo proof5.AggregateSealVerifyProofAndInfos, proofs [][]byte) (out []byte, err error) {
	sp, err := toFilRegisteredSealProof(aggregateInfo.SealProof)
	if err != nil {
		return nil, err
	}

	commRs := make([]cgo.ByteArray32, len(aggregateInfo.Infos))
	seeds := make([]cgo.ByteArray32, len(aggregateInfo.Infos))
	for i, info := range aggregateInfo.Infos {
		seeds[i] = cgo.AsByteArray32(info.InteractiveRandomness)
		commRs[i], err = to32ByteCommR(info.SealedCID)
		if err != nil {
			return nil, err
		}
	}

	pfs := make([]cgo.SliceBoxedUint8, len(proofs))
	for i := range proofs {
		p, err := cgo.AsSliceBoxedUint8(proofs[i])
		if err != nil {
			return nil, err
		}
		pfs[i] = p
	}

	rap, err := toFilRegisteredAggregationProof(aggregateInfo.AggregateProof)
	if err != nil {
		return nil, err
	}

	return cgo.AggregateSealProofs(
		sp,
		rap,
		cgo.AsSliceRefByteArray32(commRs),
		cgo.AsSliceRefByteArray32(seeds),
		cgo.AsSliceRefSliceBoxedUint8(pfs),
	)
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
	sectorSize, err := proofType.SectorSize()
	if err != nil {
		return err
	}

	unpaddedBytesAmount := abi.PaddedPieceSize(sectorSize).Unpadded()

	return UnsealRange(proofType, cacheDirPath, sealedSector, unsealOutput, sectorNum, minerID, ticket, unsealedCID, 0, uint64(unpaddedBytesAmount))
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
	sp, err := toFilRegisteredSealProof(proofType)
	if err != nil {
		return err
	}

	proverID, err := toProverID(minerID)
	if err != nil {
		return err
	}

	commD, err := to32ByteCommD(unsealedCID)
	if err != nil {
		return err
	}

	sealedSectorFd := sealedSector.Fd()
	defer runtime.KeepAlive(sealedSector)

	unsealOutputFd := unsealOutput.Fd()
	defer runtime.KeepAlive(unsealOutput)

	ticketBytes := cgo.AsByteArray32(ticket)
	return cgo.UnsealRange(
		sp,
		cgo.AsSliceRefUint8([]byte(cacheDirPath)),
		int32(sealedSectorFd),
		int32(unsealOutputFd),
		uint64(sectorNum),
		&proverID,
		&ticketBytes,
		&commD,
		unpaddedByteIndex,
		unpaddedBytesAmount,
	)
}

// // GenerateWinningPoStSectorChallenge
// func GenerateWinningPoStSectorChallenge(
// 	proofType abi.RegisteredPoStProof,
// 	minerID abi.ActorID,
// 	randomness abi.PoStRandomness,
// 	eligibleSectorsLen uint64,
// ) ([]uint64, error) {
// 	proverID, err := toProverID(minerID)
// 	if err != nil {
// 		return nil, err
// 	}

// 	pp, err := toFilRegisteredPoStProof(proofType)
// 	if err != nil {
// 		return nil, err
// 	}

// 	resp := cgo.GenerateWinningPostSectorChallenge(
// 		pp, toByteArray32(randomness),
// 		eligibleSectorsLen, proverID,
// 	)
// 	resp.Deref()
// 	resp.IdsPtr = make([]uint64, resp.IdsLen)
// 	resp.Deref()

// 	defer cgo.DestroyGenerateWinningPostSectorChallenge(resp)

// 	if resp.StatusCode != cgo.FCPResponseStatusFCPNoError {
// 		return nil, errors.New(cgo.RawString(resp.ErrorMsg).Copy())
// 	}

// 	// copy from C memory space to Go
// 	out := make([]uint64, resp.IdsLen)
// 	for idx := range out {
// 		out[idx] = resp.IdsPtr[idx]
// 	}

// 	return out, nil
// }

// // GenerateWinningPoSt
// func GenerateWinningPoSt(
// 	minerID abi.ActorID,
// 	privateSectorInfo SortedPrivateSectorInfo,
// 	randomness abi.PoStRandomness,
// ) ([]proof5.PoStProof, error) {
// 	filReplicas, filReplicasLen, free, err := toFilPrivateReplicaInfos(privateSectorInfo.Values(), "winning")
// 	if err != nil {
// 		return nil, errors.Wrap(err, "failed to create private replica info array for FFI")
// 	}
// 	defer free()

// 	proverID, err := toProverID(minerID)
// 	if err != nil {
// 		return nil, err
// 	}

// 	resp := cgo.GenerateWinningPost(
// 		toByteArray32(randomness),
// 		filReplicas, filReplicasLen,
// 		proverID,
// 	)
// 	resp.Deref()
// 	resp.ProofsPtr = make([]cgo.PoStProof, resp.ProofsLen)
// 	resp.Deref()

// 	defer cgo.DestroyGenerateWinningPostResponse(resp)

// 	if resp.StatusCode != cgo.FCPResponseStatusFCPNoError {
// 		return nil, errors.New(cgo.RawString(resp.ErrorMsg).Copy())
// 	}

// 	proofs, err := fromFilPoStProofs(resp.ProofsPtr)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return proofs, nil
// }

// // GenerateWindowPoSt
// func GenerateWindowPoSt(
// 	minerID abi.ActorID,
// 	privateSectorInfo SortedPrivateSectorInfo,
// 	randomness abi.PoStRandomness,
// ) ([]proof5.PoStProof, []abi.SectorNumber, error) {
// 	filReplicas, filReplicasLen, free, err := toFilPrivateReplicaInfos(privateSectorInfo.Values(), "window")
// 	if err != nil {
// 		return nil, nil, errors.Wrap(err, "failed to create private replica info array for FFI")
// 	}
// 	defer free()

// 	proverID, err := toProverID(minerID)
// 	if err != nil {
// 		return nil, nil, err
// 	}

// 	resp := cgo.GenerateWindowPost(toByteArray32(randomness), filReplicas, filReplicasLen, proverID)
// 	resp.Deref()
// 	resp.ProofsPtr = make([]cgo.PoStProof, resp.ProofsLen)
// 	resp.Deref()
// 	resp.FaultySectorsPtr = resp.FaultySectorsPtr[:resp.FaultySectorsLen]

// 	defer cgo.DestroyGenerateWindowPostResponse(resp)

// 	faultySectors, err := fromFilPoStFaultySectors(resp.FaultySectorsPtr, resp.FaultySectorsLen)
// 	if err != nil {
// 		return nil, nil, xerrors.Errorf("failed to parse faulty sectors list: %w", err)
// 	}

// 	if resp.StatusCode != cgo.FCPResponseStatusFCPNoError {
// 		return nil, faultySectors, errors.New(cgo.RawString(resp.ErrorMsg).Copy())
// 	}

// 	proofs, err := fromFilPoStProofs(resp.ProofsPtr)
// 	if err != nil {
// 		return nil, nil, err
// 	}

// 	return proofs, faultySectors, nil
// }

// // GetGPUDevices produces a slice of strings, each representing the name of a
// // detected GPU device.
// func GetGPUDevices() ([]string, error) {
// 	resp := cgo.GetGpuDevices()
// 	resp.Deref()
// 	resp.DevicesPtr = make([]string, resp.DevicesLen)
// 	resp.Deref()

// 	defer cgo.DestroyGpuDeviceResponse(resp)

// 	out := make([]string, len(resp.DevicesPtr))
// 	for idx := range out {
// 		out[idx] = cgo.RawString(resp.DevicesPtr[idx]).Copy()
// 	}

// 	return out, nil
// }

// // GetSealVersion
// func GetSealVersion(proofType abi.RegisteredSealProof) (string, error) {
// 	sp, err := toFilRegisteredSealProof(proofType)
// 	if err != nil {
// 		return "", err
// 	}

// 	resp := cgo.GetSealVersion(sp)
// 	resp.Deref()

// 	defer cgo.DestroyStringResponse(resp)

// 	if resp.StatusCode != cgo.FCPResponseStatusFCPNoError {
// 		return "", errors.New(cgo.RawString(resp.ErrorMsg).Copy())
// 	}

// 	return cgo.RawString(resp.StringVal).Copy(), nil
// }

// // GetPoStVersion
// func GetPoStVersion(proofType abi.RegisteredPoStProof) (string, error) {
// 	pp, err := toFilRegisteredPoStProof(proofType)
// 	if err != nil {
// 		return "", err
// 	}

// 	resp := cgo.GetPostVersion(pp)
// 	resp.Deref()

// 	defer cgo.DestroyStringResponse(resp)

// 	if resp.StatusCode != cgo.FCPResponseStatusFCPNoError {
// 		return "", errors.New(cgo.RawString(resp.ErrorMsg).Copy())
// 	}

// 	return cgo.RawString(resp.StringVal).Copy(), nil
// }

// func GetNumPartitionForFallbackPost(proofType abi.RegisteredPoStProof, numSectors uint) (uint, error) {
// 	pp, err := toFilRegisteredPoStProof(proofType)
// 	if err != nil {
// 		return 0, err
// 	}
// 	resp := cgo.GetNumPartitionForFallbackPost(pp, numSectors)
// 	resp.Deref()
// 	defer cgo.DestroyGetNumPartitionForFallbackPostResponse(resp)

// 	if resp.StatusCode != cgo.FCPResponseStatusFCPNoError {
// 		return 0, errors.New(cgo.RawString(resp.ErrorMsg).Copy())
// 	}

// 	return resp.NumPartition, nil
// }

// // ClearCache
// func ClearCache(sectorSize uint64, cacheDirPath string) error {
// 	resp := cgo.ClearCache(sectorSize, cacheDirPath)
// 	resp.Deref()

// 	defer cgo.DestroyClearCacheResponse(resp)

// 	if resp.StatusCode != cgo.FCPResponseStatusFCPNoError {
// 		return errors.New(cgo.RawString(resp.ErrorMsg).Copy())
// 	}

// 	return nil
// }

// func FauxRep(proofType abi.RegisteredSealProof, cacheDirPath string, sealedSectorPath string) (cid.Cid, error) {
// 	sp, err := toFilRegisteredSealProof(proofType)
// 	if err != nil {
// 		return cid.Undef, err
// 	}

// 	resp := cgo.Fauxrep(sp, cacheDirPath, sealedSectorPath)
// 	resp.Deref()

// 	defer cgo.DestroyFauxrepResponse(resp)

// 	if resp.StatusCode != cgo.FCPResponseStatusFCPNoError {
// 		return cid.Undef, errors.New(cgo.RawString(resp.ErrorMsg).Copy())
// 	}

// 	return commcid.ReplicaCommitmentV1ToCID(resp.Commitment[:])
// }

// func FauxRep2(proofType abi.RegisteredSealProof, cacheDirPath string, existingPAuxPath string) (cid.Cid, error) {
// 	sp, err := toFilRegisteredSealProof(proofType)
// 	if err != nil {
// 		return cid.Undef, err
// 	}

// 	resp := cgo.Fauxrep2(sp, cacheDirPath, existingPAuxPath)
// 	resp.Deref()

// 	defer cgo.DestroyFauxrepResponse(resp)

// 	if resp.StatusCode != cgo.FCPResponseStatusFCPNoError {
// 		return cid.Undef, errors.New(cgo.RawString(resp.ErrorMsg).Copy())
// 	}

// 	return commcid.ReplicaCommitmentV1ToCID(resp.Commitment[:])
// }

func toFilExistingPieceSizes(src []abi.UnpaddedPieceSize) []uint64 {
	out := make([]uint64, len(src))

	for idx := range out {
		out[idx] = uint64(src[idx])
	}

	return out
}

func toFilPublicPieceInfos(src []abi.PieceInfo) ([]cgo.PublicPieceInfo, error) {
	out := make([]cgo.PublicPieceInfo, len(src))

	for idx := range out {
		commP, err := to32ByteCommP(src[idx].PieceCID)
		if err != nil {
			return nil, err
		}

		out[idx] = cgo.NewPublicPieceInfo(uint64(src[idx].Size.Unpadded()), commP)
	}

	return out, nil
}

func toFilPublicReplicaInfos(src []proof5.SectorInfo, typ string) ([]cgo.PublicReplicaInfo, error) {
	out := make([]cgo.PublicReplicaInfo, len(src))

	for idx := range out {
		commR, err := to32ByteCommR(src[idx].SealedCID)
		if err != nil {
			return nil, err
		}

		var pp cgo.RegisteredPoStProof

		switch typ {
		case "window":
			p, err := src[idx].SealProof.RegisteredWindowPoStProof()
			if err != nil {
				return nil, err
			}

			pp, err = toFilRegisteredPoStProof(p)
			if err != nil {
				return nil, err
			}
		case "winning":
			p, err := src[idx].SealProof.RegisteredWinningPoStProof()
			if err != nil {
				return nil, err
			}

			pp, err = toFilRegisteredPoStProof(p)
			if err != nil {
				return nil, err
			}
		}

		out[idx] = cgo.NewPublicReplicaInfo(pp, commR, uint64(src[idx].SectorNumber))
	}

	return out, nil
}

func toFilPrivateReplicaInfo(src PrivateSectorInfo) (cgo.PrivateReplicaInfo, error) {
	commR, err := to32ByteCommR(src.SealedCID)
	if err != nil {
		return cgo.PrivateReplicaInfo{}, err
	}

	pp, err := toFilRegisteredPoStProof(src.PoStProofType)
	if err != nil {
		return cgo.PrivateReplicaInfo{}, err
	}

	cacheDirPath, err := cgo.AsSliceBoxedUint8([]byte(src.CacheDirPath))
	if err != nil {
		return cgo.PrivateReplicaInfo{}, err
	}
	sealedSectorPath, err := cgo.AsSliceBoxedUint8([]byte(src.SealedSectorPath))
	if err != nil {
		return cgo.PrivateReplicaInfo{}, err
	}

	out := cgo.NewPrivateReplicaInfo(
		pp,
		cacheDirPath,
		commR,
		sealedSectorPath,
		uint64(src.SectorNumber),
	)

	return out, nil
}

func toFilPrivateReplicaInfos(src []PrivateSectorInfo, typ string) ([]cgo.PrivateReplicaInfo, error) {
	out := make([]cgo.PrivateReplicaInfo, len(src))

	for idx := range out {
		commR, err := to32ByteCommR(src[idx].SealedCID)
		if err != nil {
			return nil, err
		}

		pp, err := toFilRegisteredPoStProof(src[idx].PoStProofType)
		if err != nil {
			return nil, err
		}

		cacheDirPath, err := cgo.AsSliceBoxedUint8([]byte(src[idx].CacheDirPath))
		if err != nil {
			return nil, err
		}
		sealedSectorPath, err := cgo.AsSliceBoxedUint8([]byte(src[idx].SealedSectorPath))
		if err != nil {
			return nil, err
		}

		out[idx] = cgo.NewPrivateReplicaInfo(
			pp,
			cacheDirPath,
			commR,
			sealedSectorPath,
			uint64(src[idx].SectorNumber),
		)
	}

	return out, nil
}

func fromFilPoStFaultySectors(ptr []uint64, l uint) ([]abi.SectorNumber, error) {
	if l == 0 {
		return nil, nil
	}

	type sliceHeader struct {
		Data unsafe.Pointer
		Len  int
		Cap  int
	}

	(*sliceHeader)(unsafe.Pointer(&ptr)).Len = int(l) // don't worry about it

	snums := make([]abi.SectorNumber, 0, l)
	for i := uint(0); i < l; i++ {
		snums = append(snums, abi.SectorNumber(ptr[i]))
	}

	return snums, nil
}

func fromFilPoStProofs(src []cgo.PoStProof) ([]proof5.PoStProof, error) {
	out := make([]proof5.PoStProof, len(src))

	for idx := range out {
		pp, err := fromFilRegisteredPoStProof(src[idx].RegisteredProof())
		if err != nil {
			return nil, err
		}

		out[idx] = proof5.PoStProof{
			PoStProof:  pp,
			ProofBytes: copyBytes(src[idx].Proof(), uint(len(src[idx].Proof()))),
		}
	}

	return out, nil
}

func toFilPoStProofs(src []proof5.PoStProof) ([]cgo.PoStProof, error) {
	out := make([]cgo.PoStProof, len(src))
	for idx := range out {
		pp, err := toFilRegisteredPoStProof(src[idx].PoStProof)
		if err != nil {
			return nil, err
		}

		proof, err := cgo.AsSliceBoxedUint8(src[idx].ProofBytes)
		if err != nil {
			return nil, err
		}
		out[idx] = cgo.NewPoStProof(pp, proof)
	}

	return out, nil
}

func toProverID(minerID abi.ActorID) (cgo.ByteArray32, error) {
	maddr, err := address.NewIDAddress(uint64(minerID))
	if err != nil {
		return cgo.ByteArray32{}, errors.Wrap(err, "failed to convert ActorID to prover id ([32]byte) for FFI")
	}

	return cgo.AsByteArray32(maddr.Payload()), nil
}

func fromFilRegisteredPoStProof(p cgo.RegisteredPoStProof) (abi.RegisteredPoStProof, error) {
	switch p {
	case cgo.RegisteredPoStProofStackedDrgWinning2KiBV1:
		return abi.RegisteredPoStProof_StackedDrgWinning2KiBV1, nil
	case cgo.RegisteredPoStProofStackedDrgWinning8MiBV1:
		return abi.RegisteredPoStProof_StackedDrgWinning8MiBV1, nil
	case cgo.RegisteredPoStProofStackedDrgWinning512MiBV1:
		return abi.RegisteredPoStProof_StackedDrgWinning512MiBV1, nil
	case cgo.RegisteredPoStProofStackedDrgWinning32GiBV1:
		return abi.RegisteredPoStProof_StackedDrgWinning32GiBV1, nil
	case cgo.RegisteredPoStProofStackedDrgWinning64GiBV1:
		return abi.RegisteredPoStProof_StackedDrgWinning64GiBV1, nil

	case cgo.RegisteredPoStProofStackedDrgWindow2KiBV1:
		return abi.RegisteredPoStProof_StackedDrgWindow2KiBV1, nil
	case cgo.RegisteredPoStProofStackedDrgWindow8MiBV1:
		return abi.RegisteredPoStProof_StackedDrgWindow8MiBV1, nil
	case cgo.RegisteredPoStProofStackedDrgWindow512MiBV1:
		return abi.RegisteredPoStProof_StackedDrgWindow512MiBV1, nil
	case cgo.RegisteredPoStProofStackedDrgWindow32GiBV1:
		return abi.RegisteredPoStProof_StackedDrgWindow32GiBV1, nil
	case cgo.RegisteredPoStProofStackedDrgWindow64GiBV1:
		return abi.RegisteredPoStProof_StackedDrgWindow64GiBV1, nil
	default:
		return 0, errors.Errorf("no mapping to abi.RegisteredPoStProof value available for: %v", p)
	}
}

func toFilRegisteredPoStProof(p abi.RegisteredPoStProof) (cgo.RegisteredPoStProof, error) {
	switch p {
	case abi.RegisteredPoStProof_StackedDrgWinning2KiBV1:
		return cgo.RegisteredPoStProofStackedDrgWinning2KiBV1, nil
	case abi.RegisteredPoStProof_StackedDrgWinning8MiBV1:
		return cgo.RegisteredPoStProofStackedDrgWinning8MiBV1, nil
	case abi.RegisteredPoStProof_StackedDrgWinning512MiBV1:
		return cgo.RegisteredPoStProofStackedDrgWinning512MiBV1, nil
	case abi.RegisteredPoStProof_StackedDrgWinning32GiBV1:
		return cgo.RegisteredPoStProofStackedDrgWinning32GiBV1, nil
	case abi.RegisteredPoStProof_StackedDrgWinning64GiBV1:
		return cgo.RegisteredPoStProofStackedDrgWinning64GiBV1, nil

	case abi.RegisteredPoStProof_StackedDrgWindow2KiBV1:
		return cgo.RegisteredPoStProofStackedDrgWindow2KiBV1, nil
	case abi.RegisteredPoStProof_StackedDrgWindow8MiBV1:
		return cgo.RegisteredPoStProofStackedDrgWindow8MiBV1, nil
	case abi.RegisteredPoStProof_StackedDrgWindow512MiBV1:
		return cgo.RegisteredPoStProofStackedDrgWindow512MiBV1, nil
	case abi.RegisteredPoStProof_StackedDrgWindow32GiBV1:
		return cgo.RegisteredPoStProofStackedDrgWindow32GiBV1, nil
	case abi.RegisteredPoStProof_StackedDrgWindow64GiBV1:
		return cgo.RegisteredPoStProofStackedDrgWindow64GiBV1, nil
	default:
		return 0, errors.Errorf("no mapping to abi.RegisteredPoStProof value available for: %v", p)
	}
}

func toFilRegisteredSealProof(p abi.RegisteredSealProof) (cgo.RegisteredSealProof, error) {
	switch p {
	case abi.RegisteredSealProof_StackedDrg2KiBV1:
		return cgo.RegisteredSealProofStackedDrg2KiBV1, nil
	case abi.RegisteredSealProof_StackedDrg8MiBV1:
		return cgo.RegisteredSealProofStackedDrg8MiBV1, nil
	case abi.RegisteredSealProof_StackedDrg512MiBV1:
		return cgo.RegisteredSealProofStackedDrg512MiBV1, nil
	case abi.RegisteredSealProof_StackedDrg32GiBV1:
		return cgo.RegisteredSealProofStackedDrg32GiBV1, nil
	case abi.RegisteredSealProof_StackedDrg64GiBV1:
		return cgo.RegisteredSealProofStackedDrg64GiBV1, nil

	case abi.RegisteredSealProof_StackedDrg2KiBV1_1:
		return cgo.RegisteredSealProofStackedDrg2KiBV11, nil
	case abi.RegisteredSealProof_StackedDrg8MiBV1_1:
		return cgo.RegisteredSealProofStackedDrg8MiBV11, nil
	case abi.RegisteredSealProof_StackedDrg512MiBV1_1:
		return cgo.RegisteredSealProofStackedDrg512MiBV11, nil
	case abi.RegisteredSealProof_StackedDrg32GiBV1_1:
		return cgo.RegisteredSealProofStackedDrg32GiBV11, nil
	case abi.RegisteredSealProof_StackedDrg64GiBV1_1:
		return cgo.RegisteredSealProofStackedDrg64GiBV11, nil
	default:
		return 0, errors.Errorf("no mapping to C.FFIRegisteredSealProof value available for: %v", p)
	}
}

func toFilRegisteredAggregationProof(p abi.RegisteredAggregationProof) (cgo.RegisteredAggregationProof, error) {
	switch p {
	case abi.RegisteredAggregationProof_SnarkPackV1:
		return cgo.RegisteredAggregationProofSnarkPackV1, nil
	default:
		return 0, errors.Errorf("no mapping to abi.RegisteredAggregationProof value available for: %v", p)
	}
}

func to32ByteCommD(unsealedCID cid.Cid) (cgo.ByteArray32, error) {
	commD, err := commcid.CIDToDataCommitmentV1(unsealedCID)
	if err != nil {
		return cgo.ByteArray32{}, errors.Wrap(err, "failed to transform sealed CID to CommD")
	}

	return cgo.AsByteArray32(commD), nil
}

func to32ByteCommR(sealedCID cid.Cid) (cgo.ByteArray32, error) {
	commR, err := commcid.CIDToReplicaCommitmentV1(sealedCID)
	if err != nil {
		return cgo.ByteArray32{}, errors.Wrap(err, "failed to transform sealed CID to CommR")
	}

	return cgo.AsByteArray32(commR), nil
}

func to32ByteCommP(pieceCID cid.Cid) (cgo.ByteArray32, error) {
	commP, err := commcid.CIDToPieceCommitmentV1(pieceCID)
	if err != nil {
		return cgo.ByteArray32{}, errors.Wrap(err, "failed to transform sealed CID to CommP")
	}

	return cgo.AsByteArray32(commP), nil
}

func copyBytes(v []byte, vLen uint) []byte {
	buf := make([]byte, vLen)
	if n := copy(buf, v[:vLen]); n != int(vLen) {
		panic("partial read")
	}

	return buf
}

// type stringHeader struct {
// 	Data unsafe.Pointer
// 	Len  int
// }

// func toVanillaProofs(src [][]byte) ([]Bytes, func()) {
// 	allocs := make([]AllocationManager, len(src))

// 	out := make([]cgo.VanillaProof, len(src))
// 	for idx := range out {
// 		out[idx] = Bytes{
// 			ProofLen: uint(len(src[idx])),
// 			ProofPtr: src[idx],
// 		}

// 		_, allocs[idx] = out[idx].PassRef()
// 	}

// 	return out, func() {
// 		for idx := range allocs {
// 			allocs[idx].Free()
// 		}
// 	}
// }

// func toPartitionProofs(src []PartitionProof) ([]cgo.PartitionSnarkProofT, func(), error) {
// 	allocs := make([]AllocationManager, len(src))
// 	cleanup := func() {
// 		for idx := range allocs {
// 			allocs[idx].Free()
// 		}
// 	}

// 	out := make([]cgo.PartitionSnarkProof, len(src))
// 	for idx := range out {
// 		rp, err := toFilRegisteredPoStProof(src[idx].PoStProof)
// 		if err != nil {
// 			return nil, cleanup, err
// 		}

// 		out[idx] = cgo.PartitionSnarkProofT{
// 			RegisteredProof: rp,
// 			ProofLen:        uint(len(src[idx].ProofBytes)),
// 			ProofPtr:        src[idx].ProofBytes,
// 		}

// 		_, allocs[idx] = out[idx].PassRef()
// 	}

// 	return out, cleanup, nil
// }
