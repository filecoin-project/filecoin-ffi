//go:build cgo
// +build cgo

package ffi

// #cgo linux LDFLAGS: ${SRCDIR}/libfilcrypto.a -Wl,-unresolved-symbols=ignore-all
// #cgo darwin LDFLAGS: ${SRCDIR}/libfilcrypto.a -Wl,-undefined,dynamic_lookup
// #cgo pkg-config: ${SRCDIR}/filcrypto.pc
// #include "./filcrypto.h"
import "C"
import (
	"os"
	"runtime"

	"github.com/filecoin-project/go-state-types/proof"

	"github.com/ipfs/go-cid"
	"github.com/pkg/errors"
	"golang.org/x/xerrors"

	"github.com/filecoin-project/go-address"
	commcid "github.com/filecoin-project/go-fil-commcid"
	"github.com/filecoin-project/go-state-types/abi"

	"github.com/filecoin-project/filecoin-ffi/cgo"
)

// VerifySeal returns true if the sealing operation from which its inputs were
// derived was valid, and false if not.
func VerifySeal(info proof.SealVerifyInfo) (bool, error) {
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

func VerifyAggregateSeals(aggregate proof.AggregateSealVerifyProofAndInfos) (bool, error) {
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
func VerifyWinningPoSt(info proof.WinningPoStVerifyInfo) (bool, error) {
	filPublicReplicaInfos, err := toFilPublicReplicaInfosForWinningPoSt(info.ChallengedSectors)
	if err != nil {
		return false, errors.Wrap(err, "failed to create public replica info array for FFI")
	}

	filPoStProofs, cleanup, err := toFilPoStProofs(info.Proofs)
	if err != nil {
		return false, errors.Wrap(err, "failed to create PoSt proofs array for FFI")
	}
	defer cleanup()

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
func VerifyWindowPoSt(info proof.WindowPoStVerifyInfo) (bool, error) {
	if len(info.Proofs) == 0 {
		return false, errors.New("nothing to verify")
	}
	filPublicReplicaInfos, err := toFilPublicReplicaInfosForWindowPoSt(info.ChallengedSectors, info.Proofs[0].PoStProof)
	if err != nil {
		return false, errors.Wrap(err, "failed to create public replica info array for FFI")
	}

	filPoStProofs, cleanup, err := toFilPoStProofs(info.Proofs)
	if err != nil {
		return false, errors.Wrap(err, "failed to create PoSt proofs array for FFI")
	}
	defer cleanup()

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

// SealCommitPhase2CircuitProofs runs a non-interactive proof and returns the circuit proof bytes
// rather than the aggregated proof bytes. This is used to aggregate multiple non-interactive
// proofs as the aggregated single proof outputs can't further be aggregated.
func SealCommitPhase2CircuitProofs(phase1Output []byte, sectorNum abi.SectorNumber) ([]byte, error) {
	return cgo.SealCommitPhase2CircuitProofs(cgo.AsSliceRefUint8(phase1Output), uint64(sectorNum))
}

// TODO AggregateSealProofs it only needs InteractiveRandomness out of the aggregateInfo.Infos
func AggregateSealProofs(aggregateInfo proof.AggregateSealVerifyProofAndInfos, proofs [][]byte) (out []byte, err error) {
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

	pfs, cleaner := toVanillaProofs(proofs)
	defer cleaner()

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

func GenerateSDR(
	proofType abi.RegisteredSealProof,
	cacheDirPath string,
	replicaId [32]byte,
) (err error) {
	sp, err := toFilRegisteredSealProof(proofType)
	if err != nil {
		return err
	}

	replicaIdtBytes := cgo.AsByteArray32(replicaId[:])

	return cgo.GenerateSDR(
		sp,
		cgo.AsSliceRefUint8([]byte(cacheDirPath)),
		&replicaIdtBytes,
	)
}

// GenerateWinningPoStSectorChallenge
func GenerateWinningPoStSectorChallenge(
	proofType abi.RegisteredPoStProof,
	minerID abi.ActorID,
	randomness abi.PoStRandomness,
	eligibleSectorsLen uint64,
) ([]uint64, error) {
	proverID, err := toProverID(minerID)
	if err != nil {
		return nil, err
	}

	pp, err := toFilRegisteredPoStProof(proofType)
	if err != nil {
		return nil, err
	}

	randomnessBytes := cgo.AsByteArray32(randomness)

	return cgo.GenerateWinningPoStSectorChallenge(pp, &randomnessBytes, eligibleSectorsLen, &proverID)
}

// GenerateWinningPoSt
func GenerateWinningPoSt(
	minerID abi.ActorID,
	privateSectorInfo SortedPrivateSectorInfo,
	randomness abi.PoStRandomness,
) ([]proof.PoStProof, error) {
	filReplicas, cleanup, err := toFilPrivateReplicaInfos(privateSectorInfo.Values(), "winning")
	if err != nil {
		return nil, errors.Wrap(err, "failed to create private replica info array for FFI")
	}
	defer cleanup()

	proverID, err := toProverID(minerID)
	if err != nil {
		return nil, err
	}
	randomnessBytes := cgo.AsByteArray32(randomness)
	rawProofs, err := cgo.GenerateWinningPoSt(&randomnessBytes, cgo.AsSliceRefPrivateReplicaInfo(filReplicas), &proverID)
	if err != nil {
		return nil, err
	}

	proofs, err := fromFilPoStProofs(rawProofs)
	if err != nil {
		return nil, err
	}

	return proofs, nil
}

// GenerateWindowPoSt
func GenerateWindowPoSt(
	minerID abi.ActorID,
	privateSectorInfo SortedPrivateSectorInfo,
	randomness abi.PoStRandomness,
) ([]proof.PoStProof, []abi.SectorNumber, error) {
	filReplicas, cleanup, err := toFilPrivateReplicaInfos(privateSectorInfo.Values(), "window")
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to create private replica info array for FFI")
	}
	defer cleanup()

	proverID, err := toProverID(minerID)
	if err != nil {
		return nil, nil, err
	}

	randomnessBytes := cgo.AsByteArray32(randomness)
	proofsRaw, faultsRaw, err := cgo.GenerateWindowPoSt(&randomnessBytes, cgo.AsSliceRefPrivateReplicaInfo(filReplicas), &proverID)
	if err != nil {
		faultySectors := fromFilPoStFaultySectors(faultsRaw)
		return nil, faultySectors, err
	}

	proofs, err := fromFilPoStProofs(proofsRaw)
	if err != nil {
		return nil, nil, err
	}

	return proofs, nil, nil
}

// GetGPUDevices produces a slice of strings, each representing the name of a
// detected GPU device.
func GetGPUDevices() ([]string, error) {
	return cgo.GetGpuDevices()
}

// GetSealVersion
func GetSealVersion(proofType abi.RegisteredSealProof) (string, error) {
	sp, err := toFilRegisteredSealProof(proofType)
	if err != nil {
		return "", err
	}

	return cgo.GetSealVersion(sp)
}

// GetPoStVersion
func GetPoStVersion(proofType abi.RegisteredPoStProof) (string, error) {
	pp, err := toFilRegisteredPoStProof(proofType)
	if err != nil {
		return "", err
	}

	return cgo.GetPoStVersion(pp)
}

func GetNumPartitionForFallbackPost(proofType abi.RegisteredPoStProof, numSectors uint) (uint, error) {
	pp, err := toFilRegisteredPoStProof(proofType)
	if err != nil {
		return 0, err
	}

	return cgo.GetNumPartitionForFallbackPost(pp, numSectors)
}

// ClearCache
func ClearCache(sectorSize uint64, cacheDirPath string) error {
	return cgo.ClearCache(sectorSize, cgo.AsSliceRefUint8([]byte(cacheDirPath)))
}

// ClearSyntheticProofs
func ClearSyntheticProofs(sectorSize uint64, cacheDirPath string) error {
	return cgo.ClearSyntheticProofs(sectorSize, cgo.AsSliceRefUint8([]byte(cacheDirPath)))
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
	sp, err := toFilRegisteredSealProof(proofType)
	if err != nil {
		return err
	}
	filPublicPieceInfos, err := toFilPublicPieceInfos(pieces)
	if err != nil {
		return err
	}
	commR, err := to32ByteCommR(sealedCID)
	if err != nil {
		return err
	}

	commD, err := to32ByteCommD(unsealedCID)
	if err != nil {
		return err
	}
	proverID, err := toProverID(minerID)
	if err != nil {
		return err
	}
	return cgo.GenerateSynthProofs(sp,
		commR, commD,
		cgo.AsSliceRefUint8([]byte(cacheDirPath)), cgo.AsSliceRefUint8([]byte(replicaPath)),
		uint64(sector_id),
		proverID, cgo.AsByteArray32(ticket),
		cgo.AsSliceRefPublicPieceInfo(filPublicPieceInfos))
}

func FauxRep(proofType abi.RegisteredSealProof, cacheDirPath string, sealedSectorPath string) (cid.Cid, error) {
	sp, err := toFilRegisteredSealProof(proofType)
	if err != nil {
		return cid.Undef, err
	}

	rawCid, err := cgo.Fauxrep(sp, cgo.AsSliceRefUint8([]byte(cacheDirPath)), cgo.AsSliceRefUint8([]byte(sealedSectorPath)))
	if err != nil {
		return cid.Undef, err
	}

	return commcid.ReplicaCommitmentV1ToCID(rawCid)
}

func FauxRep2(proofType abi.RegisteredSealProof, cacheDirPath string, existingPAuxPath string) (cid.Cid, error) {
	sp, err := toFilRegisteredSealProof(proofType)
	if err != nil {
		return cid.Undef, err
	}

	rawCid, err := cgo.Fauxrep2(sp, cgo.AsSliceRefUint8([]byte(cacheDirPath)), cgo.AsSliceRefUint8([]byte(existingPAuxPath)))
	if err != nil {
		return cid.Undef, err
	}

	return commcid.ReplicaCommitmentV1ToCID(rawCid)
}

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

func toFilPublicReplicaInfosForWinningPoSt(src []proof.SectorInfo) ([]cgo.PublicReplicaInfo, error) {
	out := make([]cgo.PublicReplicaInfo, len(src))

	for idx := range out {
		commR, err := to32ByteCommR(src[idx].SealedCID)
		if err != nil {
			return nil, err
		}

		p, err := src[idx].SealProof.RegisteredWinningPoStProof()
		if err != nil {
			return nil, err
		}

		pp, err := toFilRegisteredPoStProof(p)
		if err != nil {
			return nil, err
		}

		out[idx] = cgo.NewPublicReplicaInfo(pp, commR, uint64(src[idx].SectorNumber))
	}

	return out, nil
}

func toFilPublicReplicaInfosForWindowPoSt(src []proof.SectorInfo, postProofType abi.RegisteredPoStProof) ([]cgo.PublicReplicaInfo, error) {
	out := make([]cgo.PublicReplicaInfo, len(src))

	for idx := range out {
		commR, err := to32ByteCommR(src[idx].SealedCID)
		if err != nil {
			return nil, err
		}

		pp, err := toFilRegisteredPoStProof(postProofType)
		if err != nil {
			return nil, err
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

	return cgo.NewPrivateReplicaInfo(
		pp,
		src.CacheDirPath,
		commR,
		src.SealedSectorPath,
		uint64(src.SectorNumber),
	), nil
}

func makeCleanerPRI(src []cgo.PrivateReplicaInfo, limit int) func() {
	return func() {
		for i := 0; i < limit; i++ {
			src[i].Destroy()
		}
	}
}

func toFilPrivateReplicaInfos(src []PrivateSectorInfo, typ string) ([]cgo.PrivateReplicaInfo, func(), error) {
	out := make([]cgo.PrivateReplicaInfo, len(src))

	for idx := range out {
		commR, err := to32ByteCommR(src[idx].SealedCID)
		if err != nil {
			makeCleanerPRI(out, idx)()
			return nil, nil, err
		}

		pp, err := toFilRegisteredPoStProof(src[idx].PoStProofType)
		if err != nil {
			makeCleanerPRI(out, idx)()
			return nil, nil, err
		}

		out[idx] = cgo.NewPrivateReplicaInfo(
			pp,
			src[idx].CacheDirPath,
			commR,
			src[idx].SealedSectorPath,
			uint64(src[idx].SectorNumber),
		)
	}

	return out, makeCleanerPRI(out, len(src)), nil
}

func fromFilPoStFaultySectors(ptr []uint64) []abi.SectorNumber {
	snums := make([]abi.SectorNumber, len(ptr))
	for i := range ptr {
		snums[i] = abi.SectorNumber(ptr[i])
	}

	return snums
}

func fromFilPoStProofs(src []cgo.PoStProofGo) ([]proof.PoStProof, error) {
	out := make([]proof.PoStProof, len(src))

	for idx := range out {
		pp, err := fromFilRegisteredPoStProof(src[idx].RegisteredProof)
		if err != nil {
			return nil, err
		}

		out[idx] = proof.PoStProof{
			PoStProof:  pp,
			ProofBytes: src[idx].Proof,
		}
	}

	return out, nil
}

func toFilPoStProofs(src []proof.PoStProof) ([]cgo.PoStProof, func(), error) {
	out := make([]cgo.PoStProof, len(src))
	for idx := range out {
		pp, err := toFilRegisteredPoStProof(src[idx].PoStProof)
		if err != nil {
			makeCleanerPOST(out, idx)()
			return nil, nil, err
		}

		out[idx] = cgo.NewPoStProof(pp, src[idx].ProofBytes)
	}

	return out, makeCleanerPOST(out, len(src)), nil
}

func makeCleanerPOST(src []cgo.PoStProof, limit int) func() {
	return func() {
		for i := 0; i < limit; i++ {
			src[i].Destroy()
		}
	}
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

	case cgo.RegisteredPoStProofStackedDrgWindow2KiBV1_1:
		return abi.RegisteredPoStProof_StackedDrgWindow2KiBV1_1, nil
	case cgo.RegisteredPoStProofStackedDrgWindow8MiBV1_1:
		return abi.RegisteredPoStProof_StackedDrgWindow8MiBV1_1, nil
	case cgo.RegisteredPoStProofStackedDrgWindow512MiBV1_1:
		return abi.RegisteredPoStProof_StackedDrgWindow512MiBV1_1, nil
	case cgo.RegisteredPoStProofStackedDrgWindow32GiBV1_1:
		return abi.RegisteredPoStProof_StackedDrgWindow32GiBV1_1, nil
	case cgo.RegisteredPoStProofStackedDrgWindow64GiBV1_1:
		return abi.RegisteredPoStProof_StackedDrgWindow64GiBV1_1, nil
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

	case abi.RegisteredPoStProof_StackedDrgWindow2KiBV1_1:
		return cgo.RegisteredPoStProofStackedDrgWindow2KiBV1_1, nil
	case abi.RegisteredPoStProof_StackedDrgWindow8MiBV1_1:
		return cgo.RegisteredPoStProofStackedDrgWindow8MiBV1_1, nil
	case abi.RegisteredPoStProof_StackedDrgWindow512MiBV1_1:
		return cgo.RegisteredPoStProofStackedDrgWindow512MiBV1_1, nil
	case abi.RegisteredPoStProof_StackedDrgWindow32GiBV1_1:
		return cgo.RegisteredPoStProofStackedDrgWindow32GiBV1_1, nil
	case abi.RegisteredPoStProof_StackedDrgWindow64GiBV1_1:
		return cgo.RegisteredPoStProofStackedDrgWindow64GiBV1_1, nil
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

	case abi.RegisteredSealProof_StackedDrg2KiBV1_1_Feat_SyntheticPoRep:
		return cgo.RegisteredSealProofStackedDrg2KiBV11_Feat_SyntheticPoRep, nil
	case abi.RegisteredSealProof_StackedDrg8MiBV1_1_Feat_SyntheticPoRep:
		return cgo.RegisteredSealProofStackedDrg8MiBV11_Feat_SyntheticPoRep, nil
	case abi.RegisteredSealProof_StackedDrg512MiBV1_1_Feat_SyntheticPoRep:
		return cgo.RegisteredSealProofStackedDrg512MiBV11_Feat_SyntheticPoRep, nil
	case abi.RegisteredSealProof_StackedDrg32GiBV1_1_Feat_SyntheticPoRep:
		return cgo.RegisteredSealProofStackedDrg32GiBV11_Feat_SyntheticPoRep, nil
	case abi.RegisteredSealProof_StackedDrg64GiBV1_1_Feat_SyntheticPoRep:
		return cgo.RegisteredSealProofStackedDrg64GiBV11_Feat_SyntheticPoRep, nil

	case abi.RegisteredSealProof_StackedDrg2KiBV1_2_Feat_NiPoRep:
		return cgo.RegisteredSealProofStackedDrg2KiBV1_2_Feat_NonInteractivePoRep, nil
	case abi.RegisteredSealProof_StackedDrg8MiBV1_2_Feat_NiPoRep:
		return cgo.RegisteredSealProofStackedDrg8MiBV1_2_Feat_NonInteractivePoRep, nil
	case abi.RegisteredSealProof_StackedDrg512MiBV1_2_Feat_NiPoRep:
		return cgo.RegisteredSealProofStackedDrg512MiBV1_2_Feat_NonInteractivePoRep, nil
	case abi.RegisteredSealProof_StackedDrg32GiBV1_2_Feat_NiPoRep:
		return cgo.RegisteredSealProofStackedDrg32GiBV1_2_Feat_NonInteractivePoRep, nil
	case abi.RegisteredSealProof_StackedDrg64GiBV1_2_Feat_NiPoRep:
		return cgo.RegisteredSealProofStackedDrg64GiBV1_2_Feat_NonInteractivePoRep, nil

	default:
		return 0, errors.Errorf("no mapping to C.FFIRegisteredSealProof value available for: %v", p)
	}
}

func toFilRegisteredAggregationProof(p abi.RegisteredAggregationProof) (cgo.RegisteredAggregationProof, error) {
	switch p {
	case abi.RegisteredAggregationProof_SnarkPackV1:
		return cgo.RegisteredAggregationProofSnarkPackV1, nil
	case abi.RegisteredAggregationProof_SnarkPackV2:
		return cgo.RegisteredAggregationProofSnarkPackV2, nil
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

func makeCleanerSBU(src []cgo.SliceBoxedUint8, limit int) func() {
	return func() {
		for i := 0; i < limit; i++ {
			src[i].Destroy()
		}
	}
}

func toVanillaProofs(src [][]byte) ([]cgo.SliceBoxedUint8, func()) {
	out := make([]cgo.SliceBoxedUint8, len(src))

	for i := range out {
		out[i] = cgo.AllocSliceBoxedUint8(src[i])
	}

	return out, makeCleanerSBU(out, len(src))
}
