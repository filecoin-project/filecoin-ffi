//+build cgo

package ffi

// #cgo LDFLAGS: ${SRCDIR}/libfilcrypto_v2.a
// #cgo pkg-config: ${SRCDIR}/filcrypto-v2.pc
// #include "./ffi-common.h"
// #include "./filcrypto-v2.h"
import "C"
import (
	"os"
	"runtime"
	"unsafe"

	"github.com/filecoin-project/go-address"
	commcid "github.com/filecoin-project/go-fil-commcid"

	// FIXME: local fork for upgrade testing
	//"github.com/filecoin-project/go-state-types/abi"
	"github.com/cryptonemo/go-state-types/abi"

	"github.com/filecoin-project/specs-actors/actors/runtime/proof"
	"github.com/ipfs/go-cid"
	"github.com/pkg/errors"
	"golang.org/x/xerrors"

	"github.com/filecoin-project/filecoin-ffi/generated_v2"
)

// VerifySeal returns true if the sealing operation from which its inputs were
// derived was valid, and false if not.
func VerifySealV2(info proof.SealVerifyInfo) (bool, error) {
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

	resp := generated_v2.FilVerifySeal(sp, commR, commD, proverID, to32ByteArray(info.Randomness), to32ByteArray(info.InteractiveRandomness), uint64(info.SectorID.Number), string(info.Proof), uint(len(info.Proof)))
	resp.Deref()

	defer generated_v2.FilDestroyVerifySealResponse(resp)

	if resp.StatusCode != generated_v2.FCPResponseStatusFCPNoError {
		return false, errors.New(generated_v2.RawString(resp.ErrorMsg).Copy())
	}

	return resp.IsValid, nil
}

// VerifyWinningPoSt returns true if the Winning PoSt-generation operation from which its
// inputs were derived was valid, and false if not.
func VerifyWinningPoStV2(info proof.WinningPoStVerifyInfo) (bool, error) {
	filPublicReplicaInfos, filPublicReplicaInfosLen, err := toFilPublicReplicaInfos(info.ChallengedSectors, "winning")
	if err != nil {
		return false, errors.Wrap(err, "failed to create public replica info array for FFI")
	}

	filPoStProofs, filPoStProofsLen, free, err := toFilPoStProofs(info.Proofs)
	if err != nil {
		return false, errors.Wrap(err, "failed to create PoSt proofs array for FFI")
	}
	defer free()

	proverID, err := toProverID(info.Prover)
	if err != nil {
		return false, err
	}

	resp := generated_v2.FilVerifyWinningPost(
		to32ByteArray(info.Randomness),
		filPublicReplicaInfos,
		filPublicReplicaInfosLen,
		filPoStProofs,
		filPoStProofsLen,
		proverID,
	)
	resp.Deref()

	defer generated_v2.FilDestroyVerifyWinningPostResponse(resp)

	if resp.StatusCode != generated_v2.FCPResponseStatusFCPNoError {
		return false, errors.New(generated_v2.RawString(resp.ErrorMsg).Copy())
	}

	return resp.IsValid, nil
}

// VerifyWindowPoSt returns true if the Winning PoSt-generation operation from which its
// inputs were derived was valid, and false if not.
func VerifyWindowPoStV2(info proof.WindowPoStVerifyInfo) (bool, error) {
	filPublicReplicaInfos, filPublicReplicaInfosLen, err := toFilPublicReplicaInfos(info.ChallengedSectors, "window")
	if err != nil {
		return false, errors.Wrap(err, "failed to create public replica info array for FFI")
	}

	filPoStProofs, filPoStProofsLen, free, err := toFilPoStProofs(info.Proofs)
	if err != nil {
		return false, errors.Wrap(err, "failed to create PoSt proofs array for FFI")
	}
	defer free()

	proverID, err := toProverID(info.Prover)
	if err != nil {
		return false, err
	}

	resp := generated_v2.FilVerifyWindowPost(
		to32ByteArray(info.Randomness),
		filPublicReplicaInfos, filPublicReplicaInfosLen,
		filPoStProofs, filPoStProofsLen,
		proverID,
	)
	resp.Deref()

	defer generated_v2.FilDestroyVerifyWindowPostResponse(resp)

	if resp.StatusCode != generated_v2.FCPResponseStatusFCPNoError {
		return false, errors.New(generated_v2.RawString(resp.ErrorMsg).Copy())
	}

	return resp.IsValid, nil
}

// GeneratePieceCommitment produces a piece commitment for the provided data
// stored at a given path.
func GeneratePieceCIDV2(proofType abi.RegisteredSealProof, piecePath string, pieceSize abi.UnpaddedPieceSize) (cid.Cid, error) {
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
func GenerateUnsealedCIDV2(proofType abi.RegisteredSealProof, pieces []abi.PieceInfo) (cid.Cid, error) {
	sp, err := toFilRegisteredSealProof(proofType)
	if err != nil {
		return cid.Undef, err
	}

	filPublicPieceInfos, filPublicPieceInfosLen, err := toFilPublicPieceInfos(pieces)
	if err != nil {
		return cid.Undef, err
	}

	resp := generated_v2.FilGenerateDataCommitment(sp, filPublicPieceInfos, filPublicPieceInfosLen)
	resp.Deref()

	defer generated_v2.FilDestroyGenerateDataCommitmentResponse(resp)

	if resp.StatusCode != generated_v2.FCPResponseStatusFCPNoError {
		return cid.Undef, errors.New(generated_v2.RawString(resp.ErrorMsg).Copy())
	}

	return commcid.DataCommitmentV1ToCID(resp.CommD[:])
}

// GeneratePieceCIDFromFile produces a piece CID for the provided data stored in
//a given file.
func GeneratePieceCIDFromFileV2(proofType abi.RegisteredSealProof, pieceFile *os.File, pieceSize abi.UnpaddedPieceSize) (cid.Cid, error) {
	sp, err := toFilRegisteredSealProof(proofType)
	if err != nil {
		return cid.Undef, err
	}

	pieceFd := pieceFile.Fd()
	defer runtime.KeepAlive(pieceFile)

	resp := generated_v2.FilGeneratePieceCommitment(sp, int32(pieceFd), uint64(pieceSize))
	resp.Deref()

	defer generated_v2.FilDestroyGeneratePieceCommitmentResponse(resp)

	if resp.StatusCode != generated_v2.FCPResponseStatusFCPNoError {
		return cid.Undef, errors.New(generated_v2.RawString(resp.ErrorMsg).Copy())
	}

	return commcid.PieceCommitmentV1ToCID(resp.CommP[:])
}

// WriteWithAlignment
func WriteWithAlignmentV2(
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

	filExistingPieceSizes, filExistingPieceSizesLen := toFilExistingPieceSizes(existingPieceSizes)

	resp := generated_v2.FilWriteWithAlignment(sp, int32(pieceFd), uint64(pieceBytes), int32(stagedSectorFd), filExistingPieceSizes, filExistingPieceSizesLen)
	resp.Deref()

	defer generated_v2.FilDestroyWriteWithAlignmentResponse(resp)

	if resp.StatusCode != generated_v2.FCPResponseStatusFCPNoError {
		return 0, 0, cid.Undef, errors.New(generated_v2.RawString(resp.ErrorMsg).Copy())
	}

	commP, errCommpSize := commcid.PieceCommitmentV1ToCID(resp.CommP[:])
	if errCommpSize != nil {
		return 0, 0, cid.Undef, errCommpSize
	}

	return abi.UnpaddedPieceSize(resp.LeftAlignmentUnpadded), abi.UnpaddedPieceSize(resp.TotalWriteUnpadded), commP, nil
}

// WriteWithoutAlignment
func WriteWithoutAlignmentV2(
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

	resp := generated_v2.FilWriteWithoutAlignment(sp, int32(pieceFd), uint64(pieceBytes), int32(stagedSectorFd))
	resp.Deref()

	defer generated_v2.FilDestroyWriteWithoutAlignmentResponse(resp)

	if resp.StatusCode != generated_v2.FCPResponseStatusFCPNoError {
		return 0, cid.Undef, errors.New(generated_v2.RawString(resp.ErrorMsg).Copy())
	}

	commP, errCommpSize := commcid.PieceCommitmentV1ToCID(resp.CommP[:])
	if errCommpSize != nil {
		return 0, cid.Undef, errCommpSize
	}

	return abi.UnpaddedPieceSize(resp.TotalWriteUnpadded), commP, nil
}

// SealPreCommitPhase1
func SealPreCommitPhase1V2(
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

	filPublicPieceInfos, filPublicPieceInfosLen, err := toFilPublicPieceInfos(pieces)
	if err != nil {
		return nil, err
	}

	resp := generated_v2.FilSealPreCommitPhase1(sp, cacheDirPath, stagedSectorPath, sealedSectorPath, uint64(sectorNum), proverID, to32ByteArray(ticket), filPublicPieceInfos, filPublicPieceInfosLen)
	resp.Deref()

	defer generated_v2.FilDestroySealPreCommitPhase1Response(resp)

	if resp.StatusCode != generated_v2.FCPResponseStatusFCPNoError {
		return nil, errors.New(generated_v2.RawString(resp.ErrorMsg).Copy())
	}

	return []byte(toGoStringCopy(resp.SealPreCommitPhase1OutputPtr, resp.SealPreCommitPhase1OutputLen)), nil
}

// SealPreCommitPhase2
func SealPreCommitPhase2V2(
	phase1Output []byte,
	cacheDirPath string,
	sealedSectorPath string,
) (sealedCID cid.Cid, unsealedCID cid.Cid, err error) {
	resp := generated_v2.FilSealPreCommitPhase2(string(phase1Output), uint(len(phase1Output)), cacheDirPath, sealedSectorPath)
	resp.Deref()

	defer generated_v2.FilDestroySealPreCommitPhase2Response(resp)

	if resp.StatusCode != generated_v2.FCPResponseStatusFCPNoError {
		return cid.Undef, cid.Undef, errors.New(generated_v2.RawString(resp.ErrorMsg).Copy())
	}

	commR, errCommrSize := commcid.ReplicaCommitmentV1ToCID(resp.CommR[:])
	if errCommrSize != nil {
		return cid.Undef, cid.Undef, errCommrSize
	}
	commD, errCommdSize := commcid.DataCommitmentV1ToCID(resp.CommD[:])
	if errCommdSize != nil {
		return cid.Undef, cid.Undef, errCommdSize
	}

	return commR, commD, nil
}

// SealCommitPhase1
func SealCommitPhase1V2(
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

	filPublicPieceInfos, filPublicPieceInfosLen, err := toFilPublicPieceInfos(pieces)
	if err != nil {
		return nil, err
	}

	resp := generated_v2.FilSealCommitPhase1(sp, commR, commD, cacheDirPath, sealedSectorPath, uint64(sectorNum), proverID, to32ByteArray(ticket), to32ByteArray(seed), filPublicPieceInfos, filPublicPieceInfosLen)
	resp.Deref()

	defer generated_v2.FilDestroySealCommitPhase1Response(resp)

	if resp.StatusCode != generated_v2.FCPResponseStatusFCPNoError {
		return nil, errors.New(generated_v2.RawString(resp.ErrorMsg).Copy())
	}

	return []byte(toGoStringCopy(resp.SealCommitPhase1OutputPtr, resp.SealCommitPhase1OutputLen)), nil
}

// SealCommitPhase2
func SealCommitPhase2V2(
	phase1Output []byte,
	sectorNum abi.SectorNumber,
	minerID abi.ActorID,
) ([]byte, error) {
	proverID, err := toProverID(minerID)
	if err != nil {
		return nil, err
	}

	resp := generated_v2.FilSealCommitPhase2(string(phase1Output), uint(len(phase1Output)), uint64(sectorNum), proverID)
	resp.Deref()

	defer generated_v2.FilDestroySealCommitPhase2Response(resp)

	if resp.StatusCode != generated_v2.FCPResponseStatusFCPNoError {
		return nil, errors.New(generated_v2.RawString(resp.ErrorMsg).Copy())
	}

	return []byte(toGoStringCopy(resp.ProofPtr, resp.ProofLen)), nil
}

// Unseal
func UnsealV2(
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
func UnsealRangeV2(
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

	resp := generated_v2.FilUnsealRange(sp, cacheDirPath, int32(sealedSectorFd), int32(unsealOutputFd), uint64(sectorNum), proverID, to32ByteArray(ticket), commD, unpaddedByteIndex, unpaddedBytesAmount)
	resp.Deref()

	defer generated_v2.FilDestroyUnsealRangeResponse(resp)

	if resp.StatusCode != generated_v2.FCPResponseStatusFCPNoError {
		return errors.New(generated_v2.RawString(resp.ErrorMsg).Copy())
	}

	return nil
}

// GenerateWinningPoStSectorChallenge
func GenerateWinningPoStSectorChallengeV2(
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

	resp := generated_v2.FilGenerateWinningPostSectorChallenge(
		pp, to32ByteArray(randomness),
		eligibleSectorsLen, proverID,
	)
	resp.Deref()
	resp.IdsPtr = make([]uint64, resp.IdsLen)
	resp.Deref()

	defer generated_v2.FilDestroyGenerateWinningPostSectorChallenge(resp)

	if resp.StatusCode != generated_v2.FCPResponseStatusFCPNoError {
		return nil, errors.New(generated_v2.RawString(resp.ErrorMsg).Copy())
	}

	// copy from C memory space to Go
	out := make([]uint64, resp.IdsLen)
	for idx := range out {
		out[idx] = resp.IdsPtr[idx]
	}

	return out, nil
}

// GenerateWinningPoSt
func GenerateWinningPoStV2(
	minerID abi.ActorID,
	privateSectorInfo SortedPrivateSectorInfo,
	randomness abi.PoStRandomness,
) ([]proof.PoStProof, error) {
	filReplicas, filReplicasLen, free, err := toFilPrivateReplicaInfos(privateSectorInfo.Values(), "winning")
	if err != nil {
		return nil, errors.Wrap(err, "failed to create private replica info array for FFI")
	}
	defer free()

	proverID, err := toProverID(minerID)
	if err != nil {
		return nil, err
	}

	resp := generated_v2.FilGenerateWinningPost(
		to32ByteArray(randomness),
		filReplicas, filReplicasLen,
		proverID,
	)
	resp.Deref()
	resp.ProofsPtr = make([]generated_v2.FilPoStProof, resp.ProofsLen)
	resp.Deref()

	defer generated_v2.FilDestroyGenerateWinningPostResponse(resp)

	if resp.StatusCode != generated_v2.FCPResponseStatusFCPNoError {
		return nil, errors.New(generated_v2.RawString(resp.ErrorMsg).Copy())
	}

	proofs, err := fromFilPoStProofs(resp.ProofsPtr)
	if err != nil {
		return nil, err
	}

	return proofs, nil
}

// GenerateWindowPoSt
func GenerateWindowPoStV2(
	minerID abi.ActorID,
	privateSectorInfo SortedPrivateSectorInfo,
	randomness abi.PoStRandomness,
) ([]proof.PoStProof, []abi.SectorNumber, error) {
	filReplicas, filReplicasLen, free, err := toFilPrivateReplicaInfos(privateSectorInfo.Values(), "window")
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to create private replica info array for FFI")
	}
	defer free()

	proverID, err := toProverID(minerID)
	if err != nil {
		return nil, nil, err
	}

	resp := generated_v2.FilGenerateWindowPost(to32ByteArray(randomness), filReplicas, filReplicasLen, proverID)
	resp.Deref()
	resp.ProofsPtr = make([]generated_v2.FilPoStProof, resp.ProofsLen)
	resp.Deref()

	defer generated_v2.FilDestroyGenerateWindowPostResponse(resp)

	faultySectors, err := fromFilPoStFaultySectors(resp.FaultySectorsPtr, resp.FaultySectorsLen)
	if err != nil {
		return nil, nil, xerrors.Errorf("failed to parse faulty sectors list: %w", err)
	}

	if resp.StatusCode != generated_v2.FCPResponseStatusFCPNoError {
		return nil, faultySectors, errors.New(generated_v2.RawString(resp.ErrorMsg).Copy())
	}

	proofs, err := fromFilPoStProofs(resp.ProofsPtr)
	if err != nil {
		return nil, nil, err
	}

	return proofs, faultySectors, nil
}

// GetGPUDevices produces a slice of strings, each representing the name of a
// detected GPU device.
func GetGPUDevicesV2() ([]string, error) {
	resp := generated_v2.FilGetGpuDevices()
	resp.Deref()
	resp.DevicesPtr = make([]string, resp.DevicesLen)
	resp.Deref()

	defer generated_v2.FilDestroyGpuDeviceResponse(resp)

	out := make([]string, len(resp.DevicesPtr))
	for idx := range out {
		out[idx] = generated_v2.RawString(resp.DevicesPtr[idx]).Copy()
	}

	return out, nil
}

// GetSealVersion
func GetSealVersionV2(proofType abi.RegisteredSealProof) (string, error) {
	sp, err := toFilRegisteredSealProof(proofType)
	if err != nil {
		return "", err
	}

	resp := generated_v2.FilGetSealVersion(sp)
	resp.Deref()

	defer generated_v2.FilDestroyStringResponse(resp)

	if resp.StatusCode != generated_v2.FCPResponseStatusFCPNoError {
		return "", errors.New(generated_v2.RawString(resp.ErrorMsg).Copy())
	}

	return generated_v2.RawString(resp.StringVal).Copy(), nil
}

// GetPoStVersion
func GetPoStVersionV2(proofType abi.RegisteredPoStProof) (string, error) {
	pp, err := toFilRegisteredPoStProof(proofType)
	if err != nil {
		return "", err
	}

	resp := generated_v2.FilGetPostVersion(pp)
	resp.Deref()

	defer generated_v2.FilDestroyStringResponse(resp)

	if resp.StatusCode != generated_v2.FCPResponseStatusFCPNoError {
		return "", errors.New(generated_v2.RawString(resp.ErrorMsg).Copy())
	}

	return generated_v2.RawString(resp.StringVal).Copy(), nil
}

// ClearCache
func ClearCacheV2(sectorSize uint64, cacheDirPath string) error {
	resp := generated_v2.FilClearCache(sectorSize, cacheDirPath)
	resp.Deref()

	defer generated_v2.FilDestroyClearCacheResponse(resp)

	if resp.StatusCode != generated_v2.FCPResponseStatusFCPNoError {
		return errors.New(generated_v2.RawString(resp.ErrorMsg).Copy())
	}

	return nil
}

func FauxRepV2(proofType abi.RegisteredSealProof, cacheDirPath string, sealedSectorPath string) (cid.Cid, error) {
	sp, err := toFilRegisteredSealProof(proofType)
	if err != nil {
		return cid.Undef, err
	}

	resp := generated_v2.FilFauxrep(sp, cacheDirPath, sealedSectorPath)
	resp.Deref()

	defer generated_v2.FilDestroyFauxrepResponse(resp)

	if resp.StatusCode != generated_v2.FCPResponseStatusFCPNoError {
		return cid.Undef, errors.New(generated_v2.RawString(resp.ErrorMsg).Copy())
	}

	return commcid.ReplicaCommitmentV1ToCID(resp.Commitment[:])
}

func FauxRep2V2(proofType abi.RegisteredSealProof, cacheDirPath string, existingPAuxPath string) (cid.Cid, error) {
	sp, err := toFilRegisteredSealProof(proofType)
	if err != nil {
		return cid.Undef, err
	}

	resp := generated_v2.FilFauxrep2(sp, cacheDirPath, existingPAuxPath)
	resp.Deref()

	defer generated_v2.FilDestroyFauxrepResponse(resp)

	if resp.StatusCode != generated_v2.FCPResponseStatusFCPNoError {
		return cid.Undef, errors.New(generated_v2.RawString(resp.ErrorMsg).Copy())
	}

	return commcid.ReplicaCommitmentV1ToCID(resp.Commitment[:])
}

func toFilExistingPieceSizesV2(src []abi.UnpaddedPieceSize) ([]uint64, uint) {
	out := make([]uint64, len(src))

	for idx := range out {
		out[idx] = uint64(src[idx])
	}

	return out, uint(len(out))
}

func toFilPublicPieceInfosV2(src []abi.PieceInfo) ([]generated_v2.FilPublicPieceInfo, uint, error) {
	out := make([]generated_v2.FilPublicPieceInfo, len(src))

	for idx := range out {
		commP, err := to32ByteCommP(src[idx].PieceCID)
		if err != nil {
			return nil, 0, err
		}

		out[idx] = generated_v2.FilPublicPieceInfo{
			NumBytes: uint64(src[idx].Size.Unpadded()),
			CommP:    commP.Inner,
		}
	}

	return out, uint(len(out)), nil
}

func toFilPublicReplicaInfosV2(src []proof.SectorInfo, typ string) ([]generated_v2.FilPublicReplicaInfo, uint, error) {
	out := make([]generated_v2.FilPublicReplicaInfo, len(src))

	for idx := range out {
		commR, err := to32ByteCommR(src[idx].SealedCID)
		if err != nil {
			return nil, 0, err
		}

		out[idx] = generated_v2.FilPublicReplicaInfo{
			CommR:    commR.Inner,
			SectorId: uint64(src[idx].SectorNumber),
		}

		switch typ {
		case "window":
			p, err := src[idx].SealProof.RegisteredWindowPoStProof()
			if err != nil {
				return nil, 0, err
			}

			out[idx].RegisteredProof, err = toFilRegisteredPoStProof(p)
			if err != nil {
				return nil, 0, err
			}
		case "winning":
			p, err := src[idx].SealProof.RegisteredWinningPoStProof()
			if err != nil {
				return nil, 0, err
			}

			out[idx].RegisteredProof, err = toFilRegisteredPoStProof(p)
			if err != nil {
				return nil, 0, err
			}
		}
	}

	return out, uint(len(out)), nil
}

func toFilPrivateReplicaInfosV2(src []PrivateSectorInfo, typ string) ([]generated_v2.FilPrivateReplicaInfo, uint, func(), error) {
	frees := make([]func(), len(src))

	out := make([]generated_v2.FilPrivateReplicaInfo, len(src))

	for idx := range out {
		commR, err := to32ByteCommR(src[idx].SealedCID)
		if err != nil {
			return nil, 0, func() {}, err
		}

		pp, err := toFilRegisteredPoStProof(src[idx].PoStProofType)
		if err != nil {
			return nil, 0, func() {}, err
		}

		out[idx] = generated_v2.FilPrivateReplicaInfo{
			RegisteredProof: pp,
			CacheDirPath:    src[idx].CacheDirPath,
			CommR:           commR.Inner,
			ReplicaPath:     src[idx].SealedSectorPath,
			SectorId:        uint64(src[idx].SectorNumber),
		}

		frees[idx] = out[idx].AllocateProxy()
	}

	return out, uint(len(out)), func() {
		for idx := range frees {
			frees[idx]()
		}
	}, nil
}

func fromFilPoStFaultySectorsV2(ptr []uint64, l uint) ([]abi.SectorNumber, error) {
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

func fromFilPoStProofsV2(src []generated_v2.FilPoStProof) ([]proof.PoStProof, error) {
	out := make([]proof.PoStProof, len(src))

	for idx := range out {
		src[idx].Deref()

		pp, err := fromFilRegisteredPoStProof(src[idx].RegisteredProof)
		if err != nil {
			return nil, err
		}

		out[idx] = proof.PoStProof{
			PoStProof:  pp,
			ProofBytes: []byte(toGoStringCopy(src[idx].ProofPtr, src[idx].ProofLen)),
		}
	}

	return out, nil
}

func toFilPoStProofsV2(src []proof.PoStProof) ([]generated_v2.FilPoStProof, uint, func(), error) {
	frees := make([]func(), len(src))

	out := make([]generated_v2.FilPoStProof, len(src))
	for idx := range out {
		pp, err := toFilRegisteredPoStProof(src[idx].PoStProof)
		if err != nil {
			return nil, 0, func() {}, err
		}

		out[idx] = generated_v2.FilPoStProof{
			RegisteredProof: pp,
			ProofLen:        uint(len(src[idx].ProofBytes)),
			ProofPtr:        string(src[idx].ProofBytes),
		}

		frees[idx] = out[idx].AllocateProxy()
	}

	return out, uint(len(out)), func() {
		for idx := range frees {
			frees[idx]()
		}
	}, nil
}

func to32ByteArrayV2(in []byte) generated_v2.Fil32ByteArray {
	var out generated_v2.Fil32ByteArray
	copy(out.Inner[:], in)
	return out
}

func toProverIDV2(minerID abi.ActorID) (generated_v2.Fil32ByteArray, error) {
	maddr, err := address.NewIDAddress(uint64(minerID))
	if err != nil {
		return generated_v2.Fil32ByteArray{}, errors.Wrap(err, "failed to convert ActorID to prover id ([32]byte) for FFI")
	}

	return to32ByteArray(maddr.Payload()), nil
}

func fromFilRegisteredPoStProofV2(p generated_v2.FilRegisteredPoStProof) (abi.RegisteredPoStProof, error) {
	switch p {
	case generated_v2.FilRegisteredPoStProofStackedDrgWinning2KiBV2:
		return abi.RegisteredPoStProof_StackedDrgWinning2KiBV2, nil
	case generated_v2.FilRegisteredPoStProofStackedDrgWinning8MiBV2:
		return abi.RegisteredPoStProof_StackedDrgWinning8MiBV2, nil
	case generated_v2.FilRegisteredPoStProofStackedDrgWinning512MiBV2:
		return abi.RegisteredPoStProof_StackedDrgWinning512MiBV2, nil
	case generated_v2.FilRegisteredPoStProofStackedDrgWinning32GiBV2:
		return abi.RegisteredPoStProof_StackedDrgWinning32GiBV2, nil
	case generated_v2.FilRegisteredPoStProofStackedDrgWinning64GiBV2:
		return abi.RegisteredPoStProof_StackedDrgWinning64GiBV2, nil
	case generated_v2.FilRegisteredPoStProofStackedDrgWindow2KiBV2:
		return abi.RegisteredPoStProof_StackedDrgWindow2KiBV2, nil
	case generated_v2.FilRegisteredPoStProofStackedDrgWindow8MiBV2:
		return abi.RegisteredPoStProof_StackedDrgWindow8MiBV2, nil
	case generated_v2.FilRegisteredPoStProofStackedDrgWindow512MiBV2:
		return abi.RegisteredPoStProof_StackedDrgWindow512MiBV2, nil
	case generated_v2.FilRegisteredPoStProofStackedDrgWindow32GiBV2:
		return abi.RegisteredPoStProof_StackedDrgWindow32GiBV2, nil
	case generated_v2.FilRegisteredPoStProofStackedDrgWindow64GiBV2:
		return abi.RegisteredPoStProof_StackedDrgWindow64GiBV2, nil
	default:
		return 0, errors.Errorf("no mapping to abi.RegisteredPoStProof value available for: %v", p)
	}
}

func toFilRegisteredPoStProofV2(p abi.RegisteredPoStProof) (generated_v2.FilRegisteredPoStProof, error) {
	switch p {
	case abi.RegisteredPoStProof_StackedDrgWinning2KiBV2:
		return generated_v2.FilRegisteredPoStProofStackedDrgWinning2KiBV2, nil
	case abi.RegisteredPoStProof_StackedDrgWinning8MiBV2:
		return generated_v2.FilRegisteredPoStProofStackedDrgWinning8MiBV2, nil
	case abi.RegisteredPoStProof_StackedDrgWinning512MiBV2:
		return generated_v2.FilRegisteredPoStProofStackedDrgWinning512MiBV2, nil
	case abi.RegisteredPoStProof_StackedDrgWinning32GiBV2:
		return generated_v2.FilRegisteredPoStProofStackedDrgWinning32GiBV2, nil
	case abi.RegisteredPoStProof_StackedDrgWinning64GiBV2:
		return generated_v2.FilRegisteredPoStProofStackedDrgWinning64GiBV2, nil
	case abi.RegisteredPoStProof_StackedDrgWindow2KiBV2:
		return generated_v2.FilRegisteredPoStProofStackedDrgWindow2KiBV2, nil
	case abi.RegisteredPoStProof_StackedDrgWindow8MiBV2:
		return generated_v2.FilRegisteredPoStProofStackedDrgWindow8MiBV2, nil
	case abi.RegisteredPoStProof_StackedDrgWindow512MiBV2:
		return generated_v2.FilRegisteredPoStProofStackedDrgWindow512MiBV2, nil
	case abi.RegisteredPoStProof_StackedDrgWindow32GiBV2:
		return generated_v2.FilRegisteredPoStProofStackedDrgWindow32GiBV2, nil
	case abi.RegisteredPoStProof_StackedDrgWindow64GiBV2:
		return generated_v2.FilRegisteredPoStProofStackedDrgWindow64GiBV2, nil
	default:
		return 0, errors.Errorf("no mapping to abi.RegisteredPoStProof value available for: %v", p)
	}
}

func toFilRegisteredSealProofV2(p abi.RegisteredSealProof) (generated_v2.FilRegisteredSealProof, error) {
	switch p {
	case abi.RegisteredSealProof_StackedDrg2KiBV2:
		return generated_v2.FilRegisteredSealProofStackedDrg2KiBV2, nil
	case abi.RegisteredSealProof_StackedDrg8MiBV2:
		return generated_v2.FilRegisteredSealProofStackedDrg8MiBV2, nil
	case abi.RegisteredSealProof_StackedDrg512MiBV2:
		return generated_v2.FilRegisteredSealProofStackedDrg512MiBV2, nil
	case abi.RegisteredSealProof_StackedDrg32GiBV2:
		return generated_v2.FilRegisteredSealProofStackedDrg32GiBV2, nil
	case abi.RegisteredSealProof_StackedDrg64GiBV2:
		return generated_v2.FilRegisteredSealProofStackedDrg64GiBV2, nil
	default:
		return 0, errors.Errorf("no mapping to C.FFIRegisteredSealProof value available for: %v", p)
	}
}

func to32ByteCommDV2(unsealedCID cid.Cid) (generated_v2.Fil32ByteArray, error) {
	commD, err := commcid.CIDToDataCommitmentV1(unsealedCID)
	if err != nil {
		return generated_v2.Fil32ByteArray{}, errors.Wrap(err, "failed to transform sealed CID to CommD")
	}

	return to32ByteArray(commD), nil
}

func to32ByteCommRV2(sealedCID cid.Cid) (generated_v2.Fil32ByteArray, error) {
	commD, err := commcid.CIDToReplicaCommitmentV1(sealedCID)
	if err != nil {
		return generated_v2.Fil32ByteArray{}, errors.Wrap(err, "failed to transform sealed CID to CommR")
	}

	return to32ByteArray(commD), nil
}

func to32ByteCommPV2(pieceCID cid.Cid) (generated_v2.Fil32ByteArray, error) {
	commP, err := commcid.CIDToPieceCommitmentV1(pieceCID)
	if err != nil {
		return generated_v2.Fil32ByteArray{}, errors.Wrap(err, "failed to transform sealed CID to CommP")
	}

	return to32ByteArray(commP), nil
}

func toGoStringCopyV2(raw string, rawLen uint) string {
	h := (*stringHeader)(unsafe.Pointer(&raw))
	return C.GoStringN((*C.char)(h.Data), C.int(rawLen))
}

type stringHeaderV2 struct {
	Data unsafe.Pointer
	Len  int
}
