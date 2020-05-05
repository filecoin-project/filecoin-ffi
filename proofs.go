//+build cgo

package ffi

// #cgo LDFLAGS: ${SRCDIR}/libfilcrypto.a
// #cgo pkg-config: ${SRCDIR}/filcrypto.pc
// #include "./filcrypto.h"
import "C"
import (
	"os"
	"runtime"
	"unsafe"

	"github.com/filecoin-project/go-address"
	commcid "github.com/filecoin-project/go-fil-commcid"
	"github.com/filecoin-project/specs-actors/actors/abi"
	"github.com/ipfs/go-cid"
	"github.com/pkg/errors"

	"github.com/filecoin-project/filecoin-ffi/generated"
)

// VerifySeal returns true if the sealing operation from which its inputs were
// derived was valid, and false if not.
func VerifySeal(info abi.SealVerifyInfo) (bool, error) {
	sp, err := toFilRegisteredSealProof(info.OnChain.RegisteredProof)
	if err != nil {
		return false, err
	}

	commR, err := to32ByteCommR(info.OnChain.SealedCID)
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

	resp := generated.FilVerifySeal(sp, commR, commD, proverID, to32ByteArray(info.Randomness), to32ByteArray(info.InteractiveRandomness), uint64(info.SectorID.Number), string(info.OnChain.Proof), uint(len(info.OnChain.Proof)))
	resp.Deref()

	defer generated.FilDestroyVerifySealResponse(resp)

	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
		return false, errors.New(generated.RawString(resp.ErrorMsg).Copy())
	}

	return resp.IsValid, nil
}

// VerifyWinningPoSt returns true if the Winning PoSt-generation operation from which its
// inputs were derived was valid, and false if not.
func VerifyWinningPoSt(info abi.WinningPoStVerifyInfo) (bool, error) {
	filPublicReplicaInfos, filPublicReplicaInfosLen, err := toFilPublicReplicaInfos(info.ChallengedSectors, "winning")
	if err != nil {
		return false, errors.Wrap(err, "failed to create public replica info array for FFI")
	}

	filPoStProofs, filPoStProofsLen, err := toFilPoStProofs(info.Proofs, "winning")
	if err != nil {
		return false, errors.Wrap(err, "failed to create PoSt proofs array for FFI")
	}

	proverID, err := toProverID(info.Prover)
	if err != nil {
		return false, err
	}

	resp := generated.FilVerifyWinningPost(
		to32ByteArray(info.Randomness),
		filPublicReplicaInfos,
		filPublicReplicaInfosLen,
		filPoStProofs,
		filPoStProofsLen,
		proverID,
	)
	resp.Deref()

	defer generated.FilDestroyVerifyWinningPostResponse(resp)

	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
		return false, errors.New(generated.RawString(resp.ErrorMsg).Copy())
	}

	return resp.IsValid, nil
}

// VerifyWindowPoSt returns true if the Winning PoSt-generation operation from which its
// inputs were derived was valid, and false if not.
func VerifyWindowPoSt(info abi.WindowPoStVerifyInfo) (bool, error) {
	filPublicReplicaInfos, filPublicReplicaInfosLen, err := toFilPublicReplicaInfos(info.ChallengedSectors, "window")
	if err != nil {
		return false, errors.Wrap(err, "failed to create public replica info array for FFI")
	}

	filPoStProofs, filPoStProofsLen, err := toFilPoStProofs(info.Proofs, "window")
	if err != nil {
		return false, errors.Wrap(err, "failed to create PoSt proofs array for FFI")
	}

	proverID, err := toProverID(info.Prover)
	if err != nil {
		return false, err
	}

	resp := generated.FilVerifyWindowPost(
		to32ByteArray(info.Randomness),
		filPublicReplicaInfos, filPublicReplicaInfosLen,
		filPoStProofs, filPoStProofsLen,
		proverID,
	)
	resp.Deref()

	defer generated.FilDestroyVerifyWindowPostResponse(resp)

	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
		return false, errors.New(generated.RawString(resp.ErrorMsg).Copy())
	}

	return resp.IsValid, nil
}

// GeneratePieceCommitment produces a piece commitment for the provided data
// stored at a given path.
func GeneratePieceCID(proofType abi.RegisteredProof, piecePath string, pieceSize abi.UnpaddedPieceSize) (cid.Cid, error) {
	pieceFile, err := os.Open(piecePath)
	if err != nil {
		return cid.Undef, err
	}

	return GeneratePieceCIDFromFile(proofType, pieceFile, pieceSize)
}

// GenerateDataCommitment produces a commitment for the sector containing the
// provided pieces.
func GenerateUnsealedCID(proofType abi.RegisteredProof, pieces []abi.PieceInfo) (cid.Cid, error) {
	sp, err := toFilRegisteredSealProof(proofType)
	if err != nil {
		return cid.Undef, err
	}

	filPublicPieceInfos, filPublicPieceInfosLen, err := toFilPublicPieceInfos(pieces)
	if err != nil {
		return cid.Undef, err
	}

	resp := generated.FilGenerateDataCommitment(sp, filPublicPieceInfos, filPublicPieceInfosLen)
	resp.Deref()

	defer generated.FilDestroyGenerateDataCommitmentResponse(resp)

	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
		return cid.Undef, errors.New(generated.RawString(resp.ErrorMsg).Copy())
	}

	return commcid.DataCommitmentV1ToCID(resp.CommD[:]), nil
}

// GeneratePieceCIDFromFile produces a piece CID for the provided data stored in
//a given file.
func GeneratePieceCIDFromFile(proofType abi.RegisteredProof, pieceFile *os.File, pieceSize abi.UnpaddedPieceSize) (cid.Cid, error) {
	sp, err := toFilRegisteredSealProof(proofType)
	if err != nil {
		return cid.Undef, err
	}

	pieceFd := pieceFile.Fd()
	runtime.KeepAlive(pieceFile)

	resp := generated.FilGeneratePieceCommitment(sp, int32(pieceFd), uint64(pieceSize))
	resp.Deref()

	defer generated.FilDestroyGeneratePieceCommitmentResponse(resp)

	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
		return cid.Undef, errors.New(generated.RawString(resp.ErrorMsg).Copy())
	}

	return commcid.PieceCommitmentV1ToCID(resp.CommP[:]), nil
}

// WriteWithAlignment
func WriteWithAlignment(
	proofType abi.RegisteredProof,
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
	runtime.KeepAlive(pieceFile)

	stagedSectorFd := stagedSectorFile.Fd()
	runtime.KeepAlive(stagedSectorFile)

	filExistingPieceSizes, filExistingPieceSizesLen := toFilExistingPieceSizes(existingPieceSizes)

	resp := generated.FilWriteWithAlignment(sp, int32(pieceFd), uint64(pieceBytes), int32(stagedSectorFd), filExistingPieceSizes, filExistingPieceSizesLen)
	resp.Deref()

	defer generated.FilDestroyWriteWithAlignmentResponse(resp)

	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
		return 0, 0, cid.Undef, errors.New(generated.RawString(resp.ErrorMsg).Copy())
	}

	return abi.UnpaddedPieceSize(resp.LeftAlignmentUnpadded), abi.UnpaddedPieceSize(resp.TotalWriteUnpadded), commcid.PieceCommitmentV1ToCID(resp.CommP[:]), nil
}

// WriteWithoutAlignment
func WriteWithoutAlignment(
	proofType abi.RegisteredProof,
	pieceFile *os.File,
	pieceBytes abi.UnpaddedPieceSize,
	stagedSectorFile *os.File,
) (abi.UnpaddedPieceSize, cid.Cid, error) {
	sp, err := toFilRegisteredSealProof(proofType)
	if err != nil {
		return 0, cid.Undef, err
	}

	pieceFd := pieceFile.Fd()
	runtime.KeepAlive(pieceFile)

	stagedSectorFd := stagedSectorFile.Fd()
	runtime.KeepAlive(stagedSectorFile)

	resp := generated.FilWriteWithoutAlignment(sp, int32(pieceFd), uint64(pieceBytes), int32(stagedSectorFd))
	resp.Deref()

	defer generated.FilDestroyWriteWithoutAlignmentResponse(resp)

	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
		return 0, cid.Undef, errors.New(generated.RawString(resp.ErrorMsg).Copy())
	}

	return abi.UnpaddedPieceSize(resp.TotalWriteUnpadded), commcid.PieceCommitmentV1ToCID(resp.CommP[:]), nil
}

// SealPreCommitPhase1
func SealPreCommitPhase1(
	proofType abi.RegisteredProof,
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

	resp := generated.FilSealPreCommitPhase1(sp, cacheDirPath, stagedSectorPath, sealedSectorPath, uint64(sectorNum), proverID, to32ByteArray(ticket), filPublicPieceInfos, filPublicPieceInfosLen)
	resp.Deref()

	defer generated.FilDestroySealPreCommitPhase1Response(resp)

	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
		return nil, errors.New(generated.RawString(resp.ErrorMsg).Copy())
	}

	return []byte(toGoStringCopy(resp.SealPreCommitPhase1OutputPtr, resp.SealPreCommitPhase1OutputLen)), nil
}

// SealPreCommitPhase2
func SealPreCommitPhase2(
	phase1Output []byte,
	cacheDirPath string,
	sealedSectorPath string,
) (sealedCID cid.Cid, unsealedCID cid.Cid, err error) {
	resp := generated.FilSealPreCommitPhase2(string(phase1Output), uint(len(phase1Output)), cacheDirPath, sealedSectorPath)
	resp.Deref()

	defer generated.FilDestroySealPreCommitPhase2Response(resp)

	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
		return cid.Undef, cid.Undef, errors.New(generated.RawString(resp.ErrorMsg).Copy())
	}

	return commcid.ReplicaCommitmentV1ToCID(resp.CommR[:]), commcid.DataCommitmentV1ToCID(resp.CommD[:]), nil
}

// SealCommitPhase1
func SealCommitPhase1(
	proofType abi.RegisteredProof,
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

	resp := generated.FilSealCommitPhase1(sp, commR, commD, cacheDirPath, sealedSectorPath, uint64(sectorNum), proverID, to32ByteArray(ticket), to32ByteArray(seed), filPublicPieceInfos, filPublicPieceInfosLen)
	resp.Deref()

	defer generated.FilDestroySealCommitPhase1Response(resp)

	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
		return nil, errors.New(generated.RawString(resp.ErrorMsg).Copy())
	}

	return []byte(toGoStringCopy(resp.SealCommitPhase1OutputPtr, resp.SealCommitPhase1OutputLen)), nil
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

	resp := generated.FilSealCommitPhase2(string(phase1Output), uint(len(phase1Output)), uint64(sectorNum), proverID)
	resp.Deref()

	defer generated.FilDestroySealCommitPhase2Response(resp)

	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
		return nil, errors.New(generated.RawString(resp.ErrorMsg).Copy())
	}

	return []byte(toGoStringCopy(resp.ProofPtr, resp.ProofLen)), nil
}

// Unseal
func Unseal(
	proofType abi.RegisteredProof,
	cacheDirPath string,
	sealedSectorPath string,
	unsealOutputPath string,
	sectorNum abi.SectorNumber,
	minerID abi.ActorID,
	ticket abi.SealRandomness,
	unsealedCID cid.Cid,
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

	resp := generated.FilUnseal(sp, cacheDirPath, sealedSectorPath, unsealOutputPath, uint64(sectorNum), proverID, to32ByteArray(ticket), commD)
	resp.Deref()

	defer generated.FilDestroyUnsealResponse(resp)

	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
		return errors.New(generated.RawString(resp.ErrorMsg).Copy())
	}

	return nil
}

// UnsealRange
func UnsealRange(
	proofType abi.RegisteredProof,
	cacheDirPath string,
	sealedSectorPath string,
	unsealOutputPath string,
	sectorNum abi.SectorNumber,
	minerID abi.ActorID,
	ticket abi.SealRandomness,
	unsealedCID cid.Cid,
	offset uint64,
	len uint64,
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

	resp := generated.FilUnsealRange(sp, cacheDirPath, sealedSectorPath, unsealOutputPath, uint64(sectorNum), proverID, to32ByteArray(ticket), commD, offset, len)
	resp.Deref()

	defer generated.FilDestroyUnsealRangeResponse(resp)

	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
		return errors.New(generated.RawString(resp.ErrorMsg).Copy())
	}

	return nil
}

// GenerateWinningPoStSectorChallenge
func GenerateWinningPoStSectorChallenge(
	proofType abi.RegisteredProof,
	minerID abi.ActorID,
	randomness abi.PoStRandomness,
	eligibleSectorsLen uint64,
) ([]uint64, error) {
	pp, err := toFilRegisteredPoStProof(proofType, "winning")
	if err != nil {
		return nil, err
	}

	proverID, err := toProverID(minerID)
	if err != nil {
		return nil, err
	}

	resp := generated.FilGenerateWinningPostSectorChallenge(
		pp, to32ByteArray(randomness),
		eligibleSectorsLen, proverID,
	)
	resp.Deref()
	resp.IdsPtr = make([]uint64, resp.IdsLen)
	resp.Deref()

	defer generated.FilDestroyGenerateWinningPostSectorChallenge(resp)

	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
		return nil, errors.New(generated.RawString(resp.ErrorMsg).Copy())
	}

	// copy from C memory space to Go
	out := make([]uint64, resp.IdsLen)
	for idx := range out {
		out[idx] = resp.IdsPtr[idx]
	}

	return out, nil
}

// GenerateWinningPoSt
func GenerateWinningPoSt(
	minerID abi.ActorID,
	privateSectorInfo SortedPrivateSectorInfo,
	randomness abi.PoStRandomness,
) ([]abi.PoStProof, error) {
	filReplicas, filReplicasLen, free, err := toFilPrivateReplicaInfos(privateSectorInfo.Values(), "winning")
	if err != nil {
		return nil, errors.Wrap(err, "failed to create private replica info array for FFI")
	}
	defer free()

	proverID, err := toProverID(minerID)
	if err != nil {
		return nil, err
	}

	resp := generated.FilGenerateWinningPost(
		to32ByteArray(randomness),
		filReplicas, filReplicasLen,
		proverID,
	)
	resp.Deref()
	resp.ProofsPtr = make([]generated.FilPoStProof, resp.ProofsLen)
	resp.Deref()

	defer generated.FilDestroyGenerateWinningPostResponse(resp)

	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
		return nil, errors.New(generated.RawString(resp.ErrorMsg).Copy())
	}

	proofs, err := fromFilPoStProofs(resp.ProofsPtr)
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
) ([]abi.PoStProof, error) {
	filReplicas, filReplicasLen, free, err := toFilPrivateReplicaInfos(privateSectorInfo.Values(), "window")
	if err != nil {
		return nil, errors.Wrap(err, "failed to create private replica info array for FFI")
	}
	defer free()

	proverID, err := toProverID(minerID)
	if err != nil {
		return nil, err
	}

	resp := generated.FilGenerateWindowPost(to32ByteArray(randomness), filReplicas, filReplicasLen, proverID)
	resp.Deref()
	resp.ProofsPtr = make([]generated.FilPoStProof, resp.ProofsLen)
	resp.Deref()

	defer generated.FilDestroyGenerateWindowPostResponse(resp)

	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
		return nil, errors.New(generated.RawString(resp.ErrorMsg).Copy())
	}

	proofs, err := fromFilPoStProofs(resp.ProofsPtr)
	if err != nil {
		return nil, err
	}

	return proofs, nil
}

// GetGPUDevices produces a slice of strings, each representing the name of a
// detected GPU device.
func GetGPUDevices() ([]string, error) {
	resp := generated.FilGetGpuDevices()
	resp.Deref()
	resp.DevicesPtr = make([]string, resp.DevicesLen)
	resp.Deref()

	defer generated.FilDestroyGpuDeviceResponse(resp)

	out := make([]string, len(resp.DevicesPtr))
	for idx := range out {
		out[idx] = generated.RawString(resp.DevicesPtr[idx]).Copy()
	}

	return out, nil
}

// GetSealVersion
func GetSealVersion(proofType abi.RegisteredProof) (string, error) {
	sp, err := toFilRegisteredSealProof(proofType)
	if err != nil {
		return "", err
	}

	resp := generated.FilGetSealVersion(sp)
	resp.Deref()

	defer generated.FilDestroyStringResponse(resp)

	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
		return "", errors.New(generated.RawString(resp.ErrorMsg).Copy())
	}

	return generated.RawString(resp.StringVal).Copy(), nil
}

// GetPoStVersion
func GetPoStVersion(proofType abi.RegisteredProof) (string, error) {
	pp, err := toFilRegisteredPoStProof(proofType, "either")
	if err != nil {
		return "", err
	}

	resp := generated.FilGetPostVersion(pp)
	resp.Deref()

	defer generated.FilDestroyStringResponse(resp)

	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
		return "", errors.New(generated.RawString(resp.ErrorMsg).Copy())
	}

	return generated.RawString(resp.StringVal).Copy(), nil
}

// ClearCache
func ClearCache(sectorSize uint64, cacheDirPath string) error {
	resp := generated.FilClearCache(sectorSize, cacheDirPath)
	resp.Deref()

	defer generated.FilDestroyClearCacheResponse(resp)

	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
		return errors.New(generated.RawString(resp.ErrorMsg).Copy())
	}

	return nil
}

func toFilExistingPieceSizes(src []abi.UnpaddedPieceSize) ([]uint64, uint) {
	out := make([]uint64, len(src))

	for idx := range out {
		out[idx] = uint64(src[idx])
	}

	return out, uint(len(out))
}

func toFilPublicPieceInfos(src []abi.PieceInfo) ([]generated.FilPublicPieceInfo, uint, error) {
	out := make([]generated.FilPublicPieceInfo, len(src))

	for idx := range out {
		commP, err := to32ByteCommP(src[idx].PieceCID)
		if err != nil {
			return nil, 0, err
		}

		out[idx] = generated.FilPublicPieceInfo{
			NumBytes: uint64(src[idx].Size.Unpadded()),
			CommP:    commP.Inner,
		}
	}

	return out, uint(len(out)), nil
}

func toFilPublicReplicaInfos(src []abi.SectorInfo, typ string) ([]generated.FilPublicReplicaInfo, uint, error) {
	out := make([]generated.FilPublicReplicaInfo, len(src))

	for idx := range out {
		commR, err := to32ByteCommR(src[idx].SealedCID)
		if err != nil {
			return nil, 0, err
		}

		pp, err := toFilRegisteredPoStProof(src[idx].RegisteredProof, typ)
		if err != nil {
			return nil, 0, err
		}

		out[idx] = generated.FilPublicReplicaInfo{
			RegisteredProof: pp,
			CommR:           commR.Inner,
			SectorId:        uint64(src[idx].SectorNumber),
		}
	}

	return out, uint(len(out)), nil
}

func toFilPrivateReplicaInfos(src []PrivateSectorInfo, typ string) ([]generated.FilPrivateReplicaInfo, uint, func(), error) {
	frees := make([]func(), len(src))

	out := make([]generated.FilPrivateReplicaInfo, len(src))

	for idx := range out {
		commR, err := to32ByteCommR(src[idx].SealedCID)
		if err != nil {
			return nil, 0, func() {}, err
		}

		pp, err := toFilRegisteredPoStProof(src[idx].PoStProofType, typ)
		if err != nil {
			return nil, 0, func() {}, err
		}

		out[idx] = generated.FilPrivateReplicaInfo{
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

func fromFilPoStProofs(src []generated.FilPoStProof) ([]abi.PoStProof, error) {
	out := make([]abi.PoStProof, len(src))

	for idx := range out {
		src[idx].Deref()

		pp, err := fromFilRegisteredPoStProof(src[idx].RegisteredProof)
		if err != nil {
			return nil, err
		}

		out[idx] = abi.PoStProof{
			RegisteredProof: pp,
			ProofBytes:      []byte(toGoStringCopy(src[idx].ProofPtr, src[idx].ProofLen)),
		}
	}

	return out, nil
}

func toFilPoStProofs(src []abi.PoStProof, typ string) ([]generated.FilPoStProof, uint, error) {
	out := make([]generated.FilPoStProof, len(src))
	for idx := range out {
		pp, err := toFilRegisteredPoStProof(src[idx].RegisteredProof, typ)
		if err != nil {
			return nil, 0, err
		}

		out[idx] = generated.FilPoStProof{
			RegisteredProof: pp,
			ProofLen:        uint(len(src[idx].ProofBytes)),
			ProofPtr:        string(src[idx].ProofBytes),
		}
	}

	return out, uint(len(out)), nil
}

func to32ByteArray(in []byte) generated.Fil32ByteArray {
	var out generated.Fil32ByteArray
	copy(out.Inner[:], in)
	return out
}

func toProverID(minerID abi.ActorID) (generated.Fil32ByteArray, error) {
	maddr, err := address.NewIDAddress(uint64(minerID))
	if err != nil {
		return generated.Fil32ByteArray{}, errors.Wrap(err, "failed to convert ActorID to prover id ([32]byte) for FFI")
	}

	return to32ByteArray(maddr.Payload()), nil
}

func fromFilRegisteredPoStProof(p generated.FilRegisteredPoStProof) (abi.RegisteredProof, error) {
	switch p {
	case generated.FilRegisteredPoStProofStackedDrgWinning2KiBV1:
		return abi.RegisteredProof_StackedDRG2KiBWinningPoSt, nil
	case generated.FilRegisteredPoStProofStackedDrgWinning8MiBV1:
		return abi.RegisteredProof_StackedDRG8MiBWinningPoSt, nil
	case generated.FilRegisteredPoStProofStackedDrgWinning512MiBV1:
		return abi.RegisteredProof_StackedDRG512MiBWinningPoSt, nil
	case generated.FilRegisteredPoStProofStackedDrgWinning32GiBV1:
		return abi.RegisteredProof_StackedDRG32GiBWinningPoSt, nil
	case generated.FilRegisteredPoStProofStackedDrgWindow2KiBV1:
		return abi.RegisteredProof_StackedDRG2KiBWindowPoSt, nil
	case generated.FilRegisteredPoStProofStackedDrgWindow8MiBV1:
		return abi.RegisteredProof_StackedDRG8MiBWindowPoSt, nil
	case generated.FilRegisteredPoStProofStackedDrgWindow512MiBV1:
		return abi.RegisteredProof_StackedDRG512MiBWindowPoSt, nil
	case generated.FilRegisteredPoStProofStackedDrgWindow32GiBV1:
		return abi.RegisteredProof_StackedDRG32GiBWindowPoSt, nil
	default:
		return 0, errors.Errorf("no mapping to abi.RegisteredPoStProof value available for: %v", p)
	}
}

func toFilRegisteredPoStProof(pp abi.RegisteredProof, typ string) (generated.FilRegisteredPoStProof, error) {
	var p abi.RegisteredProof
	switch typ {
	case "window":
		pp, err := pp.RegisteredWindowPoStProof()
		if err != nil {
			return 0, err
		}
		p = pp
	case "winning":
		pp, err := pp.RegisteredWinningPoStProof()
		if err != nil {
			return 0, err
		}
		p = pp
	case "either":
		v, err := pp.RegisteredWinningPoStProof()
		if err == nil {
			p = v
		} else {
			v, err := pp.RegisteredWindowPoStProof()
			if err == nil {
				p = v
			} else {
				return 0, errors.Errorf("no mapping to generated.RegisteredPoStProof value available for: %v", pp)
			}
		}
	default:
		return 0, errors.Errorf("no mapping to generated.RegisteredPoStProof value available for: %v", pp)
	}

	switch p {
	case abi.RegisteredProof_StackedDRG2KiBPoSt, abi.RegisteredProof_StackedDRG8MiBPoSt, abi.RegisteredProof_StackedDRG512MiBPoSt, abi.RegisteredProof_StackedDRG32GiBPoSt:
		return 0, errors.Errorf("unsupported version of election post: %v", p)
	case abi.RegisteredProof_StackedDRG32GiBWindowPoSt:
		return generated.FilRegisteredPoStProofStackedDrgWindow32GiBV1, nil
	case abi.RegisteredProof_StackedDRG512MiBWindowPoSt:
		return generated.FilRegisteredPoStProofStackedDrgWindow512MiBV1, nil
	case abi.RegisteredProof_StackedDRG8MiBWindowPoSt:
		return generated.FilRegisteredPoStProofStackedDrgWindow8MiBV1, nil
	case abi.RegisteredProof_StackedDRG2KiBWindowPoSt:
		return generated.FilRegisteredPoStProofStackedDrgWindow2KiBV1, nil

	case abi.RegisteredProof_StackedDRG32GiBWinningPoSt:
		return generated.FilRegisteredPoStProofStackedDrgWinning32GiBV1, nil
	case abi.RegisteredProof_StackedDRG512MiBWinningPoSt:
		return generated.FilRegisteredPoStProofStackedDrgWinning512MiBV1, nil
	case abi.RegisteredProof_StackedDRG8MiBWinningPoSt:
		return generated.FilRegisteredPoStProofStackedDrgWinning8MiBV1, nil
	case abi.RegisteredProof_StackedDRG2KiBWinningPoSt:
		return generated.FilRegisteredPoStProofStackedDrgWinning2KiBV1, nil

	default:
		return 0, errors.Errorf("no mapping to generated.RegisteredPoStProof value available for: %v", p)
	}
}

func toFilRegisteredSealProof(p abi.RegisteredProof) (generated.FilRegisteredSealProof, error) {
	pp, err := p.RegisteredSealProof()
	if err != nil {
		return 0, err
	}

	switch pp {
	case abi.RegisteredProof_StackedDRG2KiBSeal:
		return generated.FilRegisteredSealProofStackedDrg2KiBV1, nil
	case abi.RegisteredProof_StackedDRG8MiBSeal:
		return generated.FilRegisteredSealProofStackedDrg8MiBV1, nil
	case abi.RegisteredProof_StackedDRG512MiBSeal:
		return generated.FilRegisteredSealProofStackedDrg512MiBV1, nil
	case abi.RegisteredProof_StackedDRG32GiBSeal:
		return generated.FilRegisteredSealProofStackedDrg32GiBV1, nil
	default:
		return 0, errors.Errorf("no mapping to C.FFIRegisteredSealProof value available for: %v", p)
	}
}

func to32ByteCommD(unsealedCID cid.Cid) (generated.Fil32ByteArray, error) {
	commD, err := commcid.CIDToDataCommitmentV1(unsealedCID)
	if err != nil {
		return generated.Fil32ByteArray{}, errors.Wrap(err, "failed to transform sealed CID to CommD")
	}

	return to32ByteArray(commD), nil
}

func to32ByteCommR(sealedCID cid.Cid) (generated.Fil32ByteArray, error) {
	commD, err := commcid.CIDToReplicaCommitmentV1(sealedCID)
	if err != nil {
		return generated.Fil32ByteArray{}, errors.Wrap(err, "failed to transform sealed CID to CommR")
	}

	return to32ByteArray(commD), nil
}

func to32ByteCommP(pieceCID cid.Cid) (generated.Fil32ByteArray, error) {
	commP, err := commcid.CIDToPieceCommitmentV1(pieceCID)
	if err != nil {
		return generated.Fil32ByteArray{}, errors.Wrap(err, "failed to transform sealed CID to CommP")
	}

	return to32ByteArray(commP), nil
}

func toGoStringCopy(raw string, rawLen uint) string {
	h := (*stringHeader)(unsafe.Pointer(&raw))
	return C.GoStringN((*C.char)(h.Data), C.int(rawLen))
}

type stringHeader struct {
	Data unsafe.Pointer
	Len  int
}
