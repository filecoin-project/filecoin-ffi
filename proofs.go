//+build cgo

package ffi

import (
	"os"
	"runtime"
	"unsafe"

	commcid "github.com/filecoin-project/go-fil-commcid"
	"github.com/filecoin-project/specs-actors/actors/abi"
	cid "github.com/ipfs/go-cid"
	"github.com/pkg/errors"
)

// #cgo LDFLAGS: ${SRCDIR}/libfilecoin.a
// #cgo pkg-config: ${SRCDIR}/filecoin.pc
// #include "./filecoin.h"
import "C"

func cRegisteredPoStProof(p abi.RegisteredProof) (C.FFIRegisteredPoStProof, error) {
	switch p {
	case abi.RegisteredProof_StackedDRG1KiBPoSt:
		return C.FFIRegisteredPoStProof_StackedDrg1KiBV1, nil
	case abi.RegisteredProof_StackedDRG16MiBPoSt:
		return C.FFIRegisteredPoStProof_StackedDrg16MiBV1, nil
	case abi.RegisteredProof_StackedDRG256MiBPoSt:
		return C.FFIRegisteredPoStProof_StackedDrg256MiBV1, nil
	case abi.RegisteredProof_StackedDRG1GiBPoSt:
		return C.FFIRegisteredPoStProof_StackedDrg1GiBV1, nil
	case abi.RegisteredProof_StackedDRG32GiBPoSt:
		return C.FFIRegisteredPoStProof_StackedDrg32GiBV1, nil
	default:
		return 0, errors.Errorf("no mapping to C.FFIRegisteredPoStProof value available for: %v", p)
	}
}

func cRegisteredSealProof(p abi.RegisteredProof) (C.FFIRegisteredSealProof, error) {
	switch p {
	case abi.RegisteredProof_StackedDRG1KiBSeal:
		return C.FFIRegisteredSealProof_StackedDrg1KiBV1, nil
	case abi.RegisteredProof_StackedDRG16MiBSeal:
		return C.FFIRegisteredSealProof_StackedDrg16MiBV1, nil
	case abi.RegisteredProof_StackedDRG256MiBSeal:
		return C.FFIRegisteredSealProof_StackedDrg256MiBV1, nil
	case abi.RegisteredProof_StackedDRG1GiBSeal:
		return C.FFIRegisteredSealProof_StackedDrg1GiBV1, nil
	case abi.RegisteredProof_StackedDRG32GiBSeal:
		return C.FFIRegisteredSealProof_StackedDrg32GiBV1, nil
	default:
		return 0, errors.Errorf("no mapping to C.FFIRegisteredSealProof value available for: %v", p)
	}
}

// VerifySeal returns true if the sealing operation from which its inputs were
// derived was valid, and false if not.
func VerifySeal(
	proofType abi.RegisteredProof,
	sealedCID cid.Cid,
	unsealedCID cid.Cid,
	proverID [32]byte,
	ticket abi.SealRandomness,
	seed abi.InteractiveSealRandomness,
	sectorNum abi.SectorNumber,
	proof abi.SealProof,
) (bool, error) {
	cProofType, err := cRegisteredSealProof(proofType)
	if err != nil {
		return false, errors.Wrap(err, "failed to create registered seal proof type for FFI")
	}

	commD, err := commcid.CIDToDataCommitmentV1(unsealedCID)
	if err != nil {
		return false, errors.Wrap(err, "failed to convert unsealed CID to CommD")
	}

	commR, err := commcid.CIDToReplicaCommitmentV1(sealedCID)
	if err != nil {
		return false, errors.Wrap(err, "failed to convert unsealed CID to CommR")
	}

	commDCBytes := C.CBytes(from32ByteArray(to32ByteArray(commD)))
	defer C.free(commDCBytes)

	commRCBytes := C.CBytes(from32ByteArray(to32ByteArray(commR)))
	defer C.free(commRCBytes)

	proofCBytes := C.CBytes(proof.ProofBytes[:])
	defer C.free(proofCBytes)

	proverIDCBytes := C.CBytes(proverID[:])
	defer C.free(proverIDCBytes)

	ticketCBytes := C.CBytes(from32ByteArray(to32ByteArray(ticket)))
	defer C.free(ticketCBytes)

	seedCBytes := C.CBytes(from32ByteArray(to32ByteArray(seed)))
	defer C.free(seedCBytes)

	// a mutable pointer to a VerifySealResponse C-struct
	resPtr := C.verify_seal(
		cProofType,
		(*[CommitmentBytesLen]C.uint8_t)(commRCBytes),
		(*[CommitmentBytesLen]C.uint8_t)(commDCBytes),
		(*[32]C.uint8_t)(proverIDCBytes),
		(*[32]C.uint8_t)(ticketCBytes),
		(*[32]C.uint8_t)(seedCBytes),
		C.uint64_t(uint64(sectorNum)),
		(*C.uint8_t)(proofCBytes),
		C.size_t(len(proof.ProofBytes)),
	)
	defer C.destroy_verify_seal_response(resPtr)

	if resPtr.status_code != 0 {
		return false, errors.New(C.GoString(resPtr.error_msg))
	}

	return bool(resPtr.is_valid), nil
}

// VerifyPoSt returns true if the PoSt-generation operation from which its
// inputs were derived was valid, and false if not.
func VerifyPoSt(
	sectorInfo SortedPublicSectorInfo,
	randomness abi.PoStRandomness,
	challengeCount uint64,
	proof []byte,
	winners []abi.PoStCandidate,
	proverID [32]byte,
) (bool, error) {
	cInfoPtr, cInfoSize, err := cPublicReplicaInfos(sectorInfo.Values())
	if err != nil {
		return false, errors.Wrap(err, "failed to create public replica info for FFI")
	}

	defer C.free(unsafe.Pointer(cInfoPtr))

	randomnessCBytes := C.CBytes(from32ByteArray(to32ByteArray(randomness)))
	defer C.free(randomnessCBytes)

	flattenedProofsCBytes := C.CBytes(proof)
	defer C.free(flattenedProofsCBytes)

	winnersPtr, winnersSize := cCandidates(winners)
	defer C.free(unsafe.Pointer(winnersPtr))

	proverIDCBytes := C.CBytes(proverID[:])
	defer C.free(proverIDCBytes)

	// a mutable pointer to a VerifyPoStResponse C-struct
	resPtr := C.verify_post(
		(*[32]C.uint8_t)(randomnessCBytes),
		C.uint64_t(challengeCount),
		cInfoPtr,
		cInfoSize,
		(*C.uint8_t)(flattenedProofsCBytes),
		C.size_t(len(proof)),
		winnersPtr,
		winnersSize,
		(*[32]C.uint8_t)(proverIDCBytes),
	)
	defer C.destroy_verify_post_response(resPtr)

	if resPtr.status_code != 0 {
		return false, errors.New(C.GoString(resPtr.error_msg))
	}

	return bool(resPtr.is_valid), nil
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
	cProofType, err := cRegisteredSealProof(proofType)
	if err != nil {
		return cid.Undef, errors.Wrap(err, "failed to create registered seal proof type for FFI")
	}

	cPiecesPtr, cPiecesLen, err := cPublicPieceInfo(pieces)
	if err != nil {
		return cid.Undef, errors.Wrap(err, "failed to create public piece info array for FFI")
	}
	defer C.free(unsafe.Pointer(cPiecesPtr))

	resPtr := C.generate_data_commitment(cProofType, (*C.FFIPublicPieceInfo)(cPiecesPtr), cPiecesLen)
	defer C.destroy_generate_data_commitment_response(resPtr)

	if resPtr.status_code != 0 {
		return cid.Undef, errors.New(C.GoString(resPtr.error_msg))
	}

	commD := goCommitment(&resPtr.comm_d[0])

	return commcid.DataCommitmentV1ToCID(commD[:]), nil
}

func GenerateUnsealedCIDMeow(proofType abi.RegisteredProof, pieces []abi.PieceInfo) (cid.Cid, [32]byte, error) {
	cProofType, err := cRegisteredSealProof(proofType)
	if err != nil {
		return cid.Undef, [32]byte{}, errors.Wrap(err, "failed to create registered seal proof type for FFI")
	}

	cPiecesPtr, cPiecesLen, err := cPublicPieceInfo(pieces)
	if err != nil {
		return cid.Undef, [32]byte{}, errors.Wrap(err, "failed to create public piece info array for FFI")
	}
	defer C.free(unsafe.Pointer(cPiecesPtr))

	resPtr := C.generate_data_commitment(cProofType, (*C.FFIPublicPieceInfo)(cPiecesPtr), cPiecesLen)
	defer C.destroy_generate_data_commitment_response(resPtr)

	if resPtr.status_code != 0 {
		return cid.Undef, [32]byte{}, errors.New(C.GoString(resPtr.error_msg))
	}

	commD := goCommitment(&resPtr.comm_d[0])

	return commcid.DataCommitmentV1ToCID(commD[:]), commD, nil
}

// GeneratePieceCIDFromFile produces a piece CID for the provided data stored in
//a given file.
func GeneratePieceCIDFromFile(proofType abi.RegisteredProof, pieceFile *os.File, pieceSize abi.UnpaddedPieceSize) (cid.Cid, error) {
	cProofType, err := cRegisteredSealProof(proofType)
	if err != nil {
		return cid.Undef, errors.Wrap(err, "failed to create registered seal proof type for FFI")
	}

	pieceFd := pieceFile.Fd()

	resPtr := C.generate_piece_commitment(cProofType, C.int(pieceFd), C.uint64_t(pieceSize))
	defer C.destroy_generate_piece_commitment_response(resPtr)

	// Make sure our filedescriptor stays alive, stayin alive
	runtime.KeepAlive(pieceFile)

	if resPtr.status_code != 0 {
		return cid.Undef, errors.New(C.GoString(resPtr.error_msg))
	}

	commD := goCommitment(&resPtr.comm_p[0])

	return commcid.DataCommitmentV1ToCID(commD[:]), nil
}

// WriteWithAlignment
func WriteWithAlignment(
	proofType abi.RegisteredProof,
	pieceFile *os.File,
	pieceBytes abi.UnpaddedPieceSize,
	stagedSectorFile *os.File,
	existingPieceSizes []abi.UnpaddedPieceSize,
) (leftAlignment, total abi.UnpaddedPieceSize, pieceCID cid.Cid, retErr error) {
	cProofType, err := cRegisteredSealProof(proofType)
	if err != nil {
		return 0, 0, cid.Undef, errors.Wrap(err, "failed to create registered seal proof type for FFI")
	}

	pieceFd := pieceFile.Fd()
	runtime.KeepAlive(pieceFile)

	stagedSectorFd := stagedSectorFile.Fd()
	runtime.KeepAlive(stagedSectorFile)

	raw := make([]uint64, len(existingPieceSizes))
	for idx := range existingPieceSizes {
		raw[idx] = uint64(existingPieceSizes[idx])
	}

	ptr, len := cUint64s(raw)
	defer C.free(unsafe.Pointer(ptr))

	resPtr := C.write_with_alignment(
		cProofType,
		C.int(pieceFd),
		C.uint64_t(uint64(pieceBytes)),
		C.int(stagedSectorFd),
		ptr,
		len,
	)
	defer C.destroy_write_with_alignment_response(resPtr)

	if resPtr.status_code != 0 {
		return 0, 0, cid.Undef, errors.New(C.GoString(resPtr.error_msg))
	}

	commP := goCommitment(&resPtr.comm_p[0])

	return abi.UnpaddedPieceSize(uint64(resPtr.left_alignment_unpadded)), abi.UnpaddedPieceSize(uint64(resPtr.total_write_unpadded)), commcid.PieceCommitmentV1ToCID(commP[:]), nil
}

// WriteWithoutAlignment
func WriteWithoutAlignment(
	proofType abi.RegisteredProof,
	pieceFile *os.File,
	pieceBytes abi.UnpaddedPieceSize,
	stagedSectorFile *os.File,
) (abi.UnpaddedPieceSize, cid.Cid, error) {
	cProofType, err := cRegisteredSealProof(proofType)
	if err != nil {
		return 0, cid.Undef, errors.Wrap(err, "failed to create registered seal proof type for FFI")
	}

	pieceFd := pieceFile.Fd()
	runtime.KeepAlive(pieceFile)

	stagedSectorFd := stagedSectorFile.Fd()
	runtime.KeepAlive(stagedSectorFile)

	resPtr := C.write_without_alignment(
		cProofType,
		C.int(pieceFd),
		C.uint64_t(pieceBytes),
		C.int(stagedSectorFd),
	)
	defer C.destroy_write_without_alignment_response(resPtr)

	if resPtr.status_code != 0 {
		return 0, cid.Undef, errors.New(C.GoString(resPtr.error_msg))
	}

	commP := goCommitment(&resPtr.comm_p[0])

	return abi.UnpaddedPieceSize(uint64(resPtr.total_write_unpadded)), commcid.PieceCommitmentV1ToCID(commP[:]), nil
}

// SealPreCommitPhase1
func SealPreCommitPhase1(
	proofType abi.RegisteredProof,
	cacheDirPath string,
	stagedSectorPath string,
	sealedSectorPath string,
	sectorNum abi.SectorNumber,
	proverID [32]byte,
	ticket abi.SealRandomness,
	pieces []abi.PieceInfo,
) (phase1Output []byte, err error) {
	cProofType, err := cRegisteredSealProof(proofType)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create registered seal proof type for FFI")
	}

	cCacheDirPath := C.CString(cacheDirPath)
	defer C.free(unsafe.Pointer(cCacheDirPath))

	cStagedSectorPath := C.CString(stagedSectorPath)
	defer C.free(unsafe.Pointer(cStagedSectorPath))

	cSealedSectorPath := C.CString(sealedSectorPath)
	defer C.free(unsafe.Pointer(cSealedSectorPath))

	proverIDCBytes := C.CBytes(proverID[:])
	defer C.free(proverIDCBytes)

	ticketCBytes := C.CBytes(from32ByteArray(to32ByteArray(ticket)))
	defer C.free(ticketCBytes)

	cPiecesPtr, cPiecesLen, err := cPublicPieceInfo(pieces)
	if err != nil {
		return nil, errors.Wrap(err, "could not convert to C.FFIPublicPieceInfo")
	}

	defer C.free(unsafe.Pointer(cPiecesPtr))

	resPtr := C.seal_pre_commit_phase1(
		cProofType,
		cCacheDirPath,
		cStagedSectorPath,
		cSealedSectorPath,
		C.uint64_t(uint64(sectorNum)),
		(*[32]C.uint8_t)(proverIDCBytes),
		(*[32]C.uint8_t)(ticketCBytes),
		(*C.FFIPublicPieceInfo)(cPiecesPtr),
		cPiecesLen,
	)
	defer C.destroy_seal_pre_commit_phase1_response(resPtr)

	if resPtr.status_code != 0 {
		return nil, errors.New(C.GoString(resPtr.error_msg))
	}

	return goBytes(resPtr.seal_pre_commit_phase1_output_ptr, resPtr.seal_pre_commit_phase1_output_len), nil
}

// SealPreCommitPhase2
func SealPreCommitPhase2(
	phase1Output []byte,
	cacheDirPath string,
	sealedSectorPath string,
) (sealedCID cid.Cid, unsealedCID cid.Cid, err error) {
	cCacheDirPath := C.CString(cacheDirPath)
	defer C.free(unsafe.Pointer(cCacheDirPath))

	cSealedSectorPath := C.CString(sealedSectorPath)
	defer C.free(unsafe.Pointer(cSealedSectorPath))

	phase1OutputCBytes := C.CBytes(phase1Output[:])
	defer C.free(phase1OutputCBytes)

	resPtr := C.seal_pre_commit_phase2(
		(*C.uint8_t)(phase1OutputCBytes),
		C.size_t(len(phase1Output)),
		cCacheDirPath,
		cSealedSectorPath,
	)
	defer C.destroy_seal_pre_commit_phase2_response(resPtr)

	if resPtr.status_code != 0 {
		return cid.Undef, cid.Undef, errors.New(C.GoString(resPtr.error_msg))
	}

	commR := goCommitment(&resPtr.comm_r[0])
	commD := goCommitment(&resPtr.comm_d[0])

	return commcid.ReplicaCommitmentV1ToCID(commR[:]), commcid.DataCommitmentV1ToCID(commD[:]), nil
}

// SealCommitPhase1
func SealCommitPhase1(
	proofType abi.RegisteredProof,
	sealedCID cid.Cid,
	unsealedCID cid.Cid,
	cacheDirPath string,
	sectorNum abi.SectorNumber,
	proverID [32]byte,
	ticket abi.SealRandomness,
	seed abi.InteractiveSealRandomness,
	pieces []abi.PieceInfo,
) (phase1Output []byte, err error) {
	cProofType, err := cRegisteredSealProof(proofType)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create registered seal proof type for FFI")
	}

	commR, err := commcid.CIDToReplicaCommitmentV1(sealedCID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to compute CommR from sealed CID")
	}

	commD, err := commcid.CIDToDataCommitmentV1(unsealedCID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to compute CommD from sealed CID")
	}

	commRCBytes := C.CBytes(from32ByteArray(to32ByteArray(commR)))
	defer C.free(commRCBytes)

	commDCBytes := C.CBytes(from32ByteArray(to32ByteArray(commD)))
	defer C.free(commDCBytes)

	cCacheDirPath := C.CString(cacheDirPath)
	defer C.free(unsafe.Pointer(cCacheDirPath))

	proverIDCBytes := C.CBytes(proverID[:])
	defer C.free(proverIDCBytes)

	ticketCBytes := C.CBytes(from32ByteArray(to32ByteArray(ticket)))
	defer C.free(ticketCBytes)

	seedCBytes := C.CBytes(from32ByteArray(to32ByteArray(seed)))
	defer C.free(seedCBytes)

	cPiecesPtr, cPiecesLen, err := cPublicPieceInfo(pieces)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create public piece info array for FFI")
	}

	defer C.free(unsafe.Pointer(cPiecesPtr))

	resPtr := C.seal_commit_phase1(
		cProofType,
		(*[CommitmentBytesLen]C.uint8_t)(commRCBytes),
		(*[CommitmentBytesLen]C.uint8_t)(commDCBytes),
		cCacheDirPath,
		C.uint64_t(uint64(sectorNum)),
		(*[32]C.uint8_t)(proverIDCBytes),
		(*[32]C.uint8_t)(ticketCBytes),
		(*[32]C.uint8_t)(seedCBytes),
		(*C.FFIPublicPieceInfo)(cPiecesPtr),
		cPiecesLen,
	)
	defer C.destroy_seal_commit_phase1_response(resPtr)

	if resPtr.status_code != 0 {
		return nil, errors.New(C.GoString(resPtr.error_msg))
	}

	return goBytes(resPtr.seal_commit_phase1_output_ptr, resPtr.seal_commit_phase1_output_len), nil
}

// SealCommitPhase2
func SealCommitPhase2(
	phase1Output []byte,
	sectorID abi.SectorNumber,
	proverID [32]byte,
) (abi.SealProof, error) {
	phase1OutputCBytes := C.CBytes(phase1Output)
	defer C.free(phase1OutputCBytes)

	proverIDCBytes := C.CBytes(proverID[:])
	defer C.free(proverIDCBytes)

	resPtr := C.seal_commit_phase2(
		(*C.uint8_t)(phase1OutputCBytes),
		C.size_t(len(phase1Output)),
		C.uint64_t(sectorID),
		(*[32]C.uint8_t)(proverIDCBytes),
	)
	defer C.destroy_seal_commit_phase2_response(resPtr)

	if resPtr.status_code != 0 {
		return abi.SealProof{}, errors.New(C.GoString(resPtr.error_msg))
	}

	return abi.SealProof{ProofBytes: goBytes(resPtr.proof_ptr, resPtr.proof_len)}, nil
}

// Unseal
func Unseal(
	proofType abi.RegisteredProof,
	cacheDirPath string,
	sealedSectorPath string,
	unsealOutputPath string,
	sectorNum abi.SectorNumber,
	proverID [32]byte,
	ticket abi.SealRandomness,
	unsealedCID cid.Cid,
) error {
	cProofType, err := cRegisteredSealProof(proofType)
	if err != nil {
		return errors.Wrap(err, "failed to create registered seal proof type for FFI")
	}

	commD, err := commcid.CIDToDataCommitmentV1(unsealedCID)
	if err != nil {
		return errors.Wrap(err, "failed to compute CommD from unsealed CID")
	}

	cCacheDirPath := C.CString(cacheDirPath)
	defer C.free(unsafe.Pointer(cCacheDirPath))

	cSealedSectorPath := C.CString(sealedSectorPath)
	defer C.free(unsafe.Pointer(cSealedSectorPath))

	cUnsealOutputPath := C.CString(unsealOutputPath)
	defer C.free(unsafe.Pointer(cUnsealOutputPath))

	proverIDCBytes := C.CBytes(proverID[:])
	defer C.free(proverIDCBytes)

	ticketCBytes := C.CBytes(from32ByteArray(to32ByteArray(ticket)))
	defer C.free(ticketCBytes)

	commDCBytes := C.CBytes(from32ByteArray(to32ByteArray(commD)))
	defer C.free(commDCBytes)

	resPtr := C.unseal(
		cProofType,
		cCacheDirPath,
		cSealedSectorPath,
		cUnsealOutputPath,
		C.uint64_t(uint64(sectorNum)),
		(*[32]C.uint8_t)(proverIDCBytes),
		(*[32]C.uint8_t)(ticketCBytes),
		(*[CommitmentBytesLen]C.uint8_t)(commDCBytes),
	)
	defer C.destroy_unseal_response(resPtr)

	if resPtr.status_code != 0 {
		return errors.New(C.GoString(resPtr.error_msg))
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
	proverID [32]byte,
	ticket abi.SealRandomness,
	unsealedCID cid.Cid,
	offset uint64,
	len uint64,
) error {
	cProofType, err := cRegisteredSealProof(proofType)
	if err != nil {
		return errors.Wrap(err, "failed to create registered seal proof type for FFI")
	}

	commD, err := commcid.CIDToDataCommitmentV1(unsealedCID)
	if err != nil {
		return errors.Wrap(err, "failed to compute CommD from unsealed CID")
	}

	cCacheDirPath := C.CString(cacheDirPath)
	defer C.free(unsafe.Pointer(cCacheDirPath))

	cSealedSectorPath := C.CString(sealedSectorPath)
	defer C.free(unsafe.Pointer(cSealedSectorPath))

	cUnsealOutputPath := C.CString(unsealOutputPath)
	defer C.free(unsafe.Pointer(cUnsealOutputPath))

	proverIDCBytes := C.CBytes(proverID[:])
	defer C.free(proverIDCBytes)

	ticketCBytes := C.CBytes(from32ByteArray(to32ByteArray(ticket)))
	defer C.free(ticketCBytes)

	commDCBytes := C.CBytes(from32ByteArray(to32ByteArray(commD)))
	defer C.free(commDCBytes)

	resPtr := C.unseal_range(
		cProofType,
		cCacheDirPath,
		cSealedSectorPath,
		cUnsealOutputPath,
		C.uint64_t(uint64(sectorNum)),
		(*[32]C.uint8_t)(proverIDCBytes),
		(*[32]C.uint8_t)(ticketCBytes),
		(*[CommitmentBytesLen]C.uint8_t)(commDCBytes),
		C.uint64_t(offset),
		C.uint64_t(len),
	)
	defer C.destroy_unseal_range_response(resPtr)

	if resPtr.status_code != 0 {
		return errors.New(C.GoString(resPtr.error_msg))
	}

	return nil
}

// FinalizeTicket creates an actual ticket from a partial ticket.
func FinalizeTicket(partialTicket abi.PartialTicket) ([32]byte, error) {
	partialTicketCBytes := C.CBytes(from32ByteArray(to32ByteArray(partialTicket)))
	defer C.free(partialTicketCBytes)

	resPtr := C.finalize_ticket(
		(*[32]C.uint8_t)(partialTicketCBytes),
	)
	defer C.destroy_finalize_ticket_response(resPtr)

	if resPtr.status_code != 0 {
		return [32]byte{}, errors.New(C.GoString(resPtr.error_msg))
	}

	return goCommitment(&resPtr.ticket[0]), nil
}

// GenerateCandidates
func GenerateCandidates(
	proverID [32]byte,
	randomness abi.PoStRandomness,
	challengeCount uint64,
	privateSectorInfo SortedPrivateSectorInfo,
) ([]PoStCandidateWithTicket, error) {
	randomessCBytes := C.CBytes(from32ByteArray(to32ByteArray(randomness)))
	defer C.free(randomessCBytes)

	proverIDCBytes := C.CBytes(proverID[:])
	defer C.free(proverIDCBytes)

	replicasPtr, replicasSize, err := cPrivateReplicaInfos(privateSectorInfo.Values())
	if err != nil {
		return nil, errors.Wrap(err, "failed to create private replica array")
	}

	defer C.free(unsafe.Pointer(replicasPtr))

	resPtr := C.generate_candidates(
		(*[32]C.uint8_t)(randomessCBytes),
		C.uint64_t(challengeCount),
		replicasPtr,
		replicasSize,
		(*[32]C.uint8_t)(proverIDCBytes),
	)
	defer C.destroy_generate_candidates_response(resPtr)

	if resPtr.status_code != 0 {
		return nil, errors.New(C.GoString(resPtr.error_msg))
	}

	candidates, err := goCandidatesWithTickets(resPtr.candidates_ptr, resPtr.candidates_len)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create candidates with tickets")
	}

	return candidates, nil
}

// GeneratePoSt
func GeneratePoSt(
	proverID [32]byte,
	privateSectorInfo SortedPrivateSectorInfo,
	randomness abi.PoStRandomness,
	winners []abi.PoStCandidate,
) ([]byte, error) {
	replicasPtr, replicasSize, err := cPrivateReplicaInfos(privateSectorInfo.Values())
	if err != nil {
		return nil, errors.Wrap(err, "failed to create private replica info array for FFI")
	}

	defer C.free(unsafe.Pointer(replicasPtr))

	randomnessCBytes := C.CBytes(from32ByteArray(to32ByteArray(randomness)))
	defer C.free(randomnessCBytes)

	winnersPtr, winnersSize := cCandidates(winners)
	defer C.free(unsafe.Pointer(winnersPtr))

	proverIDCBytes := C.CBytes(proverID[:])
	defer C.free(proverIDCBytes)

	resPtr := C.generate_post(
		(*[32]C.uint8_t)(randomnessCBytes),
		replicasPtr,
		replicasSize,
		winnersPtr,
		winnersSize,
		(*[32]C.uint8_t)(proverIDCBytes),
	)
	defer C.destroy_generate_post_response(resPtr)

	if resPtr.status_code != 0 {
		return nil, errors.New(C.GoString(resPtr.error_msg))
	}

	return goBytes(resPtr.flattened_proofs_ptr, resPtr.flattened_proofs_len), nil
}

// GetGPUDevices produces a slice of strings, each representing the name of a
// detected GPU device.
func GetGPUDevices() ([]string, error) {
	resPtr := C.get_gpu_devices()
	defer C.destroy_gpu_device_response(resPtr)

	if resPtr.status_code != 0 {
		return nil, errors.New(C.GoString(resPtr.error_msg))
	}

	devices := make([]string, resPtr.devices_len)
	if resPtr.devices_ptr == nil || resPtr.devices_len == 0 {
		return devices, nil
	}

	ptrs := (*[1 << 30]*C.char)(unsafe.Pointer(resPtr.devices_ptr))[:resPtr.devices_len:resPtr.devices_len]
	for i := 0; i < int(resPtr.devices_len); i++ {
		devices[i] = C.GoString(ptrs[i])
	}

	return devices, nil
}

// GetSealVersion
func GetSealVersion(
	proofType abi.RegisteredProof,
) (string, error) {
	cProofType, err := cRegisteredSealProof(proofType)
	if err != nil {
		return "", errors.Wrap(err, "failed to create registered seal proof type for FFI")
	}

	resPtr := C.get_seal_version(cProofType)
	defer C.destroy_string_response(resPtr)

	if resPtr.status_code != 0 {
		return "", errors.New(C.GoString(resPtr.error_msg))
	}

	return C.GoString(resPtr.string_val), nil
}

// GetPoStVersion
func GetPoStVersion(
	proofType abi.RegisteredProof,
) (string, error) {
	cProofType, err := cRegisteredPoStProof(proofType)
	if err != nil {
		return "", errors.Wrap(err, "failed to create registered PoSt proof type for FFI")
	}

	resPtr := C.get_post_version(cProofType)
	defer C.destroy_string_response(resPtr)

	if resPtr.status_code != 0 {
		return "", errors.New(C.GoString(resPtr.error_msg))
	}

	return C.GoString(resPtr.string_val), nil
}

// SingleProofPartitionProofLen denotes the number of bytes in a proof generated
// with a single partition. The number of bytes in a proof increases linearly
// with the number of partitions used when creating that proof.
const SingleProofPartitionProofLen = 192

func cPublicReplicaInfos(src []PublicSectorInfo) (*C.FFIPublicReplicaInfo, C.size_t, error) {
	srcCSizeT := C.size_t(len(src))

	// allocate array in C heap
	cPublicReplicas := C.malloc(srcCSizeT * C.sizeof_FFIPublicReplicaInfo)

	// create a Go slice backed by the C-array
	xs := (*[1 << 30]C.FFIPublicReplicaInfo)(cPublicReplicas)
	for i, v := range src {
		commR, err := commcid.CIDToReplicaCommitmentV1(v.SealedCID)
		if err != nil {
			return (*C.FFIPublicReplicaInfo)(unsafe.Pointer(nil)), 0, errors.Wrap(err, "failed to transform sealed CID to CommR")
		}

		commRAry := to32ByteArray(commR)

		cProofType, err := cRegisteredPoStProof(v.PoStProofType)
		if err != nil {
			return (*C.FFIPublicReplicaInfo)(unsafe.Pointer(nil)), 0, errors.Wrap(err, "failed to create registered PoSt proof type for FFI")
		}

		xs[i] = C.FFIPublicReplicaInfo{
			comm_r:           *(*[CommitmentBytesLen]C.uint8_t)(unsafe.Pointer(&commRAry)),
			registered_proof: cProofType,
			sector_id:        C.uint64_t(v.SectorNum),
		}
	}

	return (*C.FFIPublicReplicaInfo)(cPublicReplicas), srcCSizeT, nil
}

func cPublicPieceInfo(src []abi.PieceInfo) (*C.FFIPublicPieceInfo, C.size_t, error) {
	srcCSizeT := C.size_t(len(src))

	// allocate array in C heap
	cPublicPieceInfos := C.malloc(srcCSizeT * C.sizeof_FFIPublicPieceInfo)

	// create a Go slice backed by the C-array
	xs := (*[1 << 30]C.FFIPublicPieceInfo)(cPublicPieceInfos)
	for i, v := range src {
		commP, err := commcid.CIDToPieceCommitmentV1(v.PieceCID)
		if err != nil {
			return (*C.FFIPublicPieceInfo)(unsafe.Pointer(nil)), 0, errors.Wrap(err, "failed to create CommP from PieceCID")
		}

		commPAry := to32ByteArray(commP)

		xs[i] = C.FFIPublicPieceInfo{
			num_bytes: C.uint64_t(v.Size.Unpadded()),
			comm_p:    *(*[CommitmentBytesLen]C.uint8_t)(unsafe.Pointer(&commPAry)),
		}
	}

	return (*C.FFIPublicPieceInfo)(cPublicPieceInfos), srcCSizeT, nil
}

func cUint64s(src []uint64) (*C.uint64_t, C.size_t) {
	srcCSizeT := C.size_t(len(src))

	// allocate array in C heap
	cUint64s := C.malloc(srcCSizeT * C.sizeof_uint64_t)

	// create a Go slice backed by the C-array
	pp := (*[1 << 30]C.uint64_t)(cUint64s)
	for i, v := range src {
		pp[i] = C.uint64_t(v)
	}

	return (*C.uint64_t)(cUint64s), srcCSizeT
}

func cCandidates(src []abi.PoStCandidate) (*C.FFICandidate, C.size_t) {
	srcCSizeT := C.size_t(len(src))

	// allocate array in C heap
	cCandidates := C.malloc(srcCSizeT * C.sizeof_FFICandidate)

	// create a Go slice backed by the C-array
	pp := (*[1 << 30]C.FFICandidate)(cCandidates)
	for i, v := range src {
		pt := to32ByteArray(v.PartialTicket)

		pp[i] = C.FFICandidate{
			sector_id:              C.uint64_t(uint64(v.SectorID.Number)),
			partial_ticket:         *(*[32]C.uint8_t)(unsafe.Pointer(&pt)),
			ticket:                 *(*[32]C.uint8_t)(unsafe.Pointer(&pt)), // this field is ignored by verify_post and generate_post
			sector_challenge_index: C.uint64_t(v.ChallengeIndex),
		}
	}

	return (*C.FFICandidate)(cCandidates), srcCSizeT
}

func cPrivateReplicaInfos(src []PrivateSectorInfo) (*C.FFIPrivateReplicaInfo, C.size_t, error) {
	srcCSizeT := C.size_t(len(src))

	cPrivateReplicas := C.malloc(srcCSizeT * C.sizeof_FFIPrivateReplicaInfo)

	pp := (*[1 << 30]C.FFIPrivateReplicaInfo)(cPrivateReplicas)
	for i, v := range src {
		commR, err := commcid.CIDToReplicaCommitmentV1(v.SealedCID)
		if err != nil {
			return (*C.FFIPrivateReplicaInfo)(unsafe.Pointer(nil)), 0, errors.Wrap(err, "failed to transform sealed CID to CommR")
		}

		commRAry := to32ByteArray(commR)

		proofType, err := cRegisteredPoStProof(v.PoStProofType)
		if err != nil {
			return (*C.FFIPrivateReplicaInfo)(unsafe.Pointer(nil)), 0, errors.Wrap(err, "failed to create PoSt proof type")
		}

		pp[i] = C.FFIPrivateReplicaInfo{
			cache_dir_path:   C.CString(v.CacheDirPath),
			comm_r:           *(*[CommitmentBytesLen]C.uint8_t)(unsafe.Pointer(&commRAry)),
			replica_path:     C.CString(v.SealedSectorPath),
			sector_id:        C.uint64_t(v.SectorNum),
			registered_proof: proofType,
		}
	}

	return (*C.FFIPrivateReplicaInfo)(cPrivateReplicas), srcCSizeT, nil
}

func goBytes(src *C.uint8_t, size C.size_t) []byte {
	return C.GoBytes(unsafe.Pointer(src), C.int(size))
}

func goCandidatesWithTickets(src *C.FFICandidate, size C.size_t) ([]PoStCandidateWithTicket, error) {
	candidates := make([]PoStCandidateWithTicket, size)
	if src == nil || size == 0 {
		return candidates, nil
	}

	ptrs := (*[1 << 30]C.FFICandidate)(unsafe.Pointer(src))[:size:size]
	for i := 0; i < int(size); i++ {
		candidates[i] = goCandidateWithTicket(ptrs[i])
	}

	return candidates, nil
}

func goCandidateWithTicket(src C.FFICandidate) PoStCandidateWithTicket {
	p := goCommitment(&src.partial_ticket[0])

	return PoStCandidateWithTicket{
		Candidate: abi.PoStCandidate{
			SectorID: abi.SectorID{
				Miner:  0,
				Number: abi.SectorNumber(uint64(src.sector_id)),
			},
			PartialTicket:  p[:],
			ChallengeIndex: int64(src.sector_challenge_index),
		},
		Ticket: goCommitment(&src.ticket[0]),
	}
}

func goCommitment(src *C.uint8_t) [CommitmentBytesLen]byte {
	return to32ByteArray(C.GoBytes(unsafe.Pointer(src), 32))
}

func to32ByteArray(in []byte) [32]byte {
	var out [32]byte
	copy(out[:], in)

	return out
}

func from32ByteArray(in [32]byte) []byte {
	return in[:]
}
