package ffi

import (
	"bytes"
	"encoding/json"
	"os"
	"runtime"
	"sort"
	"time"
	"unsafe"

	logging "github.com/ipfs/go-log"
	"github.com/pkg/errors"
)

// #cgo LDFLAGS: ${SRCDIR}/libfilecoin.a
// #cgo pkg-config: ${SRCDIR}/filecoin.pc
// #include "./filecoin.h"
import "C"

var log = logging.Logger("libfilecoin") // nolint: deadcode

func elapsed(what string) func() {
	start := time.Now()
	return func() {
		log.Debugf("%s took %v\n", what, time.Since(start))
	}
}

// SortedPublicSectorInfo is a slice of PublicSectorInfo sorted
// (lexicographically, ascending) by replica commitment (CommR).
type SortedPublicSectorInfo struct {
	f []SectorPublicInfo
}

// SortedPrivateSectorInfo is a slice of PrivateSectorInfo sorted
// (lexicographically, ascending) by replica commitment (CommR).
type SortedPrivateSectorInfo struct {
	f []SectorPrivateInfo
}

// SealTicket is required for the first step of Interactive PoRep.
type SealTicket struct {
	BlockHeight uint64
	TicketBytes [32]byte
}

// SealSeed is required for the second step of Interactive PoRep.
type SealSeed struct {
	BlockHeight uint64
	TicketBytes [32]byte
}

type Candidate struct {
	SectorID             uint64
	PartialTicket        [32]byte
	Ticket               [32]byte
	SectorChallengeIndex uint64
}

// NewSortedSectorPublicInfo returns a SortedPublicSectorInfo
func NewSortedSectorPublicInfo(sectorInfo ...SectorPublicInfo) SortedPublicSectorInfo {
	fn := func(i, j int) bool {
		return bytes.Compare(sectorInfo[i].CommR[:], sectorInfo[j].CommR[:]) == -1
	}

	sort.Slice(sectorInfo[:], fn)

	return SortedPublicSectorInfo{
		f: sectorInfo,
	}
}

// Values returns the sorted SectorPublicInfo as a slice
func (s *SortedPublicSectorInfo) Values() []SectorPublicInfo {
	return s.f
}

// MarshalJSON JSON-encodes and serializes the SortedPublicSectorInfo.
func (s SortedPublicSectorInfo) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.f)
}

// UnmarshalJSON parses the JSON-encoded byte slice and stores the result in the
// value pointed to by s.f. Note that this method allows for construction of a
// SortedPublicSectorInfo which violates its invariant (that its SectorPublicInfo are sorted
// in some defined way). Callers should take care to never provide a byte slice
// which would violate this invariant.
func (s *SortedPublicSectorInfo) UnmarshalJSON(b []byte) error {
	return json.Unmarshal(b, &s.f)
}

type SectorPublicInfo struct {
	SectorID uint64
	CommR    [CommitmentBytesLen]byte
}

// NewSortedSectorPrivateInfo returns a SortedPrivateSectorInfo
func NewSortedSectorPrivateInfo(sectorInfo ...SectorPrivateInfo) SortedPrivateSectorInfo {
	fn := func(i, j int) bool {
		return bytes.Compare(sectorInfo[i].CommR[:], sectorInfo[j].CommR[:]) == -1
	}

	sort.Slice(sectorInfo[:], fn)

	return SortedPrivateSectorInfo{
		f: sectorInfo,
	}
}

// Values returns the sorted SectorPrivateInfo as a slice
func (s *SortedPrivateSectorInfo) Values() []SectorPrivateInfo {
	return s.f
}

// MarshalJSON JSON-encodes and serializes the SortedPrivateSectorInfo.
func (s SortedPrivateSectorInfo) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.f)
}

func (s *SortedPrivateSectorInfo) UnmarshalJSON(b []byte) error {
	return json.Unmarshal(b, &s.f)
}

type SectorPrivateInfo struct {
	SectorID         uint64
	CommR            [CommitmentBytesLen]byte
	CacheDirPath     string
	SealedSectorPath string
}

// CommitmentBytesLen is the number of bytes in a CommR, CommD, CommP, and CommRStar.
const CommitmentBytesLen = 32

// SealPreCommitOutput is used to acquire a seed from the chain for the second
// step of Interactive PoRep.
type SealPreCommitOutput struct {
	SectorID uint64
	CommD    [CommitmentBytesLen]byte
	CommR    [CommitmentBytesLen]byte
	Pieces   []PieceMetadata
	Ticket   SealTicket
}

// RawSealPreCommitOutput is used to acquire a seed from the chain for the
// second step of Interactive PoRep. The PersistentAux is not expected to appear
// on-chain, but is needed for committing. This struct is useful for standalone
// (e.g. no sector builder) sealing.
type RawSealPreCommitOutput struct {
	CommC     [CommitmentBytesLen]byte
	CommD     [CommitmentBytesLen]byte
	CommR     [CommitmentBytesLen]byte
	CommRLast [CommitmentBytesLen]byte
}

// SealCommitOutput is produced by the second step of Interactive PoRep.
type SealCommitOutput struct {
	SectorID uint64
	CommD    [CommitmentBytesLen]byte
	CommR    [CommitmentBytesLen]byte
	Proof    []byte
	Pieces   []PieceMetadata
	Ticket   SealTicket
	Seed     SealSeed
}

// PieceMetadata represents a piece stored by the sector builder.
type PieceMetadata struct {
	Key   string
	Size  uint64
	CommP [CommitmentBytesLen]byte
}

// PublicPieceInfo is an on-chain tuple of CommP and aligned piece-size.
type PublicPieceInfo struct {
	Size  uint64
	CommP [CommitmentBytesLen]byte
}

// VerifySeal returns true if the sealing operation from which its inputs were
// derived was valid, and false if not.
func VerifySeal(
	sectorSize uint64,
	commR [CommitmentBytesLen]byte,
	commD [CommitmentBytesLen]byte,
	proverID [32]byte,
	ticket [32]byte,
	seed [32]byte,
	sectorID uint64,
	proof []byte,
) (bool, error) {
	defer elapsed("VerifySeal")()

	commDCBytes := C.CBytes(commD[:])
	defer C.free(commDCBytes)

	commRCBytes := C.CBytes(commR[:])
	defer C.free(commRCBytes)

	proofCBytes := C.CBytes(proof[:])
	defer C.free(proofCBytes)

	proverIDCBytes := C.CBytes(proverID[:])
	defer C.free(proverIDCBytes)

	ticketCBytes := C.CBytes(ticket[:])
	defer C.free(ticketCBytes)

	seedCBytes := C.CBytes(seed[:])
	defer C.free(seedCBytes)

	// a mutable pointer to a VerifySealResponse C-struct
	resPtr := C.verify_seal(
		C.uint64_t(sectorSize),
		(*[CommitmentBytesLen]C.uint8_t)(commRCBytes),
		(*[CommitmentBytesLen]C.uint8_t)(commDCBytes),
		(*[32]C.uint8_t)(proverIDCBytes),
		(*[32]C.uint8_t)(ticketCBytes),
		(*[32]C.uint8_t)(seedCBytes),
		C.uint64_t(sectorID),
		(*C.uint8_t)(proofCBytes),
		C.size_t(len(proof)),
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
	sectorSize uint64,
	sectorInfo SortedPublicSectorInfo,
	randomness [32]byte,
	challengeCount uint64,
	proof []byte,
	winners []Candidate,
	proverID [32]byte,
) (bool, error) {
	defer elapsed("VerifyPoSt")()

	// CommRs and sector ids must be provided to C.verify_post in the same order
	// that they were provided to the C.generate_post
	sortedCommRs := make([][CommitmentBytesLen]byte, len(sectorInfo.Values()))
	sortedSectorIds := make([]uint64, len(sectorInfo.Values()))
	for idx, v := range sectorInfo.Values() {
		sortedCommRs[idx] = v.CommR
		sortedSectorIds[idx] = v.SectorID
	}

	// flattening the byte slice makes it easier to copy into the C heap
	flattened := make([]byte, CommitmentBytesLen*len(sortedCommRs))
	for idx, commR := range sortedCommRs {
		copy(flattened[(CommitmentBytesLen*idx):(CommitmentBytesLen*(1+idx))], commR[:])
	}

	// copy bytes from Go to C heap
	flattenedCommRsCBytes := C.CBytes(flattened)
	defer C.free(flattenedCommRsCBytes)

	randomnessCBytes := C.CBytes(randomness[:])
	defer C.free(randomnessCBytes)

	proofCBytes := C.CBytes(proof)
	defer C.free(proofCBytes)

	// allocate fixed-length array of uint64s in C heap
	sectorIdsPtr, sectorIdsSize := cUint64s(sortedSectorIds)
	defer C.free(unsafe.Pointer(sectorIdsPtr))

	winnersPtr, winnersSize := cCandidates(winners)
	defer C.free(unsafe.Pointer(winnersPtr))

	proverIDCBytes := C.CBytes(proverID[:])
	defer C.free(proverIDCBytes)

	// a mutable pointer to a VerifyPoStResponse C-struct
	resPtr := C.verify_post(
		C.uint64_t(sectorSize),
		(*[32]C.uint8_t)(randomnessCBytes),
		C.uint64_t(challengeCount),
		sectorIdsPtr,
		sectorIdsSize,
		(*C.uint8_t)(flattenedCommRsCBytes),
		C.size_t(len(flattened)),
		(*C.uint8_t)(proofCBytes),
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

// GetMaxUserBytesPerStagedSector returns the number of user bytes that will fit
// into a staged sector. Due to bit-padding, the number of user bytes that will
// fit into the staged sector will be less than number of bytes in sectorSize.
func GetMaxUserBytesPerStagedSector(sectorSize uint64) uint64 {
	defer elapsed("GetMaxUserBytesPerStagedSector")()

	return uint64(C.get_max_user_bytes_per_staged_sector(C.uint64_t(sectorSize)))
}

// FinalizeTicket creates an actual ticket from a partial ticket.
func FinalizeTicket(partialTicket [32]byte) ([32]byte, error) {
	defer elapsed("FinalizeTicket")()

	partialTicketPtr := unsafe.Pointer(&(partialTicket)[0])
	resPtr := C.finalize_ticket(
		(*[32]C.uint8_t)(partialTicketPtr),
	)
	defer C.destroy_finalize_ticket_response(resPtr)

	if resPtr.status_code != 0 {
		return [32]byte{}, errors.New(C.GoString(resPtr.error_msg))
	}

	return goCommitment(&resPtr.ticket[0]), nil
}

// GeneratePieceCommitment produces a piece commitment for the provided data
// stored at a given path.
func GeneratePieceCommitment(piecePath string, pieceSize uint64) ([CommitmentBytesLen]byte, error) {
	pieceFile, err := os.Open(piecePath)
	if err != nil {
		return [CommitmentBytesLen]byte{}, err
	}

	return GeneratePieceCommitmentFromFile(pieceFile, pieceSize)
}

// GenerateDataCommitment produces a commitment for the sector containing the
// provided pieces.
func GenerateDataCommitment(sectorSize uint64, pieces []PublicPieceInfo) ([CommitmentBytesLen]byte, error) {
	cPiecesPtr, cPiecesLen := cPublicPieceInfo(pieces)
	defer C.free(unsafe.Pointer(cPiecesPtr))

	resPtr := C.generate_data_commitment(C.uint64_t(sectorSize), (*C.FFIPublicPieceInfo)(cPiecesPtr), cPiecesLen)
	defer C.destroy_generate_data_commitment_response(resPtr)

	if resPtr.status_code != 0 {
		return [CommitmentBytesLen]byte{}, errors.New(C.GoString(resPtr.error_msg))
	}

	return goCommitment(&resPtr.comm_d[0]), nil
}

// GeneratePieceCommitmentFromFile produces a piece commitment for the provided data
// stored in a given file.
func GeneratePieceCommitmentFromFile(pieceFile *os.File, pieceSize uint64) (commP [CommitmentBytesLen]byte, err error) {
	pieceFd := pieceFile.Fd()

	resPtr := C.generate_piece_commitment(C.int(pieceFd), C.uint64_t(pieceSize))
	defer C.destroy_generate_piece_commitment_response(resPtr)

	// Make sure our filedescriptor stays alive, stayin alive
	runtime.KeepAlive(pieceFile)

	if resPtr.status_code != 0 {
		return [CommitmentBytesLen]byte{}, errors.New(C.GoString(resPtr.error_msg))
	}

	return goCommitment(&resPtr.comm_p[0]), nil
}

// WriteWithAlignment
func WriteWithAlignment(
	pieceFile *os.File,
	pieceBytes uint64,
	stagedSectorFile *os.File,
	existingPieceSizes []uint64,
) (leftAlignment, total uint64, commP [CommitmentBytesLen]byte, retErr error) {
	defer elapsed("WriteWithAlignment")()

	pieceFd := pieceFile.Fd()
	runtime.KeepAlive(pieceFile)

	stagedSectorFd := stagedSectorFile.Fd()
	runtime.KeepAlive(stagedSectorFile)

	ptr, len := cUint64s(existingPieceSizes)
	defer C.free(unsafe.Pointer(ptr))

	resPtr := C.write_with_alignment(
		C.int(pieceFd),
		C.uint64_t(pieceBytes),
		C.int(stagedSectorFd),
		ptr,
		len,
	)
	defer C.destroy_write_with_alignment_response(resPtr)

	if resPtr.status_code != 0 {
		return 0, 0, [CommitmentBytesLen]byte{}, errors.New(C.GoString(resPtr.error_msg))
	}

	return uint64(resPtr.left_alignment_unpadded), uint64(resPtr.total_write_unpadded), goCommitment(&resPtr.comm_p[0]), nil
}

// WriteWithoutAlignment
func WriteWithoutAlignment(
	pieceFile *os.File,
	pieceBytes uint64,
	stagedSectorFile *os.File,
) (uint64, [CommitmentBytesLen]byte, error) {
	defer elapsed("WriteWithoutAlignment")()

	pieceFd := pieceFile.Fd()
	runtime.KeepAlive(pieceFile)

	stagedSectorFd := stagedSectorFile.Fd()
	runtime.KeepAlive(stagedSectorFile)

	resPtr := C.write_without_alignment(
		C.int(pieceFd),
		C.uint64_t(pieceBytes),
		C.int(stagedSectorFd),
	)
	defer C.destroy_write_without_alignment_response(resPtr)

	if resPtr.status_code != 0 {
		return 0, [CommitmentBytesLen]byte{}, errors.New(C.GoString(resPtr.error_msg))
	}

	return uint64(resPtr.total_write_unpadded), goCommitment(&resPtr.comm_p[0]), nil
}

// SealPreCommit
func SealPreCommit(
	sectorSize uint64,
	poRepProofPartitions uint8,
	cacheDirPath string,
	stagedSectorPath string,
	sealedSectorPath string,
	sectorID uint64,
	proverID [32]byte,
	ticket [32]byte,
	pieces []PublicPieceInfo,
) (RawSealPreCommitOutput, error) {
	defer elapsed("SealPreCommit")()

	cCacheDirPath := C.CString(cacheDirPath)
	defer C.free(unsafe.Pointer(cCacheDirPath))

	cStagedSectorPath := C.CString(stagedSectorPath)
	defer C.free(unsafe.Pointer(cStagedSectorPath))

	cSealedSectorPath := C.CString(sealedSectorPath)
	defer C.free(unsafe.Pointer(cSealedSectorPath))

	proverIDCBytes := C.CBytes(proverID[:])
	defer C.free(proverIDCBytes)

	ticketCBytes := C.CBytes(ticket[:])
	defer C.free(ticketCBytes)

	cPiecesPtr, cPiecesLen := cPublicPieceInfo(pieces)
	defer C.free(unsafe.Pointer(cPiecesPtr))

	resPtr := C.seal_pre_commit(
		cSectorClass(sectorSize, poRepProofPartitions),
		cCacheDirPath,
		cStagedSectorPath,
		cSealedSectorPath,
		C.uint64_t(sectorID),
		(*[32]C.uint8_t)(proverIDCBytes),
		(*[32]C.uint8_t)(ticketCBytes),
		(*C.FFIPublicPieceInfo)(cPiecesPtr),
		cPiecesLen,
	)
	defer C.destroy_seal_pre_commit_response(resPtr)

	if resPtr.status_code != 0 {
		return RawSealPreCommitOutput{}, errors.New(C.GoString(resPtr.error_msg))
	}

	return goRawSealPreCommitOutput(resPtr.seal_pre_commit_output), nil
}

// SealCommit
func SealCommit(
	sectorSize uint64,
	poRepProofPartitions uint8,
	cacheDirPath string,
	sectorID uint64,
	proverID [32]byte,
	ticket [32]byte,
	seed [32]byte,
	pieces []PublicPieceInfo,
	rspco RawSealPreCommitOutput,
) ([]byte, error) {
	defer elapsed("SealCommit")()

	cCacheDirPath := C.CString(cacheDirPath)
	defer C.free(unsafe.Pointer(cCacheDirPath))

	proverIDCBytes := C.CBytes(proverID[:])
	defer C.free(proverIDCBytes)

	ticketCBytes := C.CBytes(ticket[:])
	defer C.free(ticketCBytes)

	seedCBytes := C.CBytes(seed[:])
	defer C.free(seedCBytes)

	cPiecesPtr, cPiecesLen := cPublicPieceInfo(pieces)
	defer C.free(unsafe.Pointer(cPiecesPtr))

	resPtr := C.seal_commit(
		cSectorClass(sectorSize, poRepProofPartitions),
		cCacheDirPath,
		C.uint64_t(sectorID),
		(*[32]C.uint8_t)(proverIDCBytes),
		(*[32]C.uint8_t)(ticketCBytes),
		(*[32]C.uint8_t)(seedCBytes),
		(*C.FFIPublicPieceInfo)(cPiecesPtr),
		cPiecesLen,
		cSealPreCommitOutput(rspco),
	)
	defer C.destroy_seal_commit_response(resPtr)

	if resPtr.status_code != 0 {
		return nil, errors.New(C.GoString(resPtr.error_msg))
	}

	return C.GoBytes(unsafe.Pointer(resPtr.proof_ptr), C.int(resPtr.proof_len)), nil
}

// Unseal
func Unseal(
	sectorSize uint64,
	poRepProofPartitions uint8,
	cacheDirPath string,
	sealedSectorPath string,
	unsealOutputPath string,
	sectorID uint64,
	proverID [32]byte,
	ticket [32]byte,
	commD [CommitmentBytesLen]byte,
) error {
	defer elapsed("Unseal")()

	cCacheDirPath := C.CString(cacheDirPath)
	defer C.free(unsafe.Pointer(cCacheDirPath))

	cSealedSectorPath := C.CString(sealedSectorPath)
	defer C.free(unsafe.Pointer(cSealedSectorPath))

	cUnsealOutputPath := C.CString(unsealOutputPath)
	defer C.free(unsafe.Pointer(cUnsealOutputPath))

	proverIDCBytes := C.CBytes(proverID[:])
	defer C.free(proverIDCBytes)

	ticketCBytes := C.CBytes(ticket[:])
	defer C.free(ticketCBytes)

	commDCBytes := C.CBytes(commD[:])
	defer C.free(commDCBytes)

	resPtr := C.unseal(
		cSectorClass(sectorSize, poRepProofPartitions),
		cCacheDirPath,
		cSealedSectorPath,
		cUnsealOutputPath,
		C.uint64_t(sectorID),
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

// GenerateCandidates
func GenerateCandidates(
	sectorSize uint64,
	proverID [32]byte,
	randomness [32]byte,
	challengeCount uint64,
	privateSectorInfo SortedPrivateSectorInfo,
) ([]Candidate, error) {
	defer elapsed("GenerateCandidates")()

	randomessCBytes := C.CBytes(randomness[:])
	defer C.free(randomessCBytes)

	proverIDCBytes := C.CBytes(proverID[:])
	defer C.free(proverIDCBytes)

	replicasPtr, replicasSize := cPrivateReplicaInfos(privateSectorInfo.Values())
	defer C.free(unsafe.Pointer(replicasPtr))

	resPtr := C.generate_candidates(
		C.uint64_t(sectorSize),
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

	return goCandidates(resPtr.candidates_ptr, resPtr.candidates_len)
}

// GeneratePoSt
func GeneratePoSt(
	sectorSize uint64,
	proverID [32]byte,
	privateSectorInfo SortedPrivateSectorInfo,
	randomness [32]byte,
	winners []Candidate,
) ([]byte, error) {
	defer elapsed("GeneratePoSt")()

	replicasPtr, replicasSize := cPrivateReplicaInfos(privateSectorInfo.Values())
	defer C.free(unsafe.Pointer(replicasPtr))

	winnersPtr, winnersSize := cCandidates(winners)
	defer C.free(unsafe.Pointer(winnersPtr))

	proverIDCBytes := C.CBytes(proverID[:])
	defer C.free(proverIDCBytes)

	resPtr := C.generate_post(
		C.uint64_t(sectorSize),
		(*[32]C.uint8_t)(unsafe.Pointer(&(randomness)[0])),
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
