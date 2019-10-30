package go_sectorbuilder

import (
	"bytes"
	"encoding/json"
	"os"
	"runtime"
	"sort"
	"time"
	"unsafe"

	"github.com/filecoin-project/go-sectorbuilder/sealed_sector_health"
	"github.com/filecoin-project/go-sectorbuilder/sealing_state"

	logging "github.com/ipfs/go-log"
	"github.com/pkg/errors"
)

// #cgo LDFLAGS: ${SRCDIR}/libsector_builder_ffi.a
// #cgo pkg-config: ${SRCDIR}/sector_builder_ffi.pc
// #include "./sector_builder_ffi.h"
import "C"

var log = logging.Logger("libsectorbuilder") // nolint: deadcode

func elapsed(what string) func() {
	start := time.Now()
	return func() {
		log.Debugf("%s took %v\n", what, time.Since(start))
	}
}

// SortedSectorInfo is a slice of SectorInfo sorted (lexicographically,
// ascending) by replica commitment (CommR).
type SortedSectorInfo struct {
	f []SectorInfo
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

// NewSortedSectorInfo returns a SortedSectorInfo
func NewSortedSectorInfo(sectorInfo ...SectorInfo) SortedSectorInfo {
	fn := func(i, j int) bool {
		return bytes.Compare(sectorInfo[i].CommR[:], sectorInfo[j].CommR[:]) == -1
	}

	sort.Slice(sectorInfo[:], fn)

	return SortedSectorInfo{
		f: sectorInfo,
	}
}

// Values returns the sorted SectorInfo as a slice
func (s *SortedSectorInfo) Values() []SectorInfo {
	return s.f
}

// MarshalJSON JSON-encodes and serializes the SortedSectorInfo.
func (s SortedSectorInfo) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.f)
}

// UnmarshalJSON parses the JSON-encoded byte slice and stores the result in the
// value pointed to by s.f. Note that this method allows for construction of a
// SortedSectorInfo which violates its invariant (that its SectorInfo are sorted
// in some defined way). Callers should take care to never provide a byte slice
// which would violate this invariant.
func (s *SortedSectorInfo) UnmarshalJSON(b []byte) error {
	return json.Unmarshal(b, &s.f)
}

type SectorInfo struct {
	SectorID uint64
	CommR    [CommitmentBytesLen]byte
}

// CommitmentBytesLen is the number of bytes in a CommR, CommD, CommP, and CommRStar.
const CommitmentBytesLen = 32

// StagedSectorMetadata is a sector into which we write user piece-data before
// sealing. Note: SectorID is unique across all staged and sealed sectors for a
// storage miner actor.
type StagedSectorMetadata struct {
	SectorID uint64
}

// SealedSectorMetadata represents a sector in the builder that has been sealed.
type SealedSectorMetadata struct {
	SectorID uint64
	CommD    [CommitmentBytesLen]byte
	CommR    [CommitmentBytesLen]byte
	Proof    []byte
	Pieces   []PieceMetadata
	Health   sealed_sector_health.Health
	Ticket   SealTicket
	Seed     SealSeed
}

// SealPreCommitOutput is used to acquire a seed from the chain for the second
// step of Interactive PoRep.
type SealPreCommitOutput struct {
	SectorID uint64
	CommD    [CommitmentBytesLen]byte
	CommR    [CommitmentBytesLen]byte
	Pieces   []PieceMetadata
	Ticket   SealTicket
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

// SectorSealingStatus communicates how far along in the sealing process a
// sector has progressed.
type SectorSealingStatus struct {
	SectorID     uint64
	State        sealing_state.State
	SealErrorMsg string                   // will be nil unless State == Failed
	CommD        [CommitmentBytesLen]byte // will be empty unless State == Committed
	CommR        [CommitmentBytesLen]byte // will be empty unless State == Committed
	Proof        []byte                   // will be empty unless State == Committed
	Pieces       []PieceMetadata          // will be empty unless State == Committed
	Ticket       SealTicket               // will be empty unless State == Committed
	Seed         SealSeed                 // will be empty unless State == Committed
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
	pieces []PublicPieceInfo,
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

	cPiecesPtr, cPiecesLen := cPublicPieceInfo(pieces)
	defer C.free(unsafe.Pointer(cPiecesPtr))

	// a mutable pointer to a VerifySealResponse C-struct
	resPtr := C.sector_builder_ffi_verify_seal(
		C.uint64_t(sectorSize),
		(*[CommitmentBytesLen]C.uint8_t)(commRCBytes),
		(*[CommitmentBytesLen]C.uint8_t)(commDCBytes),
		(*[32]C.uint8_t)(proverIDCBytes),
		C.uint64_t(sectorID),
		(*[32]C.uint8_t)(ticketCBytes),
		(*[32]C.uint8_t)(seedCBytes),
		(*C.uint8_t)(proofCBytes),
		C.size_t(len(proof)),
		(*C.sector_builder_ffi_FFIPublicPieceInfo)(cPiecesPtr),
		cPiecesLen,
	)
	defer C.sector_builder_ffi_destroy_verify_seal_response(resPtr)

	if resPtr.status_code != 0 {
		return false, errors.New(C.GoString(resPtr.error_msg))
	}

	return bool(resPtr.is_valid), nil
}

// VerifyPoSt returns true if the PoSt-generation operation from which its
// inputs were derived was valid, and false if not.
func VerifyPoSt(
	sectorSize uint64,
	sectorInfo SortedSectorInfo,
	challengeSeed [32]byte,
	proof []byte,
	faults []uint64,
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

	challengeSeedCBytes := C.CBytes(challengeSeed[:])
	defer C.free(challengeSeedCBytes)

	proofCBytes := C.CBytes(proof)
	defer C.free(proofCBytes)

	// allocate fixed-length array of uint64s in C heap
	sectorIdsPtr, sectorIdsSize := cUint64s(sortedSectorIds)
	defer C.free(unsafe.Pointer(sectorIdsPtr))

	faultsPtr, faultsSize := cUint64s(faults)
	defer C.free(unsafe.Pointer(faultsPtr))

	// a mutable pointer to a VerifyPoStResponse C-struct
	resPtr := C.sector_builder_ffi_verify_post(
		C.uint64_t(sectorSize),
		(*[CommitmentBytesLen]C.uint8_t)(challengeSeedCBytes),
		sectorIdsPtr,
		sectorIdsSize,
		faultsPtr,
		faultsSize,
		(*C.uint8_t)(flattenedCommRsCBytes),
		C.size_t(len(flattened)),
		(*C.uint8_t)(proofCBytes),
		C.size_t(len(proof)),
	)
	defer C.sector_builder_ffi_destroy_verify_post_response(resPtr)

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

	return uint64(C.sector_builder_ffi_get_max_user_bytes_per_staged_sector(C.uint64_t(sectorSize)))
}

// InitSectorBuilder allocates and returns a pointer to a sector builder.
func InitSectorBuilder(
	sectorSize uint64,
	poRepProofPartitions uint8,
	lastUsedSectorID uint64,
	metadataDir string,
	proverID [32]byte,
	sealedSectorDir string,
	stagedSectorDir string,
	sectorCacheRootDir string,
	maxNumOpenStagedSectors uint8,
	numWorkerThreads uint8,
) (unsafe.Pointer, error) {
	defer elapsed("InitSectorBuilder")()

	cMetadataDir := C.CString(metadataDir)
	defer C.free(unsafe.Pointer(cMetadataDir))

	proverIDCBytes := C.CBytes(proverID[:])
	defer C.free(proverIDCBytes)

	cStagedSectorDir := C.CString(stagedSectorDir)
	defer C.free(unsafe.Pointer(cStagedSectorDir))

	cSealedSectorDir := C.CString(sealedSectorDir)
	defer C.free(unsafe.Pointer(cSealedSectorDir))

	cSectorCacheRootDir := C.CString(sectorCacheRootDir)
	defer C.free(unsafe.Pointer(cSectorCacheRootDir))

	class, err := cSectorClass(sectorSize, poRepProofPartitions)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get sector class")
	}

	resPtr := C.sector_builder_ffi_init_sector_builder(
		class,
		C.uint64_t(lastUsedSectorID),
		cMetadataDir,
		(*[32]C.uint8_t)(proverIDCBytes),
		cSealedSectorDir,
		cStagedSectorDir,
		cSectorCacheRootDir,
		C.uint8_t(maxNumOpenStagedSectors),
		C.uint8_t(numWorkerThreads),
	)
	defer C.sector_builder_ffi_destroy_init_sector_builder_response(resPtr)

	if resPtr.status_code != 0 {
		return nil, errors.New(C.GoString(resPtr.error_msg))
	}

	return unsafe.Pointer(resPtr.sector_builder), nil
}

// DestroySectorBuilder deallocates the sector builder associated with the
// provided pointer. This function will panic if the provided pointer is null
// or if the sector builder has been previously deallocated.
func DestroySectorBuilder(sectorBuilderPtr unsafe.Pointer) {
	defer elapsed("DestroySectorBuilder")()

	C.sector_builder_ffi_destroy_sector_builder((*C.sector_builder_ffi_SectorBuilder)(sectorBuilderPtr))
}

// AddPiece writes the given piece into an unsealed sector and returns the id of that sector.
func AddPiece(
	sectorBuilderPtr unsafe.Pointer,
	pieceKey string,
	pieceBytes uint64,
	piecePath string,
) (uint64, error) {
	defer elapsed("AddPiece")()

	pieceFile, err := os.Open(piecePath)
	if err != nil {
		return 0, err
	}

	return AddPieceFromFile(sectorBuilderPtr, pieceKey, pieceBytes, pieceFile)
}

// AddPieceFromFile writes the given piece into an unsealed sector and returns the id of that sector.
func AddPieceFromFile(
	sectorBuilderPtr unsafe.Pointer,
	pieceKey string,
	pieceBytes uint64,
	pieceFile *os.File,
) (sectorID uint64, retErr error) {
	defer elapsed("AddPieceFromFile")()

	cPieceKey := C.CString(pieceKey)
	defer C.free(unsafe.Pointer(cPieceKey))

	pieceFd := pieceFile.Fd()

	// TODO: The UTC time, in seconds, at which the sector builder can safely
	// delete the piece. This allows for co-location of pieces with similar time
	// constraints, and allows the sector builder to remove sectors containing
	// pieces whose deals have expired.
	//
	// This value is currently ignored by the sector builder.
	//
	// https://github.com/filecoin-project/rust-fil-sector-builder/issues/32
	pieceExpiryUtcSeconds := 0

	resPtr := C.sector_builder_ffi_add_piece(
		(*C.sector_builder_ffi_SectorBuilder)(sectorBuilderPtr),
		cPieceKey,
		C.int(pieceFd),
		C.uint64_t(pieceBytes),
		C.uint64_t(pieceExpiryUtcSeconds),
	)
	defer C.sector_builder_ffi_destroy_add_piece_response(resPtr)

	// Make sure our filedescriptor stays alive, stayin alive
	runtime.KeepAlive(pieceFile)

	if resPtr.status_code != 0 {
		return 0, errors.New(C.GoString(resPtr.error_msg))
	}

	return uint64(resPtr.sector_id), nil
}

// ReadPieceFromSealedSector produces a byte buffer containing the piece
// associated with the provided key. If the key is not associated with any piece
// yet sealed into a sector, an error will be returned.
func ReadPieceFromSealedSector(sectorBuilderPtr unsafe.Pointer, pieceKey string) ([]byte, error) {
	defer elapsed("ReadPieceFromSealedSector")()

	cPieceKey := C.CString(pieceKey)
	defer C.free(unsafe.Pointer(cPieceKey))

	resPtr := C.sector_builder_ffi_read_piece_from_sealed_sector(
		(*C.sector_builder_ffi_SectorBuilder)(sectorBuilderPtr),
		cPieceKey,
	)
	defer C.sector_builder_ffi_destroy_read_piece_from_sealed_sector_response(resPtr)

	if resPtr.status_code != 0 {
		return nil, errors.New(C.GoString(resPtr.error_msg))
	}

	return goBytes(resPtr.data_ptr, resPtr.data_len), nil
}

// SealPreCommit pre-commits the sector with the provided id to the ticket,
// blocking until completion. If no staged sector with the provided id exists in
// the FullyPacked or AcceptingPieces state, an error will be returned.
func SealPreCommit(sectorBuilderPtr unsafe.Pointer, sectorID uint64, ticket SealTicket) (SealPreCommitOutput, error) {
	defer elapsed("SealPreCommit")()

	cTicketBytes := C.CBytes(ticket.TicketBytes[:])
	defer C.free(cTicketBytes)

	cSealTicket := C.sector_builder_ffi_FFISealTicket{
		block_height: C.uint64_t(ticket.BlockHeight),
		ticket_bytes: *(*[32]C.uint8_t)(cTicketBytes),
	}

	resPtr := C.sector_builder_ffi_seal_pre_commit((*C.sector_builder_ffi_SectorBuilder)(sectorBuilderPtr), C.uint64_t(sectorID), cSealTicket)
	defer C.sector_builder_ffi_destroy_seal_pre_commit_response(resPtr)

	if resPtr.status_code != 0 {
		return SealPreCommitOutput{}, errors.New(C.GoString(resPtr.error_msg))
	}

	out, err := goSealPreCommitOutput(resPtr)
	if err != nil {
		return SealPreCommitOutput{}, err
	}

	return out, nil
}

// ResumeSealPreCommit resumes the pre-commit operation for a sector with the
// provided id. If no sector exists with the given id that is in the
// PreCommittingPaused state, an error will be returned.
func ResumeSealPreCommit(sectorBuilderPtr unsafe.Pointer, sectorID uint64) (SealPreCommitOutput, error) {
	defer elapsed("ResumeSealPreCommit")()

	resPtr := C.sector_builder_ffi_resume_seal_pre_commit((*C.sector_builder_ffi_SectorBuilder)(sectorBuilderPtr), C.uint64_t(sectorID))
	defer C.sector_builder_ffi_destroy_resume_seal_pre_commit_response(resPtr)

	if resPtr.status_code != 0 {
		return SealPreCommitOutput{}, errors.New(C.GoString(resPtr.error_msg))
	}

	out, err := goResumeSealPreCommitOutput(resPtr)
	if err != nil {
		return SealPreCommitOutput{}, err
	}

	return out, nil
}

// SealCommit commits the sector with the provided id to the seed, blocking
// until completion. If no staged sector exists in the PreCommitted state with
// such an id, an error will be returned.
func SealCommit(sectorBuilderPtr unsafe.Pointer, sectorID uint64, seed SealSeed) (SealCommitOutput, error) {
	defer elapsed("SealCommit")()

	cSeedBytes := C.CBytes(seed.TicketBytes[:])
	defer C.free(cSeedBytes)

	cSealSeed := C.sector_builder_ffi_FFISealSeed{
		block_height: C.uint64_t(seed.BlockHeight),
		ticket_bytes: *(*[32]C.uint8_t)(cSeedBytes),
	}

	resPtr := C.sector_builder_ffi_seal_commit((*C.sector_builder_ffi_SectorBuilder)(sectorBuilderPtr), C.uint64_t(sectorID), cSealSeed)
	defer C.sector_builder_ffi_destroy_seal_commit_response(resPtr)

	if resPtr.status_code != 0 {
		return SealCommitOutput{}, errors.New(C.GoString(resPtr.error_msg))
	}

	out, err := goSealCommitOutput(resPtr)
	if err != nil {
		return SealCommitOutput{}, err
	}

	return out, nil
}

// ResumeSealCommit resumes sector commit (the second stage of Interactive
// PoRep) for a sector in the CommittingPaused state. If no staged sector exists
// in such a state, an error will be returned.
func ResumeSealCommit(sectorBuilderPtr unsafe.Pointer, sectorID uint64) (SealCommitOutput, error) {
	defer elapsed("ResumeSealCommit")()

	resPtr := C.sector_builder_ffi_resume_seal_commit((*C.sector_builder_ffi_SectorBuilder)(sectorBuilderPtr), C.uint64_t(sectorID))
	defer C.sector_builder_ffi_destroy_resume_seal_commit_response(resPtr)

	if resPtr.status_code != 0 {
		return SealCommitOutput{}, errors.New(C.GoString(resPtr.error_msg))
	}

	out, err := goResumeSealCommitOutput(resPtr)
	if err != nil {
		return SealCommitOutput{}, err
	}

	return out, nil
}

// GetAllStagedSectors returns a slice of all staged sector metadata for the sector builder.
func GetAllStagedSectors(sectorBuilderPtr unsafe.Pointer) ([]StagedSectorMetadata, error) {
	defer elapsed("GetAllStagedSectors")()

	resPtr := C.sector_builder_ffi_get_staged_sectors((*C.sector_builder_ffi_SectorBuilder)(sectorBuilderPtr))
	defer C.sector_builder_ffi_destroy_get_staged_sectors_response(resPtr)

	if resPtr.status_code != 0 {
		return nil, errors.New(C.GoString(resPtr.error_msg))
	}

	meta, err := goStagedSectorMetadata(resPtr.sectors_ptr, resPtr.sectors_len)
	if err != nil {
		return nil, err
	}

	return meta, nil
}

// GetAllSealedSectors returns a slice of all sealed sector metadata, excluding
// sector health.
func GetAllSealedSectors(sectorBuilderPtr unsafe.Pointer) ([]SealedSectorMetadata, error) {
	defer elapsed("GetAllSealedSectors")()

	return getAllSealedSectors(sectorBuilderPtr, false)
}

// GetAllSealedSectorsWithHealth returns a slice of all sealed sector metadata
// for the sector builder, including sector health info (which can be expensive
// to compute).
func GetAllSealedSectorsWithHealth(sectorBuilderPtr unsafe.Pointer) ([]SealedSectorMetadata, error) {
	defer elapsed("GetAllSealedSectorsWithHealth")()

	return getAllSealedSectors(sectorBuilderPtr, true)
}

// GetSectorSealingStatusByID produces sector sealing status (staged, sealing in
// progress, sealed, failed) for the provided sector id. If no sector
// corresponding to the provided id exists, this function returns an error.
func GetSectorSealingStatusByID(sectorBuilderPtr unsafe.Pointer, sectorID uint64) (SectorSealingStatus, error) {
	defer elapsed("GetSectorSealingStatusByID")()

	resPtr := C.sector_builder_ffi_get_seal_status(
		(*C.sector_builder_ffi_SectorBuilder)(sectorBuilderPtr),
		C.uint64_t(sectorID),
	)
	defer C.sector_builder_ffi_destroy_get_seal_status_response(resPtr)

	if resPtr.status_code != 0 {
		return SectorSealingStatus{}, errors.New(C.GoString(resPtr.error_msg))
	}

	if resPtr.seal_status_code == C.Failed {
		return SectorSealingStatus{SectorID: sectorID, State: sealing_state.Failed, SealErrorMsg: C.GoString(resPtr.seal_error_msg)}, nil
	} else if resPtr.seal_status_code == C.AcceptingPieces {
		return SectorSealingStatus{SectorID: sectorID, State: sealing_state.AcceptingPieces}, nil
	} else if resPtr.seal_status_code == C.Committing {
		return SectorSealingStatus{SectorID: sectorID, State: sealing_state.Committing}, nil
	} else if resPtr.seal_status_code == C.CommittingPaused {
		return SectorSealingStatus{SectorID: sectorID, State: sealing_state.CommittingPaused}, nil
	} else if resPtr.seal_status_code == C.FullyPacked {
		return SectorSealingStatus{SectorID: sectorID, State: sealing_state.FullyPacked}, nil
	} else if resPtr.seal_status_code == C.PreCommitted {
		return SectorSealingStatus{SectorID: sectorID, State: sealing_state.PreCommitted}, nil
	} else if resPtr.seal_status_code == C.PreCommitting {
		return SectorSealingStatus{SectorID: sectorID, State: sealing_state.PreCommitting}, nil
	} else if resPtr.seal_status_code == C.PreCommittingPaused {
		return SectorSealingStatus{SectorID: sectorID, State: sealing_state.PreCommittingPaused}, nil
	} else if resPtr.seal_status_code == C.Committed {
		commRSlice := goBytes(&resPtr.comm_r[0], CommitmentBytesLen)
		var commR [CommitmentBytesLen]byte
		copy(commR[:], commRSlice)

		commDSlice := goBytes(&resPtr.comm_d[0], CommitmentBytesLen)
		var commD [CommitmentBytesLen]byte
		copy(commD[:], commDSlice)

		proof := goBytes(resPtr.proof_ptr, resPtr.proof_len)

		ps, err := goPieceMetadata(resPtr.pieces_ptr, resPtr.pieces_len)
		if err != nil {
			return SectorSealingStatus{}, errors.Wrap(err, "failed to marshal from string to cid")
		}

		return SectorSealingStatus{
			SectorID: sectorID,
			State:    sealing_state.Committed,
			CommD:    commD,
			CommR:    commR,
			Proof:    proof,
			Pieces:   ps,
			Ticket:   goSealTicket(resPtr.seal_ticket),
			Seed:     goSealSeed(resPtr.seal_seed),
		}, nil
	} else {
		// unknown
		return SectorSealingStatus{}, errors.New("unexpected seal status")
	}
}

// GeneratePoSt produces a proof-of-spacetime for the provided replica commitments.
func GeneratePoSt(
	sectorBuilderPtr unsafe.Pointer,
	sectorInfo SortedSectorInfo,
	challengeSeed [CommitmentBytesLen]byte,
	faults []uint64,
) ([]byte, error) {
	defer elapsed("GeneratePoSt")()

	// CommRs and sector ids must be provided to C.verify_post in the same order
	// that they were provided to the C.generate_post
	sortedCommRs := make([][CommitmentBytesLen]byte, len(sectorInfo.Values()))
	for idx, v := range sectorInfo.Values() {
		sortedCommRs[idx] = v.CommR
	}

	// flattening the byte slice makes it easier to copy into the C heap
	flattened := make([]byte, CommitmentBytesLen*len(sortedCommRs))
	for idx, commR := range sortedCommRs {
		copy(flattened[(CommitmentBytesLen*idx):(CommitmentBytesLen*(1+idx))], commR[:])
	}

	// copy the Go byte slice into C memory
	cflattened := C.CBytes(flattened)
	defer C.free(cflattened)

	challengeSeedPtr := unsafe.Pointer(&(challengeSeed)[0])

	faultsPtr, faultsSize := cUint64s(faults)
	defer C.free(unsafe.Pointer(faultsPtr))

	// a mutable pointer to a GeneratePoStResponse C-struct
	resPtr := C.sector_builder_ffi_generate_post(
		(*C.sector_builder_ffi_SectorBuilder)(sectorBuilderPtr),
		(*C.uint8_t)(cflattened),
		C.size_t(len(flattened)),
		(*[CommitmentBytesLen]C.uint8_t)(challengeSeedPtr),
		faultsPtr,
		faultsSize,
	)
	defer C.sector_builder_ffi_destroy_generate_post_response(resPtr)

	if resPtr.status_code != 0 {
		return nil, errors.New(C.GoString(resPtr.error_msg))
	}

	return goBytes(resPtr.proof_ptr, resPtr.proof_len), nil
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

// GeneratePieceCommitmentFromFile produces a piece commitment for the provided data
// stored in a given file.
func GeneratePieceCommitmentFromFile(pieceFile *os.File, pieceSize uint64) (commP [CommitmentBytesLen]byte, err error) {
	pieceFd := pieceFile.Fd()

	resPtr := C.sector_builder_ffi_generate_piece_commitment(C.int(pieceFd), C.uint64_t(pieceSize))
	defer C.sector_builder_ffi_destroy_generate_piece_commitment_response(resPtr)

	// Make sure our filedescriptor stays alive, stayin alive
	runtime.KeepAlive(pieceFile)

	if resPtr.status_code != 0 {
		return [CommitmentBytesLen]byte{}, errors.New(C.GoString(resPtr.error_msg))
	}

	commPSlice := goBytes(&resPtr.comm_p[0], CommitmentBytesLen)
	var commitment [CommitmentBytesLen]byte
	copy(commitment[:], commPSlice)

	return commitment, nil
}

func getAllSealedSectors(sectorBuilderPtr unsafe.Pointer, performHealthchecks bool) ([]SealedSectorMetadata, error) {
	resPtr := C.sector_builder_ffi_get_sealed_sectors((*C.sector_builder_ffi_SectorBuilder)(sectorBuilderPtr), C.bool(performHealthchecks))
	defer C.sector_builder_ffi_destroy_get_sealed_sectors_response(resPtr)

	if resPtr.status_code != 0 {
		return nil, errors.New(C.GoString(resPtr.error_msg))
	}

	meta, err := goSealedSectorMetadata(resPtr.meta_ptr, resPtr.meta_len)
	if err != nil {
		return nil, err
	}

	return meta, nil
}
