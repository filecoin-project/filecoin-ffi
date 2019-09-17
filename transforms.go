package go_sectorbuilder

import (
	"unsafe"

	"github.com/filecoin-project/go-sectorbuilder/sealed_sector_health"

	"github.com/pkg/errors"
)

// #cgo LDFLAGS: ${SRCDIR}/libsector_builder_ffi.a
// #cgo pkg-config: ${SRCDIR}/sector_builder_ffi.pc
// #include "./sector_builder_ffi.h"
import "C"

// SingleProofPartitionProofLen denotes the number of bytes in a proof generated
// with a single partition. The number of bytes in a proof increases linearly
// with the number of partitions used when creating that proof.
const SingleProofPartitionProofLen = 192

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

func cSectorClass(sectorSize uint64, poRepProofPartitions uint8) (C.sector_builder_ffi_FFISectorClass, error) {
	return C.sector_builder_ffi_FFISectorClass{
		sector_size:            C.uint64_t(sectorSize),
		porep_proof_partitions: C.uint8_t(poRepProofPartitions),
	}, nil
}

func goBytes(src *C.uint8_t, size C.size_t) []byte {
	return C.GoBytes(unsafe.Pointer(src), C.int(size))
}

func goStagedSectorMetadata(src *C.sector_builder_ffi_FFIStagedSectorMetadata, size C.size_t) ([]StagedSectorMetadata, error) {
	sectors := make([]StagedSectorMetadata, size)
	if src == nil || size == 0 {
		return sectors, nil
	}

	sectorPtrs := (*[1 << 30]C.sector_builder_ffi_FFIStagedSectorMetadata)(unsafe.Pointer(src))[:size:size]
	for i := 0; i < int(size); i++ {
		sectors[i] = StagedSectorMetadata{
			SectorID: uint64(sectorPtrs[i].sector_id),
		}
	}

	return sectors, nil
}

func goSealedSectorMetadata(src *C.sector_builder_ffi_FFISealedSectorMetadata, size C.size_t) ([]SealedSectorMetadata, error) {
	sectors := make([]SealedSectorMetadata, size)
	if src == nil || size == 0 {
		return sectors, nil
	}

	ptrs := (*[1 << 30]C.sector_builder_ffi_FFISealedSectorMetadata)(unsafe.Pointer(src))[:size:size]
	for i := 0; i < int(size); i++ {
		commDSlice := goBytes(&ptrs[i].comm_d[0], CommitmentBytesLen)
		var commD [CommitmentBytesLen]byte
		copy(commD[:], commDSlice)

		commRSlice := goBytes(&ptrs[i].comm_r[0], CommitmentBytesLen)
		var commR [CommitmentBytesLen]byte
		copy(commR[:], commRSlice)

		commRStarSlice := goBytes(&ptrs[i].comm_r_star[0], CommitmentBytesLen)
		var commRStar [CommitmentBytesLen]byte
		copy(commRStar[:], commRStarSlice)

		proof := goBytes(ptrs[i].proofs_ptr, ptrs[i].proofs_len)

		pieces, err := goPieceMetadata(ptrs[i].pieces_ptr, ptrs[i].pieces_len)
		if err != nil {
			return []SealedSectorMetadata{}, errors.Wrap(err, "failed to marshal piece metadata")
		}

		health, err := goSealedSectorHealth(ptrs[i].health)
		if err != nil {
			return []SealedSectorMetadata{}, errors.Wrap(err, "failed to marshal sealed sector health")
		}

		sectors[i] = SealedSectorMetadata{
			SectorID:  uint64(ptrs[i].sector_id),
			CommD:     commD,
			CommR:     commR,
			CommRStar: commRStar,
			Proof:     proof,
			Pieces:    pieces,
			Health:    health,
		}
	}

	return sectors, nil
}

func goPieceMetadata(src *C.sector_builder_ffi_FFIPieceMetadata, size C.size_t) ([]PieceMetadata, error) {
	ps := make([]PieceMetadata, size)
	if src == nil || size == 0 {
		return ps, nil
	}

	ptrs := (*[1 << 30]C.sector_builder_ffi_FFIPieceMetadata)(unsafe.Pointer(src))[:size:size]
	for i := 0; i < int(size); i++ {
		commPSlice := goBytes(&ptrs[i].comm_p[0], CommitmentBytesLen)
		var commP [CommitmentBytesLen]byte
		copy(commP[:], commPSlice)

		ps[i] = PieceMetadata{
			Key:            C.GoString(ptrs[i].piece_key),
			Size:           uint64(ptrs[i].num_bytes),
			CommP:          commP,
			InclusionProof: goBytes(ptrs[i].piece_inclusion_proof_ptr, ptrs[i].piece_inclusion_proof_len),
		}
	}

	return ps, nil
}

func goSealedSectorHealth(health C.sector_builder_ffi_FFISealedSectorHealth) (sealed_sector_health.Health, error) {
	switch health {
	case C.Unknown:
		return sealed_sector_health.Unknown, nil
	case C.Ok:
		return sealed_sector_health.Ok, nil
	case C.ErrorInvalidChecksum:
		return sealed_sector_health.InvalidChecksum, nil
	case C.ErrorInvalidLength:
		return sealed_sector_health.InvalidLength, nil
	case C.ErrorMissing:
		return sealed_sector_health.Missing, nil
	default:
		return sealed_sector_health.Unknown, errors.Errorf("unhandled sealed sector health: %v", health)
	}
}
