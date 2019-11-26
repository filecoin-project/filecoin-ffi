package ffi

import (
	"unsafe"
)

// #cgo LDFLAGS: ${SRCDIR}/libfilecoin.a
// #cgo pkg-config: ${SRCDIR}/filecoin.pc
// #include "./filecoin.h"
import "C"

// SingleProofPartitionProofLen denotes the number of bytes in a proof generated
// with a single partition. The number of bytes in a proof increases linearly
// with the number of partitions used when creating that proof.
const SingleProofPartitionProofLen = 192

func cPublicPieceInfo(src []PublicPieceInfo) (*C.FFIPublicPieceInfo, C.size_t) {
	srcCSizeT := C.size_t(len(src))

	// allocate array in C heap
	cPublicPieceInfos := C.malloc(srcCSizeT * C.sizeof_FFIPublicPieceInfo)

	// create a Go slice backed by the C-array
	xs := (*[1 << 30]C.FFIPublicPieceInfo)(cPublicPieceInfos)
	for i, v := range src {
		xs[i] = C.FFIPublicPieceInfo{
			num_bytes: C.uint64_t(v.Size),
			comm_p:    *(*[32]C.uint8_t)(unsafe.Pointer(&v.CommP)),
		}
	}

	return (*C.FFIPublicPieceInfo)(cPublicPieceInfos), srcCSizeT
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

func cSectorClass(sectorSize uint64, poRepProofPartitions uint8) C.FFISectorClass {
	return C.FFISectorClass{
		sector_size:            C.uint64_t(sectorSize),
		porep_proof_partitions: C.uint8_t(poRepProofPartitions),
	}
}

func cSealPreCommitOutput(src RawSealPreCommitOutput) C.FFISealPreCommitOutput {
	return C.FFISealPreCommitOutput{
		comm_d:            *(*[32]C.uint8_t)(unsafe.Pointer(&src.CommD)),
		comm_r:            *(*[32]C.uint8_t)(unsafe.Pointer(&src.CommR)),
		p_aux_comm_c:      *(*[32]C.uint8_t)(unsafe.Pointer(&src.CommC)),
		p_aux_comm_r_last: *(*[32]C.uint8_t)(unsafe.Pointer(&src.CommRLast)),
	}
}

func cCandidates(src []Candidate) (*C.FFICandidate, C.size_t) {
	srcCSizeT := C.size_t(len(src))

	// allocate array in C heap
	cCandidates := C.malloc(srcCSizeT * C.sizeof_FFICandidate)

	// create a Go slice backed by the C-array
	pp := (*[1 << 30]C.FFICandidate)(cCandidates)
	for i, v := range src {
		pp[i] = C.FFICandidate{
			sector_id:              C.uint64_t(v.SectorID),
			partial_ticket:         *(*[32]C.uint8_t)(unsafe.Pointer(&v.PartialTicket)),
			ticket:                 *(*[32]C.uint8_t)(unsafe.Pointer(&v.Ticket)),
			sector_challenge_index: C.uint64_t(v.SectorChallengeIndex),
		}
	}

	return (*C.FFICandidate)(cCandidates), srcCSizeT
}

func cPrivateReplicaInfos(src []SectorPrivateInfo) (*C.FFIPrivateReplicaInfo, C.size_t) {
	srcCSizeT := C.size_t(len(src))

	cPrivateReplicas := C.malloc(srcCSizeT * C.sizeof_FFIPrivateReplicaInfo)

	pp := (*[1 << 30]C.FFIPrivateReplicaInfo)(cPrivateReplicas)
	for i, v := range src {
		pp[i] = C.FFIPrivateReplicaInfo{
			cache_dir_path: C.CString(v.CacheDirPath),
			comm_r:         *(*[32]C.uint8_t)(unsafe.Pointer(&v.CommR)),
			replica_path:   C.CString(v.SealedSectorPath),
			sector_id:      C.uint64_t(v.SectorID),
		}
	}

	return (*C.FFIPrivateReplicaInfo)(cPrivateReplicas), srcCSizeT
}

func goBytes(src *C.uint8_t, size C.size_t) []byte {
	return C.GoBytes(unsafe.Pointer(src), C.int(size))
}

func goCandidates(src *C.FFICandidate, size C.size_t) ([]Candidate, error) {
	candidates := make([]Candidate, size)
	if src == nil || size == 0 {
		return candidates, nil
	}

	ptrs := (*[1 << 30]C.FFICandidate)(unsafe.Pointer(src))[:size:size]
	for i := 0; i < int(size); i++ {
		candidates[i] = goCandidate(ptrs[i])
	}

	return candidates, nil
}

func goCandidate(src C.FFICandidate) Candidate {
	return Candidate{
		SectorID:             uint64(src.sector_id),
		PartialTicket:        goCommitment(&src.partial_ticket[0]),
		Ticket:               goCommitment(&src.ticket[0]),
		SectorChallengeIndex: uint64(src.sector_challenge_index),
	}
}

func goRawSealPreCommitOutput(src C.FFISealPreCommitOutput) RawSealPreCommitOutput {
	return RawSealPreCommitOutput{
		CommD:     goCommitment(&src.comm_d[0]),
		CommR:     goCommitment(&src.comm_r[0]),
		CommRLast: goCommitment(&src.p_aux_comm_r_last[0]),
		CommC:     goCommitment(&src.p_aux_comm_c[0]),
	}
}

func goCommitment(src *C.uint8_t) [32]byte {
	slice := C.GoBytes(unsafe.Pointer(src), 32)
	var array [CommitmentBytesLen]byte
	copy(array[:], slice)

	return array
}
