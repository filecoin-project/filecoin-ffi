package cgo

/*
#cgo LDFLAGS: -L${SRCDIR}/..
#cgo pkg-config: ${SRCDIR}/../filcrypto.pc
#include "../filcrypto.h"
#include <stdlib.h>
*/
import "C"
import (
	"errors"
	"unsafe"
)

var (
	emptyUint8              C.uint8_t              = 0
	emptyUint64             C.uint64_t             = 0
	emptyUint               C.size_t               = 0
	emptyAggregationInputs  C.AggregationInputs_t  = C.AggregationInputs_t{}
	emptyPublicReplicaInfo  C.PublicReplicaInfo_t  = C.PublicReplicaInfo_t{}
	emptyPrivateReplicaInfo C.PrivateReplicaInfo_t = C.PrivateReplicaInfo_t{}
	emptyPoStProof          C.PoStProof_t          = C.PoStProof_t{}
	emptyPublicPieceInfo    C.PublicPieceInfo_t    = C.PublicPieceInfo_t{}
	emptyByteArray32        C.uint8_32_array_t     = C.uint8_32_array_t{}
	emptySliceBoxedUint8    C.slice_boxed_uint8_t  = C.slice_boxed_uint8_t{}
)

func AsSliceRefUint8(goBytes []byte) SliceRefUint8 {
	len := len(goBytes)

	if len == 0 {
		// can't take element 0 of an empty slice
		return SliceRefUint8{
			ptr: &emptyUint8,
			len: C.size_t(len),
		}
	}
	return SliceRefUint8{
		ptr: (*C.uint8_t)(unsafe.Pointer(&goBytes[0])),
		len: C.size_t(len),
	}
}

func AsSliceRefUint64(goBytes []uint64) SliceRefUint64 {
	len := len(goBytes)

	if len == 0 {
		// can't take element 0 of an empty slice
		return SliceRefUint64{
			ptr: &emptyUint64,
			len: C.size_t(len),
		}
	}
	return SliceRefUint64{
		ptr: (*C.uint64_t)(unsafe.Pointer(&goBytes[0])),
		len: C.size_t(len),
	}
}

func AllocSliceBoxedUint8(goBytes []byte) SliceBoxedUint8 {
	len := len(goBytes)

	ptr := C.alloc_boxed_slice(C.size_t(len))
	copy(ptr.slice(), goBytes)

	return ptr
}

func AsSliceRefUint(goSlice []uint) SliceRefUint {
	len := len(goSlice)

	if len == 0 {
		// can't take element 0 of an empty slice
		return SliceRefUint{
			ptr: &emptyUint,
			len: C.size_t(len),
		}
	}

	return SliceRefUint{
		ptr: (*C.size_t)(unsafe.Pointer(&goSlice[0])),
		len: C.size_t(len),
	}
}

func AsSliceRefAggregationInputs(goSlice []AggregationInputs) SliceRefAggregationInputs {
	len := len(goSlice)

	if len == 0 {
		// can't take element 0 of an empty slice
		return SliceRefAggregationInputs{
			ptr: &emptyAggregationInputs,
			len: C.size_t(len),
		}
	}

	return SliceRefAggregationInputs{
		ptr: (*C.AggregationInputs_t)(unsafe.Pointer(&goSlice[0])),
		len: C.size_t(len),
	}
}

func AsSliceRefPublicReplicaInfo(goSlice []PublicReplicaInfo) SliceRefPublicReplicaInfo {
	len := len(goSlice)

	if len == 0 {
		// can't take element 0 of an empty slice
		return SliceRefPublicReplicaInfo{
			ptr: &emptyPublicReplicaInfo,
			len: C.size_t(len),
		}
	}

	return SliceRefPublicReplicaInfo{
		ptr: (*C.PublicReplicaInfo_t)(unsafe.Pointer(&goSlice[0])),
		len: C.size_t(len),
	}
}

func AsSliceRefPrivateReplicaInfo(goSlice []PrivateReplicaInfo) SliceRefPrivateReplicaInfo {
	len := len(goSlice)

	if len == 0 {
		// can't take element 0 of an empty slice
		return SliceRefPrivateReplicaInfo{
			ptr: &emptyPrivateReplicaInfo,
			len: C.size_t(len),
		}
	}

	return SliceRefPrivateReplicaInfo{
		ptr: (*C.PrivateReplicaInfo_t)(unsafe.Pointer(&goSlice[0])),
		len: C.size_t(len),
	}
}

func AsSliceRefPoStProof(goSlice []PoStProof) SliceRefPoStProof {
	len := len(goSlice)

	if len == 0 {
		// can't take element 0 of an empty slice
		return SliceRefPoStProof{
			ptr: &emptyPoStProof,
			len: C.size_t(len),
		}
	}

	return SliceRefPoStProof{
		ptr: (*C.PoStProof_t)(unsafe.Pointer(&goSlice[0])),
		len: C.size_t(len),
	}
}

func AsSliceRefPublicPieceInfo(goSlice []PublicPieceInfo) SliceRefPublicPieceInfo {
	len := len(goSlice)

	if len == 0 {
		// can't take element 0 of an empty slice
		return SliceRefPublicPieceInfo{
			ptr: &emptyPublicPieceInfo,
			len: C.size_t(len),
		}
	}

	return SliceRefPublicPieceInfo{
		ptr: (*C.PublicPieceInfo_t)(unsafe.Pointer(&goSlice[0])),
		len: C.size_t(len),
	}
}

func AsSliceRefByteArray32(goSlice []ByteArray32) SliceRefByteArray32 {
	len := len(goSlice)

	if len == 0 {
		// can't take element 0 of an empty slice
		return SliceRefByteArray32{
			ptr: &emptyByteArray32,
			len: C.size_t(len),
		}
	}

	return SliceRefByteArray32{
		ptr: (*C.uint8_32_array_t)(unsafe.Pointer(&goSlice[0])),
		len: C.size_t(len),
	}
}

func AsSliceRefSliceBoxedUint8(goSlice []SliceBoxedUint8) SliceRefSliceBoxedUint8 {
	len := len(goSlice)

	if len == 0 {
		// can't take element 0 of an empty slice
		return SliceRefSliceBoxedUint8{
			ptr: &emptySliceBoxedUint8,
			len: C.size_t(len),
		}
	}

	return SliceRefSliceBoxedUint8{
		ptr: (*C.slice_boxed_uint8_t)(unsafe.Pointer(&goSlice[0])),
		len: C.size_t(len),
	}
}

func AsByteArray32(goSlice []byte) ByteArray32 {
	var ary ByteArray32
	l := len(goSlice)
	for idx := range goSlice {
		if idx < l {
			ary.idx[idx] = C.uchar(goSlice[idx])
		}
	}
	return ary
}

// CheckErr returns `nil` if the `code` indicates success and an error otherwise.
func CheckErr(resp result) error {
	if resp == nil {
		return errors.New("nil result from Filecoin FFI")
	}
	if resp.statusCode() == FCPResponseStatusNoError {
		return nil
	}

	return errors.New(string(resp.errorMsg().slice()))
}

func NewAggregationInputs(commR ByteArray32, commD ByteArray32, sectorId uint64, ticket ByteArray32, seed ByteArray32) AggregationInputs {
	return AggregationInputs{
		comm_r:    commR,
		comm_d:    commD,
		sector_id: C.uint64_t(sectorId),
		ticket:    ticket,
		seed:      seed,
	}
}

func NewPrivateReplicaInfo(pp RegisteredPoStProof, cacheDirPath string, commR ByteArray32, replicaPath string, sectorId uint64) PrivateReplicaInfo {
	return PrivateReplicaInfo{
		registered_proof: pp,
		cache_dir_path:   AllocSliceBoxedUint8([]byte(cacheDirPath)),
		replica_path:     AllocSliceBoxedUint8([]byte(replicaPath)),
		sector_id:        C.uint64_t(sectorId),
		comm_r:           commR,
	}
}

func NewPublicReplicaInfo(pp RegisteredPoStProof, commR ByteArray32, sectorId uint64) PublicReplicaInfo {
	return PublicReplicaInfo{
		registered_proof: pp,
		sector_id:        C.uint64_t(sectorId),
		comm_r:           commR,
	}
}

func NewPoStProof(pp RegisteredPoStProof, proof []byte) PoStProof {
	return PoStProof{
		registered_proof: pp,
		proof:            AllocSliceBoxedUint8(proof),
	}
}

func NewPublicPieceInfo(numBytes uint64, commP ByteArray32) PublicPieceInfo {
	return PublicPieceInfo{
		num_bytes: C.uint64_t(numBytes),
		comm_p:    commP,
	}
}

func NewPartitionSnarkProof(pp RegisteredPoStProof, proof []byte) PartitionSnarkProof {
	return PartitionSnarkProof{
		registered_proof: pp,
		proof:            AllocSliceBoxedUint8(proof),
	}
}
