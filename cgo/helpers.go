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

func AsSliceRefUint8(goBytes []byte) SliceRefUint8 {
	len := len(goBytes)

	if len == 0 {
		// can't take element 0 of an empty slice
		return SliceRefUint8{
			ptr: (*C.uint8_t)(unsafe.Pointer(&goBytes)),
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
			ptr: (*C.uint64_t)(unsafe.Pointer(&goBytes)),
			len: C.size_t(len),
		}
	}
	return SliceRefUint64{
		ptr: (*C.uint64_t)(unsafe.Pointer(&goBytes[0])),
		len: C.size_t(len),
	}
}

func AllocSliceBoxedUint8(goBytes []byte) (SliceBoxedUint8, error) {
	len := len(goBytes)
	if len == 0 {
		return SliceBoxedUint8{}, errors.New("SlicedBoxedUint8 must not be empty")
	}

	ptr := C.alloc_boxed_slice(C.size_t(len))
	slice := ptr.Slice()
	for i := range slice {
		slice[i] = goBytes[i]
	}

	return ptr, nil
}

func AsSliceRefUint(goSlice []uint) SliceRefUint {
	len := len(goSlice)

	if len == 0 {
		// can't take element 0 of an empty slice
		return SliceRefUint{
			ptr: (*C.size_t)(unsafe.Pointer(&goSlice)),
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
			ptr: (*C.AggregationInputs_t)(unsafe.Pointer(&goSlice)),
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
			ptr: (*C.PublicReplicaInfo_t)(unsafe.Pointer(&goSlice)),
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
			ptr: (*C.PrivateReplicaInfo_t)(unsafe.Pointer(&goSlice)),
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
			ptr: (*C.PoStProof_t)(unsafe.Pointer(&goSlice)),
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
			ptr: (*C.PublicPieceInfo_t)(unsafe.Pointer(&goSlice)),
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
			ptr: (*C.uint8_32_array_t)(unsafe.Pointer(&goSlice)),
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
			ptr: (*C.slice_boxed_uint8_t)(unsafe.Pointer(&goSlice)),
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
		} else {
			ary.idx[idx] = 0
		}
	}
	return ary
}

/// CheckErr returns `nil` if the `code` indicates success and an error otherwise.
func CheckErr(resp Result) error {
	if resp == nil {
		return errors.New("failed")
	}
	if resp.StatusCode() == FCPResponseStatusNoError {
		return nil
	}

	return errors.New(string(resp.ErrorMsg().Slice()))
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

func NewPrivateReplicaInfo(pp RegisteredPoStProof, cacheDirPath string, commR ByteArray32, replicaPath string, sectorId uint64) (PrivateReplicaInfo, error) {
	cacheDirPathBytes, err := AllocSliceBoxedUint8([]byte(cacheDirPath))
	if err != nil {
		return PrivateReplicaInfo{}, err
	}
	replicaPathBytes, err := AllocSliceBoxedUint8([]byte(replicaPath))
	if err != nil {
		return PrivateReplicaInfo{}, err
	}

	return PrivateReplicaInfo{
		registered_proof: pp,
		cache_dir_path:   cacheDirPathBytes,
		replica_path:     replicaPathBytes,
		sector_id:        C.uint64_t(sectorId),
		comm_r:           commR,
	}, nil
}

func NewPublicReplicaInfo(pp RegisteredPoStProof, commR ByteArray32, sectorId uint64) PublicReplicaInfo {
	return PublicReplicaInfo{
		registered_proof: pp,
		sector_id:        C.uint64_t(sectorId),
		comm_r:           commR,
	}
}

func NewPoStProof(pp RegisteredPoStProof, proof []byte) (PoStProof, error) {
	proofBytes, err := AllocSliceBoxedUint8(proof)
	if err != nil {
		return PoStProof{}, nil
	}
	return PoStProof{
		registered_proof: pp,
		proof:            proofBytes,
	}, nil
}

func NewPublicPieceInfo(numBytes uint64, commP ByteArray32) PublicPieceInfo {
	return PublicPieceInfo{
		num_bytes: C.uint64_t(numBytes),
		comm_p:    commP,
	}
}
