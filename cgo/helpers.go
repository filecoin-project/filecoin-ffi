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

func AsSliceBoxedUint8(goBytes []byte) (SliceBoxedUint8, error) {
	len := len(goBytes)

	if len == 0 {
		// must not be empty
		return SliceBoxedUint8{}, errors.New("SlicedBoxedUint8 must not be empty")
	}
	return SliceBoxedUint8{
		ptr: (*C.uint8_t)(unsafe.Pointer(&goBytes[0])),
		len: C.size_t(len),
	}, nil
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

func AsByteArray32(goSlice []byte) ByteArray32 {
	var ary ByteArray32
	for idx := range goSlice[:32] {
		ary.inner.idx[idx] = C.uchar(goSlice[idx])
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

func NewPrivateReplicaInfo(pp RegisteredPoStProof, cacheDirPath SliceBoxedUint8, commR []byte, replicaPath SliceBoxedUint8, sectorId uint64) PrivateReplicaInfo {
	var info PrivateReplicaInfo
	info.registered_proof = pp
	info.cache_dir_path = cacheDirPath
	info.replica_path = replicaPath
	info.sector_id = C.uint64_t(sectorId)

	for idx := range commR[:32] {
		info.comm_r.idx[idx] = C.uchar(commR[idx])
	}
	return info
}

func NewPublicReplicaInfo(pp RegisteredPoStProof, commR []byte, sectorId uint64) PublicReplicaInfo {
	var info PublicReplicaInfo
	info.registered_proof = pp
	info.sector_id = C.uint64_t(sectorId)

	for idx := range commR[:32] {
		info.comm_r.idx[idx] = C.uchar(commR[idx])
	}
	return info
}

func NewPoStProof(pp RegisteredPoStProof, proof SliceBoxedUint8) PoStProof {
	return PoStProof{
		registered_proof: pp,
		proof:            proof,
	}
}
