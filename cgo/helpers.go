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

func AsByteArray32(goSlice []byte) ByteArray32 {
	var ary ByteArray32
	for idx := range goSlice[:32] {
		ary.idx[idx] = C.uchar(goSlice[idx])
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

func NewPrivateReplicaInfo(pp RegisteredPoStProof, cacheDirPath SliceBoxedUint8, commR ByteArray32, replicaPath SliceBoxedUint8, sectorId uint64) PrivateReplicaInfo {
	return PrivateReplicaInfo{
		registered_proof: pp,
		cache_dir_path:   cacheDirPath,
		replica_path:     replicaPath,
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

func NewPoStProof(pp RegisteredPoStProof, proof SliceBoxedUint8) PoStProof {
	return PoStProof{
		registered_proof: pp,
		proof:            proof,
	}
}

func NewPublicPieceInfo(numBytes uint64, commP ByteArray32) PublicPieceInfo {
	return PublicPieceInfo{
		num_bytes: C.uint64_t(numBytes),
		comm_p:    commP,
	}
}
