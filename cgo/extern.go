package cgo

/*
#include <stdint.h>
typedef const uint8_t* buf_t;
*/
import "C"
import (
	"unsafe"

	"github.com/filecoin-project/go-address"

	"github.com/filecoin-project/go-state-types/abi"
)

//export cgo_extern_get_chain_randomness
func cgo_extern_get_chain_randomness(
	handle C.uint64_t, round C.int64_t,
	output C.buf_t,
) (res C.int32_t) {
	defer func() {
		if rerr := recover(); rerr != nil {
			logPanic(rerr)
			res = ErrPanic
		}
	}()

	out := unsafe.Slice((*byte)(unsafe.Pointer(output)), 32)
	externs, ctx := Lookup(uint64(handle))
	if externs == nil {
		return ErrInvalidHandle
	}

	rand, err := externs.GetChainRandomness(ctx, abi.ChainEpoch(round))

	switch err {
	case nil:
		copy(out[:], rand[:])
		return 0
	default:
		return ErrIO
	}
}

//export cgo_extern_get_beacon_randomness
func cgo_extern_get_beacon_randomness(
	handle C.uint64_t, round C.int64_t,
	output C.buf_t,
) (res C.int32_t) {
	defer func() {
		if rerr := recover(); rerr != nil {
			logPanic(rerr)
			res = ErrPanic
		}
	}()

	out := unsafe.Slice((*byte)(unsafe.Pointer(output)), 32)
	externs, ctx := Lookup(uint64(handle))
	if externs == nil {
		return ErrInvalidHandle
	}

	rand, err := externs.GetBeaconRandomness(ctx, abi.ChainEpoch(round))

	switch err {
	case nil:
		copy(out[:], rand[:])
		return 0
	default:
		return ErrIO
	}
}

//export cgo_extern_verify_consensus_fault
func cgo_extern_verify_consensus_fault(
	handle C.uint64_t,
	h1 C.buf_t, h1Len C.int32_t,
	h2 C.buf_t, h2Len C.int32_t,
	extra C.buf_t, extraLen C.int32_t,
	minerIdOut *C.uint64_t,
	epochOut *C.int64_t,
	faultOut *C.int64_t,
	gasUsedOut *C.int64_t,
) (res C.int32_t) {
	defer func() {
		if rerr := recover(); rerr != nil {
			logPanic(rerr)
			res = ErrPanic
		}
	}()

	externs, ctx := Lookup(uint64(handle))
	if externs == nil {
		return ErrInvalidHandle
	}

	h1Go := C.GoBytes(unsafe.Pointer(h1), h1Len)
	h2Go := C.GoBytes(unsafe.Pointer(h2), h2Len)
	extraGo := C.GoBytes(unsafe.Pointer(extra), extraLen)

	faultRes, gas := externs.VerifyConsensusFault(ctx, h1Go, h2Go, extraGo)
	*gasUsedOut = C.int64_t(gas)
	*faultOut = C.int64_t(faultRes.Type)

	if faultRes.Type != ConsensusFaultNone {
		id, err := address.IDFromAddress(faultRes.Target)
		if err != nil {
			return ErrIO
		}
		*epochOut = C.int64_t(faultRes.Epoch)
		*minerIdOut = C.uint64_t(id)
	}

	return 0
}

//export cgo_extern_get_tipset_cid
func cgo_extern_get_tipset_cid(
	handle C.uint64_t,
	epoch C.int64_t,
	output C.buf_t,
	outputLen C.int32_t,
) (res C.int32_t) {
	defer func() {
		if rerr := recover(); rerr != nil {
			logPanic(rerr)
			res = ErrPanic
		}
	}()

	externs, ctx := Lookup(uint64(handle))
	if externs == nil {
		return ErrInvalidHandle
	}

	out := unsafe.Slice((*byte)(unsafe.Pointer(output)), outputLen)

	k, err := externs.TipsetCid(ctx, abi.ChainEpoch(epoch))
	if err != nil {
		return ErrIO
	}
	if k.ByteLen() > int(outputLen) {
		return ErrInvalidArgument
	}
	copy(out, k.Bytes())
	return 0
}
