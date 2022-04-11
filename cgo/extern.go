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
	"github.com/filecoin-project/go-state-types/crypto"
)

//export cgo_extern_get_chain_randomness
func cgo_extern_get_chain_randomness(
	handle C.uint64_t, pers C.int64_t, round C.int64_t,
	entropy C.buf_t, entropyLen C.int32_t,
	output C.buf_t,
) (res C.int32_t) {
	defer func() {
		if rerr := recover(); rerr != nil {
			logPanic(rerr)
			res = ErrPanic
		}
	}()

	out := (*[32]byte)(unsafe.Pointer(output))
	externs, ctx := Lookup(uint64(handle))
	if externs == nil {
		return ErrInvalidHandle
	}

	rand, err := externs.GetChainRandomness(ctx, crypto.DomainSeparationTag(pers), abi.ChainEpoch(round), C.GoBytes(unsafe.Pointer(entropy), entropyLen))

	switch err {
	case nil:
		copy(out[:], rand)
		return 0
	default:
		return ErrIO
	}
}

//export cgo_extern_get_beacon_randomness
func cgo_extern_get_beacon_randomness(
	handle C.uint64_t, pers C.int64_t, round C.int64_t,
	entropy C.buf_t, entropyLen C.int32_t,
	output C.buf_t,
) (res C.int32_t) {
	defer func() {
		if rerr := recover(); rerr != nil {
			logPanic(rerr)
			res = ErrPanic
		}
	}()

	out := (*[32]byte)(unsafe.Pointer(output))
	externs, ctx := Lookup(uint64(handle))
	if externs == nil {
		return ErrInvalidHandle
	}

	rand, err := externs.GetBeaconRandomness(ctx, crypto.DomainSeparationTag(pers), abi.ChainEpoch(round), C.GoBytes(unsafe.Pointer(entropy), entropyLen))

	switch err {
	case nil:
		copy(out[:], rand)
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
