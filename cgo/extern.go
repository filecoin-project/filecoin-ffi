package cgo

/*
#include <stdint.h>
typedef const uint8_t* buf_t;
*/
import "C"
import (
	"context"
	"unsafe"

	"github.com/filecoin-project/go-address"

	"github.com/filecoin-project/go-state-types/abi"
	"github.com/filecoin-project/go-state-types/crypto"
)

//export cgo_extern_get_chain_randomness
func cgo_extern_get_chain_randomness(
	handle C.uint64_t, pers C.int64_t, round C.int64_t,
	entropy C.buf_t, entropy_len C.int32_t,
	output C.buf_t,
) C.int32_t {
	out := (*[32]byte)(unsafe.Pointer(output))
	externs := Lookup(uint64(handle))
	if externs == nil {
		return ErrInvalidHandle
	}

	rand, err := externs.GetChainRandomness(context.TODO(), crypto.DomainSeparationTag(pers), abi.ChainEpoch(round), C.GoBytes(unsafe.Pointer(entropy), entropy_len))

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
	entropy C.buf_t, entropy_len C.int32_t,
	output C.buf_t,
) C.int32_t {
	out := (*[32]byte)(unsafe.Pointer(output))
	externs := Lookup(uint64(handle))
	if externs == nil {
		return ErrInvalidHandle
	}

	rand, err := externs.GetBeaconRandomness(context.TODO(), crypto.DomainSeparationTag(pers), abi.ChainEpoch(round), C.GoBytes(unsafe.Pointer(entropy), entropy_len))

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
	h1 C.buf_t, h1_len C.int32_t,
	h2 C.buf_t, h2_len C.int32_t,
	extra C.buf_t, extra_len C.int32_t,
	miner_id *C.uint64_t,
	epoch *C.int64_t,
	fault *C.int64_t,
	gas_used *C.int64_t,
) C.int32_t {
	externs := Lookup(uint64(handle))
	if externs == nil {
		return ErrInvalidHandle
	}

	h1Go := C.GoBytes(unsafe.Pointer(h1), h1_len)
	h2Go := C.GoBytes(unsafe.Pointer(h2), h2_len)
	extraGo := C.GoBytes(unsafe.Pointer(extra), extra_len)

	res, gas := externs.VerifyConsensusFault(context.TODO(), h1Go, h2Go, extraGo)
	*gas_used = C.int64_t(gas)
	*fault = C.int64_t(res.Type)

	if res.Type != ConsensusFaultNone {
		id, err := address.IDFromAddress(res.Target)
		if err != nil {
			return ErrIO
		}
		*epoch = C.int64_t(res.Epoch)
		*miner_id = C.uint64_t(id)
	}

	return 0
}
