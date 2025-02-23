package cgo

/*
#cgo LDFLAGS: -L${SRCDIR}/..
#cgo pkg-config: ${SRCDIR}/../filcrypto.pc
#include "../filcrypto.h"
#include <stdlib.h>
*/
import "C"

func Hash(message SliceRefUint8) *[96]byte {
	resp := (*ByteArray96)(C.hash((C.slice_ref_uint8_t)(message)))
	defer resp.destroy()
	return resp.copyAsArray()
}

func Aggregate(flattenedSignatures SliceRefUint8) *[96]byte {
	resp := (*ByteArray96)(C.aggregate((C.slice_ref_uint8_t)(flattenedSignatures)))
	defer resp.destroy()
	return resp.copyAsArray()
}

func Verify(signature SliceRefUint8, flattenedDigests SliceRefUint8, flattenedPublicKeys SliceRefUint8) bool {
	resp := C.verify((C.slice_ref_uint8_t)(signature),
		(C.slice_ref_uint8_t)(flattenedDigests),
		(C.slice_ref_uint8_t)(flattenedPublicKeys))
	return bool(resp)
}

func HashVerify(signature SliceRefUint8, flattenedMessages SliceRefUint8, messageSizes SliceRefUint, flattenedPublicKeys SliceRefUint8) bool {
	resp := C.hash_verify((C.slice_ref_uint8_t)(signature),
		(C.slice_ref_uint8_t)(flattenedMessages),
		(C.slice_ref_size_t)(messageSizes),
		(C.slice_ref_uint8_t)(flattenedPublicKeys))
	return bool(resp)
}

func PrivateKeyGenerate() *[32]byte {
	resp := (*ByteArray32)(C.private_key_generate())
	defer resp.destroy()
	return resp.copyAsArray()
}

func PrivateKeyGenerateWithSeed(rawSeed *ByteArray32) *[32]byte {
	resp := (*ByteArray32)(C.private_key_generate_with_seed((*C.uint8_32_array_t)(rawSeed)))
	defer resp.destroy()
	return resp.copyAsArray()
}

func PrivateKeySign(rawPrivateKey SliceRefUint8, message SliceRefUint8) *[96]byte {
	resp := (*ByteArray96)(C.private_key_sign((C.slice_ref_uint8_t)(rawPrivateKey),
		(C.slice_ref_uint8_t)(message)))
	defer resp.destroy()
	return resp.copyAsArray()
}

func PrivateKeyPublicKey(rawPrivateKey SliceRefUint8) *[48]byte {
	resp := (*ByteArray48)(C.private_key_public_key((C.slice_ref_uint8_t)(rawPrivateKey)))
	defer resp.destroy()
	return resp.copyAsArray()
}

func CreateZeroSignature() *[96]byte {
	resp := (*ByteArray96)(C.create_zero_signature())
	defer resp.destroy()
	return resp.copyAsArray()
}
