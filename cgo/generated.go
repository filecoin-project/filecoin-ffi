package cgo

/*
#cgo LDFLAGS: -L${SRCDIR}/..
#cgo pkg-config: ${SRCDIR}/../filcrypto.pc
#include "../filcrypto.h"
#include <stdlib.h>
*/
import "C"
import (
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

func AsByteArray32(goSlice []byte) ByteArray32 {
	var ary ByteArray32
	for idx := range goSlice[:32] {
		ary.inner.idx[idx] = C.uchar(goSlice[idx])
	}
	return ary
}

func Hash(message SliceRefUint8) *HashResponse {
	return C.hash(message)
}

func (ptr *HashResponse) Destroy() {
	C.destroy_hash_response(ptr)
}

func Aggregate(flattenedSignatures SliceRefUint8) *AggregateResponse {
	return C.aggregate(flattenedSignatures)
}

func (ptr *AggregateResponse) Destroy() {
	C.destroy_aggregate_response(ptr)
}

func Verify(signature SliceRefUint8, flattenedDigests SliceRefUint8, flattenedPublicKeys SliceRefUint8) C.int32_t {
	return C.verify(signature, flattenedDigests, flattenedPublicKeys)
}

func HashVerify(signature SliceRefUint8, flattenedMessages SliceRefUint8, messageSizes SliceRefUint, flattenedPublicKeys SliceRefUint8) C.int32_t {
	return C.hash_verify(signature, flattenedMessages, messageSizes, flattenedPublicKeys)
}

func PrivateKeyGenerate() *PrivateKeyGenerateResponse {
	return C.private_key_generate()
}

func PrivateKeyGenerateWithSeed(rawSeed ByteArray32) *PrivateKeyGenerateResponse {
	return C.private_key_generate_with_seed(rawSeed)
}

func PrivateKeySign(rawPrivateKey SliceRefUint8, message SliceRefUint8) *PrivateKeySignResponse {
	return C.private_key_sign(rawPrivateKey, message)
}

func (ptr *PrivateKeySignResponse) Destroy() {
	C.destroy_private_key_sign_response(ptr)
}

func PrivateKeyPublicKey(rawPrivateKey SliceRefUint8) *PrivateKeyPublicKeyResponse {
	return C.private_key_public_key(rawPrivateKey)
}

func (ptr *PrivateKeyPublicKeyResponse) Destroy() {
	C.destroy_private_key_public_key_response(ptr)
}

func CreateZeroSignature() *ZeroSignatureResponse {
	return C.create_zero_signature()
}

func (ptr *ZeroSignatureResponse) Destroy() {
	C.drop_signature(ptr)
}

func (ptr *PrivateKeyGenerateResponse) Destroy() {
	C.destroy_private_key_generate_response(ptr)
}
