package cgo

/*
#cgo LDFLAGS: -L${SRCDIR}/..
#cgo pkg-config: ${SRCDIR}/../filcrypto.pc
#include "../filcrypto.h"
#include <stdlib.h>
*/
import "C"
import "unsafe"

type FCPResponseStatus int64

type SliceBoxedUint8 = C.struct_slice_boxed_uint8

func (ptr *SliceBoxedUint8) Slice() []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(&ptr.ptr)), int(ptr.len))
}

type SliceRefUint8 = C.slice_ref_uint8_t

type BLSDigest = C.BLSDigest_t

func (ptr *BLSDigest) Slice() []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(&ptr.inner.idx[0])), 96)
}

type HashResponse = C.HashResponse_t

func (ptr *HashResponse) Digest() []byte {
	return ptr.digest.Slice()
}

type BLSSignature = C.BLSSignature_t

func (ptr *BLSSignature) Slice() []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(&ptr.inner.idx[0])), 96)
}

type AggregateResponse = C.AggregateResponse_t

func (ptr *AggregateResponse) Signature() []byte {
	return ptr.signature.Slice()
}

type SliceRefUint = C.slice_ref_size_t

type BLSPrivateKey = C.BLSPrivateKey_t

func (ptr *BLSPrivateKey) Slice() []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(&ptr.inner.idx[0])), 32)
}

type PrivateKeyGenerateResponse = C.PrivateKeyGenerateResponse_t

func (ptr *PrivateKeyGenerateResponse) PrivateKey() []byte {
	return ptr.private_key.Slice()
}

type PrivateKeySignResponse = C.PrivateKeySignResponse_t

func (ptr *PrivateKeySignResponse) Signature() []byte {
	return ptr.signature.Slice()
}

type BLSPublicKey = C.BLSPublicKey_t

func (ptr *BLSPublicKey) Slice() []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(&ptr.inner.idx[0])), 48)
}

type PrivateKeyPublicKeyResponse = C.PrivateKeyPublicKeyResponse_t

func (ptr *PrivateKeyPublicKeyResponse) PublicKey() []byte {
	return ptr.public_key.Slice()
}

type ZeroSignatureResponse = C.ZeroSignatureResponse_t

func (ptr *ZeroSignatureResponse) Signature() []byte {
	return ptr.signature.Slice()
}

type RegisteredSealProof = C.RegisteredSealProof_t
type RegisteredAggregationProof = C.RegisteredAggregationProof_t
type RegisteredPoStProof = C.RegisteredPoStProof_t

type Result interface {
	StatusCode() FCPResponseStatus
	ErrorMsg() *SliceBoxedUint8
	Destroy()
}

type ResultBool = C.Result_bool_t

func (ptr *ResultBool) StatusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.status_code)
}

func (ptr *ResultBool) ErrorMsg() *SliceBoxedUint8 {
	return &ptr.error_msg
}

func (ptr *ResultBool) Destroy() {
	// TODO: correct naming
	C.destroy_verify_seal_response(ptr)
}

type AggregationInputs = C.AggregationInputs_t
type SliceRefAggregationInputs = C.slice_ref_AggregationInputs_t

type PublicReplicaInfo = C.PublicReplicaInfo_t
type PrivateReplicaInfo = C.PrivateReplicaInfo_t

type SliceRefPublicReplicaInfo = C.slice_ref_PublicReplicaInfo_t
type SliceRefPrivateReplicaInfo = C.slice_ref_PrivateReplicaInfo_t

type PoStProof = C.PoStProof_t
type SliceRefPoStProof = C.slice_ref_PoStProof_t

func (ptr *PoStProof) Proof() []byte {
	return ptr.proof.Slice()
}

func (ptr *PoStProof) RegisteredProof() RegisteredPoStProof {
	return ptr.registered_proof
}

type ByteArray32 = C.uint8_32_array_t

func (ptr *ByteArray32) Slice() []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(&ptr.idx[0])), 32)
}
