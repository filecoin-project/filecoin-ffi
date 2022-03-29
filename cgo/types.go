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

type FCPResponseStatus int64

type SliceBoxedUint8 = C.struct_slice_boxed_uint8

func (ptr SliceBoxedUint8) Slice() []byte {
	return unsafe.Slice((*byte)(ptr.ptr), int(ptr.len))
}

func (ptr SliceBoxedUint8) Copy() []byte {
	if ptr.len == 0 {
		return []byte{}
	}

	ref := ptr.Slice()
	res := make([]byte, len(ref))
	for i := range ref {
		res[i] = ref[i]
	}
	return res
}

func (ptr SliceBoxedUint8) Destroy() {
	C.destroy_boxed_slice(ptr)
}

type SliceRefUint8 = C.slice_ref_uint8_t

type BLSDigest = C.BLSDigest_t

func (ptr *BLSDigest) Slice() []byte {
	return ptr.inner.Slice()
}

type HashResponse = C.HashResponse_t

func (ptr *HashResponse) Digest() []byte {
	return ptr.digest.Slice()
}

type BLSSignature = C.BLSSignature_t

func (ptr *BLSSignature) Slice() []byte {
	return ptr.inner.Slice()
}

type AggregateResponse = C.AggregateResponse_t

func (ptr *AggregateResponse) Signature() []byte {
	return ptr.signature.Slice()
}

type SliceRefUint = C.slice_ref_size_t

type BLSPrivateKey = C.BLSPrivateKey_t

func (ptr *BLSPrivateKey) Slice() []byte {
	return ptr.inner.Slice()
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
	return ptr.inner.Slice()
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
	if ptr != nil {
		// TODO: correct naming
		C.destroy_verify_seal_response(ptr)
	}
}

type AggregationInputs = C.AggregationInputs_t
type SliceRefAggregationInputs = C.slice_ref_AggregationInputs_t

type PublicReplicaInfo = C.PublicReplicaInfo_t
type PrivateReplicaInfo = C.PrivateReplicaInfo_t

func (ptr *PrivateReplicaInfo) Destroy() {
	if ptr != nil {
		ptr.cache_dir_path.Destroy()
		ptr.replica_path.Destroy()
	}
}

type SliceRefPublicReplicaInfo = C.slice_ref_PublicReplicaInfo_t
type SliceRefPrivateReplicaInfo = C.slice_ref_PrivateReplicaInfo_t

type PoStProof = C.PoStProof_t
type SliceRefPoStProof = C.slice_ref_PoStProof_t

func (ptr *PoStProof) Proof() []byte {
	return ptr.proof.Slice()
}

func (ptr *PoStProof) CopyProof() []byte {
	return ptr.proof.Copy()
}

func (ptr *PoStProof) RegisteredProof() RegisteredPoStProof {
	return ptr.registered_proof
}

func (ptr *PoStProof) Destroy() {
	if ptr != nil {
		ptr.proof.Destroy()
	}
}

type ByteArray96 = C.uint8_96_array_t

func (ptr ByteArray96) Slice() []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(&ptr.idx[0])), 96)
}

type ByteArray48 = C.uint8_48_array_t

func (ptr ByteArray48) Slice() []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(&ptr.idx[0])), 48)
}

type ByteArray32 = C.uint8_32_array_t

func (ptr ByteArray32) Slice() []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(&ptr.idx[0])), 32)
}

func (ptr ByteArray32) Copy() []byte {
	res := make([]byte, 32)
	for i := range res {
		res[i] = byte(ptr.idx[i])
	}
	return res
}

type ResultGeneratePieceCommitment = C.Result_GeneratePieceCommitment_t

func (ptr *ResultGeneratePieceCommitment) StatusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.status_code)
}

func (ptr *ResultGeneratePieceCommitment) ErrorMsg() *SliceBoxedUint8 {
	return &ptr.error_msg
}

func (ptr *ResultGeneratePieceCommitment) Destroy() {
	if ptr != nil {
		C.destroy_generate_piece_commitment_response(ptr)
	}
}

type ResultByteArray32 = C.Result_uint8_32_array_t

func (ptr *ResultByteArray32) StatusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.status_code)
}

func (ptr *ResultByteArray32) ErrorMsg() *SliceBoxedUint8 {
	return &ptr.error_msg
}

func (ptr *ResultByteArray32) Destroy() {
	if ptr != nil {
		// TODO: better naming
		C.destroy_generate_data_commitment_response(ptr)
	}
}

func (ptr *ResultByteArray32) Value() ByteArray32 {
	return ptr.value
}

type PublicPieceInfo = C.PublicPieceInfo_t
type SliceRefPublicPieceInfo = C.slice_ref_PublicPieceInfo_t

type SliceRefUint64 = C.slice_ref_uint64_t

type ResultWriteWithAlignment = C.Result_WriteWithAlignment_t

func (ptr *ResultWriteWithAlignment) StatusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.status_code)
}

func (ptr *ResultWriteWithAlignment) ErrorMsg() *SliceBoxedUint8 {
	return &ptr.error_msg
}

func (ptr *ResultWriteWithAlignment) Destroy() {
	if ptr != nil {
		C.destroy_write_with_alignment_response(ptr)
	}
}

type ResultWriteWithoutAlignment = C.Result_WriteWithoutAlignment_t

func (ptr *ResultWriteWithoutAlignment) StatusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.status_code)
}

func (ptr *ResultWriteWithoutAlignment) ErrorMsg() *SliceBoxedUint8 {
	return &ptr.error_msg
}

func (ptr *ResultWriteWithoutAlignment) Destroy() {
	if ptr != nil {
		C.destroy_write_without_alignment_response(ptr)
	}
}

type ResultSliceBoxedUint8 = C.Result_slice_boxed_uint8_t

func (ptr *ResultSliceBoxedUint8) StatusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.status_code)
}

func (ptr *ResultSliceBoxedUint8) ErrorMsg() *SliceBoxedUint8 {
	return &ptr.error_msg
}

func (ptr *ResultSliceBoxedUint8) Destroy() {
	if ptr != nil {
		// TODO: naming
		C.destroy_seal_pre_commit_phase1_response(ptr)
	}
}

type ResultSealPreCommitPhase2 = C.Result_SealPreCommitPhase2_t

func (ptr *ResultSealPreCommitPhase2) StatusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.status_code)
}

func (ptr *ResultSealPreCommitPhase2) ErrorMsg() *SliceBoxedUint8 {
	return &ptr.error_msg
}

func (ptr *ResultSealPreCommitPhase2) Destroy() {
	if ptr != nil {
		C.destroy_seal_pre_commit_phase2_response(ptr)
	}
}

type SliceRefByteArray32 = C.slice_ref_uint8_32_array_t
type SliceRefSliceBoxedUint8 = C.slice_ref_slice_boxed_uint8_t

type ResultVoid = C.Result_void_t

func (ptr *ResultVoid) StatusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.status_code)
}

func (ptr *ResultVoid) ErrorMsg() *SliceBoxedUint8 {
	return &ptr.error_msg
}

func (ptr *ResultVoid) Destroy() {
	if ptr != nil {
		// TODO: correct naming
		C.destroy_unseal_range_response(ptr)
	}
}

type SliceBoxedUint64 = C.struct_slice_boxed_uint64

func (ptr SliceBoxedUint64) Slice() []uint64 {
	return unsafe.Slice((*uint64)(unsafe.Pointer(ptr.ptr)), int(ptr.len))
}

func (ptr SliceBoxedUint64) Copy() []uint64 {
	if ptr.len == 0 {
		return []uint64{}
	}

	ref := ptr.Slice()
	res := make([]uint64, len(ref))
	for i := range ref {
		res[i] = ref[i]
	}

	return res
}

type ResultSliceBoxedUint64 = C.Result_slice_boxed_uint64_t

func (ptr *ResultSliceBoxedUint64) StatusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.status_code)
}

func (ptr *ResultSliceBoxedUint64) ErrorMsg() *SliceBoxedUint8 {
	return &ptr.error_msg
}

func (ptr *ResultSliceBoxedUint64) Destroy() {
	if ptr != nil {
		// TODO: correct naming
		C.destroy_generate_winning_post_sector_challenge(ptr)
	}
}

type SliceBoxedPoStProof = C.struct_slice_boxed_PoStProof

func (ptr SliceBoxedPoStProof) Slice() []PoStProof {
	return unsafe.Slice((*PoStProof)(unsafe.Pointer(ptr.ptr)), int(ptr.len))
}

// PoStProofGo is a go allocated version of `PoStProof`.
type PoStProofGo struct {
	RegisteredProof RegisteredPoStProof
	Proof           []byte
}

func (ptr SliceBoxedPoStProof) Copy() []PoStProofGo {
	if ptr.len == 0 {
		return []PoStProofGo{}
	}

	ref := ptr.Slice()
	res := make([]PoStProofGo, len(ref))
	for i := range ref {
		res[i] = PoStProofGo{
			RegisteredProof: ref[i].registered_proof,
			Proof:           ref[i].proof.Copy(),
		}
	}

	return res
}

type ResultSliceBoxedPoStProof = C.Result_slice_boxed_PoStProof_t

func (ptr *ResultSliceBoxedPoStProof) StatusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.status_code)
}

func (ptr *ResultSliceBoxedPoStProof) ErrorMsg() *SliceBoxedUint8 {
	return &ptr.error_msg
}

func (ptr *ResultSliceBoxedPoStProof) Destroy() {
	if ptr != nil {
		// TODO: correct naming
		C.destroy_generate_winning_post_response(ptr)
	}
}

type ResultGenerateWindowPoSt = C.Result_GenerateWindowPoSt_t

func (ptr *ResultGenerateWindowPoSt) StatusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.status_code)
}

func (ptr *ResultGenerateWindowPoSt) ErrorMsg() *SliceBoxedUint8 {
	return &ptr.error_msg
}

func (ptr *ResultGenerateWindowPoSt) Destroy() {
	if ptr != nil {
		C.destroy_generate_window_post_response(ptr)
	}
}

type SliceBoxedSliceBoxedUint8 = C.slice_boxed_slice_boxed_uint8_t

func (ptr SliceBoxedSliceBoxedUint8) Slice() []SliceBoxedUint8 {
	return unsafe.Slice((*SliceBoxedUint8)(unsafe.Pointer(ptr.ptr)), int(ptr.len))
}

func (ptr SliceBoxedSliceBoxedUint8) CopyAsBytes() [][]byte {
	if ptr.len == 0 {
		return [][]byte{}
	}

	ref := ptr.Slice()
	res := make([][]byte, len(ref))
	for i := range ref {
		res[i] = ref[i].Copy()
	}

	return res
}

func (ptr SliceBoxedSliceBoxedUint8) CopyAsStrings() []string {
	if ptr.len == 0 {
		return []string{}
	}
	ref := ptr.Slice()
	res := make([]string, int(ptr.len))
	for i := range ref {
		res[i] = string(ref[i].Copy())
	}

	return res
}

type ResultSliceBoxedSliceBoxedUint8 = C.Result_slice_boxed_slice_boxed_uint8_t

func (ptr *ResultSliceBoxedSliceBoxedUint8) StatusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.status_code)
}

func (ptr *ResultSliceBoxedSliceBoxedUint8) ErrorMsg() *SliceBoxedUint8 {
	return &ptr.error_msg
}

func (ptr *ResultSliceBoxedSliceBoxedUint8) Destroy() {
	if ptr != nil {
		// TODO: naming
		C.destroy_generate_empty_sector_update_partition_proof_response(ptr)
	}
}

type ResultUint = C.Result_size_t

func (ptr *ResultUint) StatusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.status_code)
}

func (ptr *ResultUint) ErrorMsg() *SliceBoxedUint8 {
	return &ptr.error_msg
}

func (ptr *ResultUint) Destroy() {
	if ptr != nil {
		// TODO: naming
		C.destroy_get_num_partition_for_fallback_post_response(ptr)
	}
}
