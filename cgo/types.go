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

func (ptr SliceBoxedUint8) slice() []byte {
	return unsafe.Slice((*byte)(ptr.ptr), int(ptr.len))
}

func (ptr SliceBoxedUint8) copy() []byte {
	if ptr.len == 0 {
		return nil
	}

	res := make([]byte, int(ptr.len))
	copy(res, ptr.slice())
	return res
}

func (ptr SliceBoxedUint8) Destroy() {
	C.destroy_boxed_slice(ptr)
}

type SliceRefUint8 = C.slice_ref_uint8_t
type SliceRefUint = C.slice_ref_size_t

type RegisteredSealProof = C.RegisteredSealProof_t
type RegisteredAggregationProof = C.RegisteredAggregationProof_t
type RegisteredPoStProof = C.RegisteredPoStProof_t
type RegisteredUpdateProof = C.RegisteredUpdateProof_t

type result interface {
	statusCode() FCPResponseStatus
	errorMsg() *SliceBoxedUint8
	destroy()
}

type ResultBool = C.Result_bool_t

func (ptr *ResultBool) statusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.status_code)
}

func (ptr *ResultBool) errorMsg() *SliceBoxedUint8 {
	return &ptr.error_msg
}

func (ptr *ResultBool) destroy() {
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

func (ptr *PoStProof) registeredProof() RegisteredPoStProof {
	return ptr.registered_proof
}

func (ptr *PoStProof) destroy() {
	if ptr != nil {
		ptr.proof.Destroy()
	}
}

type ByteArray96 = C.uint8_96_array_t

func (ptr *ByteArray96) destroy() {
	if ptr != nil {
		C.destroy_box_bls_digest(ptr)
	}
}

func (ptr ByteArray96) slice() []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(&ptr.idx[0])), 96)
}

func (ptr *ByteArray96) copyAsArray() *[96]byte {
	if ptr == nil {
		return nil
	}
	var res [96]byte
	copy(res[:], ptr.slice())
	return &res
}

type ByteArray48 = C.uint8_48_array_t

func (ptr ByteArray48) slice() []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(&ptr.idx[0])), 48)
}

func (ptr *ByteArray48) copyAsArray() *[48]byte {
	if ptr == nil {
		return nil
	}
	var res [48]byte
	copy(res[:], ptr.slice())
	return &res
}

func (ptr *ByteArray48) destroy() {
	if ptr != nil {
		C.destroy_box_bls_public_key(ptr)
	}
}

type ByteArray32 = C.uint8_32_array_t

func (ptr ByteArray32) slice() []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(&ptr.idx[0])), 32)
}

func (ptr *ByteArray32) copy() []byte {
	res := make([]byte, 32)
	if ptr != nil {
		copy(res, ptr.slice())
	}
	return res
}

func (ptr *ByteArray32) copyAsArray() *[32]byte {
	if ptr == nil {
		return nil
	}
	var res [32]byte
	copy(res[:], ptr.slice())
	return &res
}

func (ptr *ByteArray32) destroy() {
	if ptr != nil {
		C.destroy_box_bls_private_key(ptr)
	}
}

type ResultGeneratePieceCommitment = C.Result_GeneratePieceCommitment_t

func (ptr *ResultGeneratePieceCommitment) statusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.status_code)
}

func (ptr *ResultGeneratePieceCommitment) errorMsg() *SliceBoxedUint8 {
	return &ptr.error_msg
}

func (ptr *ResultGeneratePieceCommitment) destroy() {
	if ptr != nil {
		C.destroy_generate_piece_commitment_response(ptr)
	}
}

type ResultByteArray32 = C.Result_uint8_32_array_t

func (ptr *ResultByteArray32) statusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.status_code)
}

func (ptr *ResultByteArray32) errorMsg() *SliceBoxedUint8 {
	return &ptr.error_msg
}

func (ptr *ResultByteArray32) destroy() {
	if ptr != nil {
		// TODO: better naming
		C.destroy_generate_data_commitment_response(ptr)
	}
}

type PublicPieceInfo = C.PublicPieceInfo_t
type SliceRefPublicPieceInfo = C.slice_ref_PublicPieceInfo_t

type SliceRefUint64 = C.slice_ref_uint64_t

type ResultWriteWithAlignment = C.Result_WriteWithAlignment_t

func (ptr *ResultWriteWithAlignment) statusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.status_code)
}

func (ptr *ResultWriteWithAlignment) errorMsg() *SliceBoxedUint8 {
	return &ptr.error_msg
}

func (ptr *ResultWriteWithAlignment) destroy() {
	if ptr != nil {
		C.destroy_write_with_alignment_response(ptr)
	}
}

type ResultWriteWithoutAlignment = C.Result_WriteWithoutAlignment_t

func (ptr *ResultWriteWithoutAlignment) statusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.status_code)
}

func (ptr *ResultWriteWithoutAlignment) errorMsg() *SliceBoxedUint8 {
	return &ptr.error_msg
}

func (ptr *ResultWriteWithoutAlignment) destroy() {
	if ptr != nil {
		C.destroy_write_without_alignment_response(ptr)
	}
}

type ResultSliceBoxedUint8 = C.Result_slice_boxed_uint8_t

func (ptr *ResultSliceBoxedUint8) statusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.status_code)
}

func (ptr *ResultSliceBoxedUint8) errorMsg() *SliceBoxedUint8 {
	return &ptr.error_msg
}

func (ptr *ResultSliceBoxedUint8) destroy() {
	if ptr != nil {
		// TODO: naming
		C.destroy_seal_pre_commit_phase1_response(ptr)
	}
}

type ResultSealPreCommitPhase2 = C.Result_SealPreCommitPhase2_t

func (ptr *ResultSealPreCommitPhase2) statusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.status_code)
}

func (ptr *ResultSealPreCommitPhase2) errorMsg() *SliceBoxedUint8 {
	return &ptr.error_msg
}

func (ptr *ResultSealPreCommitPhase2) destroy() {
	if ptr != nil {
		C.destroy_seal_pre_commit_phase2_response(ptr)
	}
}

type SliceRefByteArray32 = C.slice_ref_uint8_32_array_t
type SliceRefSliceBoxedUint8 = C.slice_ref_slice_boxed_uint8_t

type ResultVoid = C.Result_void_t

func (ptr *ResultVoid) statusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.status_code)
}

func (ptr *ResultVoid) errorMsg() *SliceBoxedUint8 {
	return &ptr.error_msg
}

func (ptr *ResultVoid) destroy() {
	if ptr != nil {
		// TODO: correct naming
		C.destroy_unseal_range_response(ptr)
	}
}

type SliceBoxedUint64 = C.struct_slice_boxed_uint64

func (ptr SliceBoxedUint64) slice() []uint64 {
	return unsafe.Slice((*uint64)(unsafe.Pointer(ptr.ptr)), int(ptr.len))
}

func (ptr SliceBoxedUint64) copy() []uint64 {
	if ptr.len == 0 {
		return []uint64{}
	}

	res := make([]uint64, int(ptr.len))
	copy(res, ptr.slice())
	return res
}

type ResultSliceBoxedUint64 = C.Result_slice_boxed_uint64_t

func (ptr *ResultSliceBoxedUint64) statusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.status_code)
}

func (ptr *ResultSliceBoxedUint64) errorMsg() *SliceBoxedUint8 {
	return &ptr.error_msg
}

func (ptr *ResultSliceBoxedUint64) destroy() {
	if ptr != nil {
		// TODO: correct naming
		C.destroy_generate_winning_post_sector_challenge(ptr)
	}
}

type SliceBoxedPoStProof = C.struct_slice_boxed_PoStProof

func (ptr SliceBoxedPoStProof) slice() []PoStProof {
	return unsafe.Slice((*PoStProof)(unsafe.Pointer(ptr.ptr)), int(ptr.len))
}

// PoStProofGo is a go allocated version of `PoStProof`.
type PoStProofGo struct {
	RegisteredProof RegisteredPoStProof
	Proof           []byte
}

func (ptr SliceBoxedPoStProof) copy() []PoStProofGo {
	if ptr.len == 0 {
		return []PoStProofGo{}
	}

	ref := ptr.slice()
	res := make([]PoStProofGo, len(ref))
	for i := range ref {
		res[i] = ref[i].copy()
	}

	return res
}

func (proof PoStProof) copy() PoStProofGo {
	return PoStProofGo{
		RegisteredProof: proof.registered_proof,
		Proof:           proof.proof.copy(),
	}
}

type ResultSliceBoxedPoStProof = C.Result_slice_boxed_PoStProof_t

func (ptr *ResultSliceBoxedPoStProof) statusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.status_code)
}

func (ptr *ResultSliceBoxedPoStProof) errorMsg() *SliceBoxedUint8 {
	return &ptr.error_msg
}

func (ptr *ResultSliceBoxedPoStProof) destroy() {
	if ptr != nil {
		// TODO: correct naming
		C.destroy_generate_winning_post_response(ptr)
	}
}

type ResultGenerateWindowPoSt = C.Result_GenerateWindowPoSt_t

func (ptr *ResultGenerateWindowPoSt) statusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.status_code)
}

func (ptr *ResultGenerateWindowPoSt) errorMsg() *SliceBoxedUint8 {
	return &ptr.error_msg
}

func (ptr *ResultGenerateWindowPoSt) destroy() {
	if ptr != nil {
		C.destroy_generate_window_post_response(ptr)
	}
}

type SliceBoxedSliceBoxedUint8 = C.slice_boxed_slice_boxed_uint8_t

func (ptr SliceBoxedSliceBoxedUint8) slice() []SliceBoxedUint8 {
	return unsafe.Slice((*SliceBoxedUint8)(unsafe.Pointer(ptr.ptr)), int(ptr.len))
}

func (ptr SliceBoxedSliceBoxedUint8) copyAsBytes() [][]byte {
	if ptr.len == 0 {
		return [][]byte{}
	}

	ref := ptr.slice()
	res := make([][]byte, int(ptr.len))
	for i := range ref {
		res[i] = ref[i].copy()
	}

	return res
}

func (ptr SliceBoxedSliceBoxedUint8) copyAsStrings() []string {
	if ptr.len == 0 {
		return []string{}
	}
	ref := ptr.slice()
	res := make([]string, int(ptr.len))
	for i := range ref {
		res[i] = string(ref[i].copy())
	}

	return res
}

type ResultSliceBoxedSliceBoxedUint8 = C.Result_slice_boxed_slice_boxed_uint8_t

func (ptr *ResultSliceBoxedSliceBoxedUint8) statusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.status_code)
}

func (ptr *ResultSliceBoxedSliceBoxedUint8) errorMsg() *SliceBoxedUint8 {
	return &ptr.error_msg
}

func (ptr *ResultSliceBoxedSliceBoxedUint8) destroy() {
	if ptr != nil {
		// TODO: naming
		C.destroy_generate_empty_sector_update_partition_proof_response(ptr)
	}
}

type ResultUint = C.Result_size_t

func (ptr *ResultUint) statusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.status_code)
}

func (ptr *ResultUint) errorMsg() *SliceBoxedUint8 {
	return &ptr.error_msg
}

func (ptr *ResultUint) destroy() {
	if ptr != nil {
		// TODO: naming
		C.destroy_get_num_partition_for_fallback_post_response(ptr)
	}
}

type ResultEmptySectorUpdateEncodeInto = C.Result_EmptySectorUpdateEncodeInto_t

func (ptr *ResultEmptySectorUpdateEncodeInto) statusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.status_code)
}

func (ptr *ResultEmptySectorUpdateEncodeInto) errorMsg() *SliceBoxedUint8 {
	return &ptr.error_msg
}

func (ptr *ResultEmptySectorUpdateEncodeInto) destroy() {
	if ptr != nil {
		C.destroy_empty_sector_update_encode_into_response(ptr)
	}
}

type SliceBoxedSliceBoxedUint64 = C.slice_boxed_slice_boxed_uint64_t

func (ptr SliceBoxedSliceBoxedUint64) slice() []SliceBoxedUint64 {
	return unsafe.Slice((*SliceBoxedUint64)(unsafe.Pointer(ptr.ptr)), int(ptr.len))
}

func (ptr SliceBoxedSliceBoxedUint64) copy() [][]uint64 {
	if ptr.len == 0 {
		return [][]uint64{}
	}

	ref := ptr.slice()
	res := make([][]uint64, int(ptr.len))
	for i := range ref {
		res[i] = ref[i].copy()
	}

	return res
}

type ResultGenerateFallbackSectorChallenges = C.Result_GenerateFallbackSectorChallenges_t

func (ptr *ResultGenerateFallbackSectorChallenges) statusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.status_code)
}

func (ptr *ResultGenerateFallbackSectorChallenges) errorMsg() *SliceBoxedUint8 {
	return &ptr.error_msg
}

func (ptr *ResultGenerateFallbackSectorChallenges) destroy() {
	if ptr != nil {
		C.destroy_generate_fallback_sector_challenges_response(ptr)
	}
}

type PartitionSnarkProof = C.PartitionSnarkProof_t
type PartitionSnarkProofGo struct {
	RegisteredProof RegisteredPoStProof
	Proof           []byte
}

func (proof PartitionSnarkProof) copy() PartitionSnarkProofGo {
	return PartitionSnarkProofGo{
		RegisteredProof: proof.registered_proof,
		Proof:           proof.proof.copy(),
	}
}

type ResultGenerateSingleWindowPoStWithVanilla = C.Result_GenerateSingleWindowPoStWithVanilla_t

func (ptr *ResultGenerateSingleWindowPoStWithVanilla) statusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.status_code)
}

func (ptr *ResultGenerateSingleWindowPoStWithVanilla) errorMsg() *SliceBoxedUint8 {
	return &ptr.error_msg
}

func (ptr *ResultGenerateSingleWindowPoStWithVanilla) destroy() {
	if ptr != nil {
		C.destroy_generate_single_window_post_with_vanilla_response(ptr)
	}
}

type ResultPoStProof = C.Result_PoStProof_t

func (ptr *ResultPoStProof) statusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.status_code)
}

func (ptr *ResultPoStProof) errorMsg() *SliceBoxedUint8 {
	return &ptr.error_msg
}

func (ptr *ResultPoStProof) destroy() {
	if ptr != nil {
		C.destroy_merge_window_post_partition_proofs_response(ptr)
	}
}
