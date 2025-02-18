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

type FCPResponseStatus = int64

type RegisteredSealProof = C.RegisteredSealProof_t
type RegisteredAggregationProof = C.RegisteredAggregationProof_t
type RegisteredPoStProof = C.RegisteredPoStProof_t
type RegisteredUpdateProof = C.RegisteredUpdateProof_t

type FvmRegisteredVersion = C.FvmRegisteredVersion_t

type AggregationInputs = C.AggregationInputs_t

type PublicReplicaInfo = C.PublicReplicaInfo_t
type PrivateReplicaInfo struct{ delegate C.PrivateReplicaInfo_t }
type PartitionSnarkProof struct{ delegate C.PartitionSnarkProof_t }
type PoStProof struct{ delegate C.PoStProof_t }
type PublicPieceInfo = C.PublicPieceInfo_t

type SliceRefPublicReplicaInfo = C.slice_ref_PublicReplicaInfo_t
type SliceRefPrivateReplicaInfo = C.slice_ref_PrivateReplicaInfo_t
type SliceRefByteArray32 = C.slice_ref_uint8_32_array_t
type SliceRefSliceBoxedUint8 = C.slice_ref_slice_boxed_uint8_t
type SliceRefUint64 = C.slice_ref_uint64_t
type SliceRefPoStProof = C.slice_ref_PoStProof_t
type SliceRefPublicPieceInfo = C.slice_ref_PublicPieceInfo_t
type SliceRefUint8 = C.slice_ref_uint8_t
type SliceRefUint = C.slice_ref_size_t
type SliceRefAggregationInputs = C.slice_ref_AggregationInputs_t

type SliceBoxedPoStProof struct {
	delegate C.struct_slice_boxed_PoStProof
}
type SliceBoxedUint64 struct{ delegate C.struct_slice_boxed_uint64 }
type SliceBoxedSliceBoxedUint8 struct {
	delegate C.slice_boxed_slice_boxed_uint8_t
}
type SliceBoxedSliceBoxedUint64 struct {
	delegate C.slice_boxed_slice_boxed_uint64_t
}
type SliceBoxedUint8 struct{ delegate C.struct_slice_boxed_uint8 }

type ByteArray32 struct{ delegate *C.uint8_32_array_t }
type ByteArray48 struct{ delegate *C.uint8_48_array_t }
type ByteArray96 struct{ delegate *C.uint8_96_array_t }

type FvmMachine struct{ delegate *C.InnerFvmMachine_t }
type FvmMachineExecuteResponse struct {
	delegate *C.FvmMachineExecuteResponse_t
}

type resultBool struct{ delegate *C.Result_bool_t }
type resultGeneratePieceCommitment struct {
	delegate *C.Result_GeneratePieceCommitment_t
}
type resultWriteWithAlignment struct {
	delegate *C.Result_WriteWithAlignment_t
}
type resultWriteWithoutAlignment struct {
	delegate *C.Result_WriteWithoutAlignment_t
}
type resultByteArray32 struct{ delegate *C.Result_uint8_32_array_t }
type resultVoid struct{ delegate *C.Result_void_t }
type resultSealPreCommitPhase2 struct {
	delegate *C.Result_SealPreCommitPhase2_t
}
type resultSliceBoxedUint8 struct{ delegate *C.Result_slice_boxed_uint8_t }
type resultSliceBoxedPoStProof struct {
	delegate *C.Result_slice_boxed_PoStProof_t
}
type resultSliceBoxedUint64 struct {
	delegate *C.Result_slice_boxed_uint64_t
}
type resultUint struct{ delegate *C.Result_size_t }
type resultSliceBoxedSliceBoxedUint8 struct {
	delegate *C.Result_slice_boxed_slice_boxed_uint8_t
}
type resultGenerateWindowPoSt struct {
	delegate *C.Result_GenerateWindowPoSt_t
}
type resultEmptySectorUpdateEncodeInto struct {
	delegate *C.Result_EmptySectorUpdateEncodeInto_t
}
type resultGenerateFallbackSectorChallenges struct {
	delegate *C.Result_GenerateFallbackSectorChallenges_t
}
type resultGenerateSingleWindowPoStWithVanilla struct {
	delegate *C.Result_GenerateSingleWindowPoStWithVanilla_t
}
type resultPoStProof struct{ delegate *C.Result_PoStProof_t }

type resultFvmMachine struct {
	delegate *C.Result_InnerFvmMachine_ptr_t
}
type resultFvmMachineExecuteResponse struct {
	delegate *C.Result_FvmMachineExecuteResponse_t
}

type result interface {
	statusCode() FCPResponseStatus
	errorMsg() *SliceBoxedUint8
	destroy()
}

// PartitionSnarkProofGo is a go allocated version of `PartitionSnarkProof`.
type PartitionSnarkProofGo struct {
	RegisteredProof RegisteredPoStProof
	Proof           []byte
}

// PoStProofGo is a go allocated version of `PoStProof`.
type PoStProofGo struct {
	RegisteredProof RegisteredPoStProof
	Proof           []byte
}

// FvmMachineExecuteResponse is a go allocated version of `FvmMachineExecuteResponse`.
type FvmMachineExecuteResponseGo struct {
	ExitCode             uint64
	ReturnVal            []byte
	GasUsed              uint64
	PenaltyHi            uint64
	PenaltyLo            uint64
	MinerTipHi           uint64
	MinerTipLo           uint64
	BaseFeeBurnHi        uint64
	BaseFeeBurnLo        uint64
	OverEstimationBurnHi uint64
	OverEstimationBurnLo uint64
	RefundHi             uint64
	RefundLo             uint64
	GasRefund            int64
	GasBurned            int64
	ExecTrace            []byte
	FailureInfo          string
	Events               []byte
	EventsRoot           []byte
}

func (ptr SliceBoxedUint8) slice() []byte {
	if ptr.delegate.ptr == nil {
		return nil
	}
	return unsafe.Slice((*byte)(ptr.delegate.ptr), int(ptr.delegate.len))
}

func (ptr SliceBoxedUint8) copy() []byte {
	if ptr.delegate.ptr == nil {
		return nil
	} else if ptr.delegate.len == 0 {
		return []byte{}
	}

	res := make([]byte, int(ptr.delegate.len))
	copy(res, ptr.slice())
	return res
}

func (ptr *resultBool) statusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.delegate.status_code)
}

func (ptr *resultBool) errorMsg() *SliceBoxedUint8 {
	return &SliceBoxedUint8{delegate: ptr.delegate.error_msg}
}

func (ptr *resultBool) destroy() {
	if ptr != nil && ptr.delegate != nil {
		// TODO: correct naming
		C.destroy_verify_seal_response(ptr.delegate)
		ptr.delegate = nil
	}
}

func (ptr *PoStProof) registeredProof() RegisteredPoStProof {
	return ptr.delegate.registered_proof
}

func (ptr *PoStProof) destroy() {
	if ptr != nil {
		proof := &SliceBoxedUint8{delegate: ptr.delegate.proof}
		proof.Destroy()
		ptr = nil
	}
}

func (ptr *ByteArray96) destroy() {
	if ptr != nil || ptr.delegate == nil {
		C.destroy_box_bls_digest(ptr.delegate)
		ptr = nil
	}
}

func (ptr ByteArray96) slice() []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(&ptr.delegate.idx[0])), 96)
}

func (ptr *ByteArray96) copyAsArray() *[96]byte {
	if ptr == nil || ptr.delegate == nil {
		return nil
	}
	var res [96]byte
	copy(res[:], ptr.slice())
	return &res
}

func (ptr ByteArray48) slice() []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(&ptr.delegate.idx[0])), 48)
}

func (ptr *ByteArray48) copyAsArray() *[48]byte {
	if ptr == nil || ptr.delegate == nil {
		return nil
	}
	var res [48]byte
	copy(res[:], ptr.slice())
	return &res
}

func (ptr *ByteArray48) destroy() {
	if ptr != nil && ptr.delegate != nil {
		c := &ptr.delegate
		C.destroy_box_bls_public_key(*c)
		ptr = nil
	}
}

func (ptr ByteArray32) slice() []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(&ptr.delegate.idx[0])), 32)
}

func (ptr *ByteArray32) copy() []byte {
	res := make([]byte, 32)
	if ptr != nil {
		copy(res, ptr.slice())
	}
	return res
}

func (ptr *ByteArray32) copyAsArray() *[32]byte {
	if ptr == nil || ptr.delegate == nil {
		return nil
	}
	var res [32]byte
	copy(res[:], ptr.slice())
	return &res
}

func (ptr *ByteArray32) destroy() {
	if ptr != nil && ptr.delegate != nil {
		c := &ptr.delegate
		C.destroy_box_bls_private_key(*c)
		ptr = nil
	}
}

func (ptr *resultGeneratePieceCommitment) statusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.delegate.status_code)
}

func (ptr *resultGeneratePieceCommitment) errorMsg() *SliceBoxedUint8 {
	return &SliceBoxedUint8{delegate: ptr.delegate.error_msg}
}

func (ptr *resultGeneratePieceCommitment) destroy() {
	if ptr != nil && ptr.delegate != nil {
		C.destroy_generate_piece_commitment_response(ptr.delegate)
		ptr.delegate = nil
	}
}

func (ptr *resultByteArray32) statusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.delegate.status_code)
}

func (ptr *resultByteArray32) errorMsg() *SliceBoxedUint8 {
	return &SliceBoxedUint8{delegate: ptr.delegate.error_msg}
}

func (ptr *resultByteArray32) destroy() {
	if ptr != nil && ptr.delegate != nil {
		// TODO: better naming
		C.destroy_generate_data_commitment_response(ptr.delegate)
		ptr.delegate = nil
	}
}

func (ptr *resultWriteWithAlignment) statusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.delegate.status_code)
}

func (ptr *resultWriteWithAlignment) errorMsg() *SliceBoxedUint8 {
	return &SliceBoxedUint8{delegate: ptr.delegate.error_msg}
}

func (ptr *resultWriteWithAlignment) destroy() {
	if ptr != nil && ptr.delegate != nil {
		C.destroy_write_with_alignment_response(ptr.delegate)
		ptr.delegate = nil
	}
}

func (ptr *resultWriteWithoutAlignment) statusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.delegate.status_code)
}

func (ptr *resultWriteWithoutAlignment) errorMsg() *SliceBoxedUint8 {
	return &SliceBoxedUint8{delegate: ptr.delegate.error_msg}
}

func (ptr *resultWriteWithoutAlignment) destroy() {
	if ptr != nil && ptr.delegate != nil {
		C.destroy_write_without_alignment_response(ptr.delegate)
		ptr.delegate = nil
	}
}

func (ptr *resultSliceBoxedUint8) statusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.delegate.status_code)
}

func (ptr *resultSliceBoxedUint8) errorMsg() *SliceBoxedUint8 {
	return &SliceBoxedUint8{delegate: ptr.delegate.error_msg}
}

func (ptr *resultSliceBoxedUint8) destroy() {
	if ptr != nil && ptr.delegate != nil {
		// TODO: naming
		C.destroy_seal_pre_commit_phase1_response(ptr.delegate)
		ptr.delegate = nil
	}
}

func (ptr *resultSealPreCommitPhase2) statusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.delegate.status_code)
}

func (ptr *resultSealPreCommitPhase2) errorMsg() *SliceBoxedUint8 {
	return &SliceBoxedUint8{delegate: ptr.delegate.error_msg}
}

func (ptr *resultSealPreCommitPhase2) destroy() {
	if ptr != nil && ptr.delegate != nil {
		C.destroy_seal_pre_commit_phase2_response(ptr.delegate)
		ptr.delegate = nil
	}
}

func (ptr *resultVoid) statusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.delegate.status_code)
}

func (ptr *resultVoid) errorMsg() *SliceBoxedUint8 {
	return &SliceBoxedUint8{delegate: ptr.delegate.error_msg}
}

func (ptr *resultVoid) destroy() {
	if ptr != nil && ptr.delegate != nil {
		// TODO: correct naming
		C.destroy_unseal_range_response(ptr.delegate)
		ptr.delegate = nil
	}
}

func (ptr SliceBoxedUint64) slice() []uint64 {
	if ptr.delegate.ptr == nil {
		return nil
	}
	return unsafe.Slice((*uint64)(unsafe.Pointer(ptr.delegate.ptr)), int(ptr.delegate.len))
}

func (ptr SliceBoxedUint64) copy() []uint64 {
	if ptr.delegate.ptr == nil {
		return nil
	} else if ptr.delegate.len == 0 {
		return []uint64{}
	}

	res := make([]uint64, int(ptr.delegate.len))
	copy(res, ptr.slice())
	return res
}

func (ptr *resultSliceBoxedUint64) statusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.delegate.status_code)
}

func (ptr *resultSliceBoxedUint64) errorMsg() *SliceBoxedUint8 {
	return &SliceBoxedUint8{delegate: ptr.delegate.error_msg}
}

func (ptr *resultSliceBoxedUint64) destroy() {
	if ptr != nil && ptr.delegate != nil {
		// TODO: correct naming
		C.destroy_generate_winning_post_sector_challenge(ptr.delegate)
		ptr.delegate = nil
	}
}

func (ptr SliceBoxedPoStProof) slice() []PoStProof {
	if ptr.delegate.ptr == nil {
		return nil
	}
	return unsafe.Slice((*PoStProof)(unsafe.Pointer(ptr.delegate.ptr)), int(ptr.delegate.len))
}

func (ptr SliceBoxedPoStProof) copy() []PoStProofGo {
	if ptr.delegate.ptr == nil {
		return nil
	} else if ptr.delegate.len == 0 {
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
		RegisteredProof: proof.registeredProof(),
		Proof:           SliceBoxedUint8{delegate: proof.delegate.proof}.copy(),
	}
}

func (ptr *resultSliceBoxedPoStProof) statusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.delegate.status_code)
}

func (ptr *resultSliceBoxedPoStProof) errorMsg() *SliceBoxedUint8 {
	return &SliceBoxedUint8{delegate: ptr.delegate.error_msg}
}

func (ptr *resultSliceBoxedPoStProof) destroy() {
	if ptr != nil && ptr.delegate != nil {
		// TODO: correct naming
		C.destroy_generate_winning_post_response(ptr.delegate)
		ptr.delegate = nil
	}
}

func (ptr *resultGenerateWindowPoSt) statusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.delegate.status_code)
}

func (ptr *resultGenerateWindowPoSt) errorMsg() *SliceBoxedUint8 {
	return &SliceBoxedUint8{delegate: ptr.delegate.error_msg}
}

func (ptr *resultGenerateWindowPoSt) destroy() {
	if ptr != nil && ptr.delegate != nil {
		C.destroy_generate_window_post_response(ptr.delegate)
		ptr.delegate = nil
	}
}

func (ptr SliceBoxedSliceBoxedUint8) slice() []SliceBoxedUint8 {
	if ptr.delegate.ptr == nil {
		return nil
	}
	return unsafe.Slice((*SliceBoxedUint8)(unsafe.Pointer(ptr.delegate.ptr)), int(ptr.delegate.len))
}

func (ptr SliceBoxedSliceBoxedUint8) copyAsBytes() [][]byte {
	if ptr.delegate.ptr == nil {
		return nil
	} else if ptr.delegate.len == 0 {
		return [][]byte{}
	}

	ref := ptr.slice()
	res := make([][]byte, int(ptr.delegate.len))
	for i := range ref {
		res[i] = ref[i].copy()
	}

	return res
}

func (ptr SliceBoxedSliceBoxedUint8) copyAsStrings() []string {
	if ptr.delegate.ptr == nil {
		return nil
	} else if ptr.delegate.len == 0 {
		return []string{}
	}
	ref := ptr.slice()
	res := make([]string, int(ptr.delegate.len))
	for i := range ref {
		res[i] = string(ref[i].copy())
	}

	return res
}

func (ptr *resultSliceBoxedSliceBoxedUint8) statusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.delegate.status_code)
}

func (ptr *resultSliceBoxedSliceBoxedUint8) errorMsg() *SliceBoxedUint8 {
	return &SliceBoxedUint8{delegate: ptr.delegate.error_msg}
}

func (ptr *resultSliceBoxedSliceBoxedUint8) destroy() {
	if ptr != nil && ptr.delegate != nil {
		// TODO: naming
		C.destroy_generate_empty_sector_update_partition_proof_response(ptr.delegate)
		ptr.delegate = nil
	}
}

func (ptr *resultUint) statusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.delegate.status_code)
}

func (ptr *resultUint) errorMsg() *SliceBoxedUint8 {
	return &SliceBoxedUint8{delegate: ptr.delegate.error_msg}
}

func (ptr *resultUint) destroy() {
	if ptr != nil && ptr.delegate != nil {
		// TODO: naming
		C.destroy_get_num_partition_for_fallback_post_response(ptr.delegate)
		ptr.delegate = nil
	}
}

func (ptr *resultEmptySectorUpdateEncodeInto) statusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.delegate.status_code)
}

func (ptr *resultEmptySectorUpdateEncodeInto) errorMsg() *SliceBoxedUint8 {
	return &SliceBoxedUint8{delegate: ptr.delegate.error_msg}
}

func (ptr *resultEmptySectorUpdateEncodeInto) destroy() {
	if ptr != nil && ptr.delegate != nil {
		C.destroy_empty_sector_update_encode_into_response(ptr.delegate)
		ptr.delegate = nil
	}
}

func (ptr SliceBoxedSliceBoxedUint64) slice() []SliceBoxedUint64 {
	if ptr.delegate.ptr == nil {
		return nil
	}
	return unsafe.Slice((*SliceBoxedUint64)(unsafe.Pointer(ptr.delegate.ptr)), int(ptr.delegate.len))
}

func (ptr SliceBoxedSliceBoxedUint64) copy() [][]uint64 {
	if ptr.delegate.ptr == nil {
		return nil
	} else if ptr.delegate.len == 0 {
		return [][]uint64{}
	}

	ref := ptr.slice()
	res := make([][]uint64, int(ptr.delegate.len))
	for i := range ref {
		res[i] = ref[i].copy()
	}

	return res
}

func (ptr *resultGenerateFallbackSectorChallenges) statusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.delegate.status_code)
}

func (ptr *resultGenerateFallbackSectorChallenges) errorMsg() *SliceBoxedUint8 {
	return &SliceBoxedUint8{delegate: ptr.delegate.error_msg}
}

func (ptr *resultGenerateFallbackSectorChallenges) destroy() {
	if ptr != nil && ptr.delegate != nil {
		C.destroy_generate_fallback_sector_challenges_response(ptr.delegate)
		ptr.delegate = nil
	}
}

func (proof PartitionSnarkProof) copy() PartitionSnarkProofGo {
	return PartitionSnarkProofGo{
		RegisteredProof: proof.delegate.registered_proof,
		Proof:           SliceBoxedUint8{delegate: proof.delegate.proof}.copy(),
	}
}

func (ptr *resultGenerateSingleWindowPoStWithVanilla) statusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.delegate.status_code)
}

func (ptr *resultGenerateSingleWindowPoStWithVanilla) errorMsg() *SliceBoxedUint8 {
	return &SliceBoxedUint8{delegate: ptr.delegate.error_msg}
}

func (ptr *resultGenerateSingleWindowPoStWithVanilla) destroy() {
	if ptr != nil && ptr.delegate != nil {
		C.destroy_generate_single_window_post_with_vanilla_response(ptr.delegate)
		ptr.delegate = nil
	}
}

func (ptr *resultPoStProof) statusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.delegate.status_code)
}

func (ptr *resultPoStProof) errorMsg() *SliceBoxedUint8 {
	return &SliceBoxedUint8{delegate: ptr.delegate.error_msg}
}

func (ptr *resultPoStProof) destroy() {
	if ptr != nil && ptr.delegate != nil {
		C.destroy_merge_window_post_partition_proofs_response(ptr.delegate)
		ptr.delegate = nil
	}
}

func (ptr *SliceBoxedUint8) Destroy() {
	if ptr != nil && ptr.delegate.ptr != nil {
		C.destroy_boxed_slice(ptr.delegate)
		ptr.delegate.ptr = nil
	}
}

func (ptr *PrivateReplicaInfo) Destroy() {
	if ptr != nil {
		cacheDirPath := SliceBoxedUint8{delegate: ptr.delegate.cache_dir_path}
		cacheDirPath.Destroy()
		replicaPath := SliceBoxedUint8{delegate: ptr.delegate.replica_path}
		replicaPath.Destroy()
		ptr = nil
	}
}

func (ptr *PoStProof) Destroy() {
	if ptr != nil {
		ptr.destroy()
		ptr = nil
	}
}

func (ptr *resultFvmMachineExecuteResponse) statusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.delegate.status_code)
}

func (ptr *resultFvmMachineExecuteResponse) errorMsg() *SliceBoxedUint8 {
	return &SliceBoxedUint8{delegate: ptr.delegate.error_msg}
}

func (ptr *resultFvmMachineExecuteResponse) destroy() {
	if ptr != nil && ptr.delegate != nil {
		C.destroy_fvm_machine_execute_response(ptr.delegate)
		ptr.delegate = nil
	}
}

func (ptr *resultFvmMachine) statusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.delegate.status_code)
}

func (ptr *resultFvmMachine) errorMsg() *SliceBoxedUint8 {
	return &SliceBoxedUint8{delegate: ptr.delegate.error_msg}
}

func (ptr *resultFvmMachine) destroy() {
	if ptr != nil && ptr.delegate != nil {
		C.destroy_create_fvm_machine_response(ptr.delegate)
		ptr.delegate = nil
	}
}

func (ptr *FvmMachine) Destroy() {
	if ptr != nil && ptr.delegate != nil {
		C.drop_fvm_machine(ptr.delegate)
		ptr.delegate = nil
	}
}

func (r FvmMachineExecuteResponse) copy() FvmMachineExecuteResponseGo {
	return FvmMachineExecuteResponseGo{
		ExitCode:             uint64(r.delegate.exit_code),
		ReturnVal:            SliceBoxedUint8{delegate: r.delegate.return_val}.copy(),
		GasUsed:              uint64(r.delegate.gas_used),
		PenaltyHi:            uint64(r.delegate.penalty_hi),
		PenaltyLo:            uint64(r.delegate.penalty_lo),
		MinerTipHi:           uint64(r.delegate.miner_tip_hi),
		MinerTipLo:           uint64(r.delegate.miner_tip_lo),
		BaseFeeBurnHi:        uint64(r.delegate.base_fee_burn_hi),
		BaseFeeBurnLo:        uint64(r.delegate.base_fee_burn_lo),
		OverEstimationBurnHi: uint64(r.delegate.over_estimation_burn_hi),
		OverEstimationBurnLo: uint64(r.delegate.over_estimation_burn_lo),
		RefundHi:             uint64(r.delegate.refund_hi),
		RefundLo:             uint64(r.delegate.refund_lo),
		GasRefund:            int64(r.delegate.gas_refund),
		GasBurned:            int64(r.delegate.gas_burned),
		ExecTrace:            SliceBoxedUint8{delegate: r.delegate.exec_trace}.copy(),
		FailureInfo:          string(SliceBoxedUint8{delegate: r.delegate.failure_info}.slice()),
		Events:               SliceBoxedUint8{delegate: r.delegate.events}.copy(),
		EventsRoot:           SliceBoxedUint8{delegate: r.delegate.events_root}.copy(),
	}
}
