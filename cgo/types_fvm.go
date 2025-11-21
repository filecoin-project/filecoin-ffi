//go:build fvm

package cgo

/*
#cgo LDFLAGS: -L${SRCDIR}/..
#cgo pkg-config: ${SRCDIR}/../filcrypto.pc
#include "../filcrypto.h"
#include <stdlib.h>
*/
import "C"

type FvmRegisteredVersion C.FvmRegisteredVersion_t

type FvmMachine C.InnerFvmMachine_t
type FvmMachineExecuteResponse C.FvmMachineExecuteResponse_t

type resultFvmMachine C.Result_InnerFvmMachine_ptr_t
type resultFvmMachineExecuteResponse C.Result_FvmMachineExecuteResponse_t

func (ptr *resultFvmMachineExecuteResponse) statusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.status_code)
}

func (ptr *resultFvmMachineExecuteResponse) errorMsg() *SliceBoxedUint8 {
	return (*SliceBoxedUint8)(&ptr.error_msg)
}

func (ptr *resultFvmMachineExecuteResponse) destroy() {
	if ptr != nil {
		C.destroy_fvm_machine_execute_response((*C.Result_FvmMachineExecuteResponse_t)(ptr))
		ptr = nil
	}
}

func (ptr *resultFvmMachine) statusCode() FCPResponseStatus {
	return FCPResponseStatus(ptr.status_code)
}

func (ptr *resultFvmMachine) errorMsg() *SliceBoxedUint8 {
	return (*SliceBoxedUint8)(&ptr.error_msg)
}

func (ptr *resultFvmMachine) destroy() {
	if ptr != nil {
		C.destroy_create_fvm_machine_response((*C.Result_InnerFvmMachine_ptr_t)(ptr))
		ptr = nil
	}
}

func (ptr *FvmMachine) Destroy() {
	if ptr != nil {
		C.drop_fvm_machine((*C.InnerFvmMachine_t)(ptr))
		ptr = nil
	}
}

func (r FvmMachineExecuteResponse) copy() FvmMachineExecuteResponseGo {
	return FvmMachineExecuteResponseGo{
		ExitCode:             uint64(r.exit_code),
		ReturnVal:            (*SliceBoxedUint8)(&r.return_val).copy(),
		GasUsed:              uint64(r.gas_used),
		PenaltyHi:            uint64(r.penalty_hi),
		PenaltyLo:            uint64(r.penalty_lo),
		MinerTipHi:           uint64(r.miner_tip_hi),
		MinerTipLo:           uint64(r.miner_tip_lo),
		BaseFeeBurnHi:        uint64(r.base_fee_burn_hi),
		BaseFeeBurnLo:        uint64(r.base_fee_burn_lo),
		OverEstimationBurnHi: uint64(r.over_estimation_burn_hi),
		OverEstimationBurnLo: uint64(r.over_estimation_burn_lo),
		RefundHi:             uint64(r.refund_hi),
		RefundLo:             uint64(r.refund_lo),
		GasRefund:            int64(r.gas_refund),
		GasBurned:            int64(r.gas_burned),
		ExecTrace:            (*SliceBoxedUint8)(&r.exec_trace).copy(),
		FailureInfo:          string((*SliceBoxedUint8)(&r.failure_info).slice()),
		Events:               (*SliceBoxedUint8)(&r.events).copy(),
		EventsRoot:           (*SliceBoxedUint8)(&r.events_root).copy(),
	}
}
