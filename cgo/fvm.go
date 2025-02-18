package cgo

/*
#cgo LDFLAGS: -L${SRCDIR}/..
#cgo pkg-config: ${SRCDIR}/../filcrypto.pc
#include "../filcrypto.h"
#include <stdlib.h>
*/
import "C"

func CreateFvmMachine(fvmVersion FvmRegisteredVersion, chainEpoch, chainTimestamp, chainId, baseFeeHi, baseFeeLo, baseCircSupplyHi, baseCircSupplyLo, networkVersion uint64, stateRoot SliceRefUint8, tracing bool, blockstoreId, externsId uint64) (*FvmMachine, error) {
	resp := &resultFvmMachine{
		delegate: C.create_fvm_machine(
			fvmVersion,
			C.uint64_t(chainEpoch),
			C.uint64_t(chainTimestamp),
			C.uint64_t(chainId),
			C.uint64_t(baseFeeHi),
			C.uint64_t(baseFeeLo),
			C.uint64_t(baseCircSupplyHi),
			C.uint64_t(baseCircSupplyLo),
			C.uint32_t(networkVersion),
			stateRoot,
			C.bool(tracing),
			C.uint64_t(blockstoreId),
			C.uint64_t(externsId),
		),
	}
	// take out the pointer from the result to ensure it doesn't get freed
	executor := resp.delegate.value
	resp.delegate.value = nil
	defer resp.destroy()

	if err := CheckErr(resp); err != nil {
		return nil, err
	}

	return &FvmMachine{delegate: executor}, nil
}

func CreateFvmDebugMachine(fvmVersion FvmRegisteredVersion, chainEpoch, chainTimestamp, chainId, baseFeeHi, baseFeeLo, baseCircSupplyHi, baseCircSupplyLo, networkVersion uint64, stateRoot SliceRefUint8, actorRedirect SliceRefUint8, tracing bool, blockstoreId, externsId uint64) (*FvmMachine, error) {
	resp := &resultFvmMachine{
		delegate: C.create_fvm_debug_machine(
			fvmVersion,
			C.uint64_t(chainEpoch),
			C.uint64_t(chainTimestamp),
			C.uint64_t(chainId),
			C.uint64_t(baseFeeHi),
			C.uint64_t(baseFeeLo),
			C.uint64_t(baseCircSupplyHi),
			C.uint64_t(baseCircSupplyLo),
			C.uint32_t(networkVersion),
			stateRoot,
			actorRedirect,
			C.bool(tracing),
			C.uint64_t(blockstoreId),
			C.uint64_t(externsId),
		),
	}
	// take out the pointer from the result to ensure it doesn't get freed
	executor := resp.delegate.value
	resp.delegate.value = nil
	defer resp.destroy()

	if err := CheckErr(resp); err != nil {
		return nil, err
	}

	return &FvmMachine{delegate: executor}, nil
}

func FvmMachineExecuteMessage(executor *FvmMachine, message SliceRefUint8, chainLen, applyKind uint64) (FvmMachineExecuteResponseGo, error) {
	resp := &resultFvmMachineExecuteResponse{
		delegate: C.fvm_machine_execute_message(
			executor.delegate,
			message,
			C.uint64_t(chainLen),
			C.uint64_t(applyKind),
		),
	}
	defer resp.destroy()

	if err := CheckErr(resp); err != nil {
		return FvmMachineExecuteResponseGo{}, err
	}

	response := &FvmMachineExecuteResponse{delegate: &resp.delegate.value}
	return response.copy(), nil
}

func FvmMachineFlush(executor *FvmMachine) ([]byte, error) {
	resp := &resultSliceBoxedUint8{delegate: C.fvm_machine_flush(executor.delegate)}
	defer resp.destroy()

	if err := CheckErr(resp); err != nil {
		return nil, err
	}
	return SliceBoxedUint8{delegate: resp.delegate.value}.copy(), nil
}
