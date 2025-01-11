package cgo

/*
#cgo LDFLAGS: -L${SRCDIR}/..
#cgo pkg-config: ${SRCDIR}/../filcrypto.pc
#include "../filcrypto.h"
#include <stdlib.h>
*/
import "C"

func CreateFvmMachine(fvmVersion FvmRegisteredVersion, chainEpoch, chainTimestamp, chainId, baseFeeHi, baseFeeLo, baseCircSupplyHi, baseCircSupplyLo, networkVersion uint64, stateRoot SliceRefUint8, tracing bool, blockstoreId, externsId uint64) (*FvmMachine, error) {
	resp := (*resultFvmMachine)(C.create_fvm_machine(
		(C.FvmRegisteredVersion_t)(fvmVersion),
		C.uint64_t(chainEpoch),
		C.uint64_t(chainTimestamp),
		C.uint64_t(chainId),
		C.uint64_t(baseFeeHi),
		C.uint64_t(baseFeeLo),
		C.uint64_t(baseCircSupplyHi),
		C.uint64_t(baseCircSupplyLo),
		C.uint32_t(networkVersion),
		(C.slice_ref_uint8_t)(stateRoot),
		C.bool(tracing),
		C.uint64_t(blockstoreId),
		C.uint64_t(externsId),
	))
	// take out the pointer from the result to ensure it doesn't get freed
	executor := (*FvmMachine)(resp.value)
	resp.value = nil
	defer resp.destroy()

	if err := CheckErr(resp); err != nil {
		return nil, err
	}

	return executor, nil
}

func CreateFvmDebugMachine(fvmVersion FvmRegisteredVersion, chainEpoch, chainTimestamp, chainId, baseFeeHi, baseFeeLo, baseCircSupplyHi, baseCircSupplyLo, networkVersion uint64, stateRoot SliceRefUint8, actorRedirect SliceRefUint8, tracing bool, blockstoreId, externsId uint64) (*FvmMachine, error) {
	resp := (*resultFvmMachine)(C.create_fvm_debug_machine(
		(C.FvmRegisteredVersion_t)(fvmVersion),
		C.uint64_t(chainEpoch),
		C.uint64_t(chainTimestamp),
		C.uint64_t(chainId),
		C.uint64_t(baseFeeHi),
		C.uint64_t(baseFeeLo),
		C.uint64_t(baseCircSupplyHi),
		C.uint64_t(baseCircSupplyLo),
		C.uint32_t(networkVersion),
		(C.slice_ref_uint8_t)(stateRoot),
		(C.slice_ref_uint8_t)(actorRedirect),
		C.bool(tracing),
		C.uint64_t(blockstoreId),
		C.uint64_t(externsId),
	))
	// take out the pointer from the result to ensure it doesn't get freed
	executor := (*FvmMachine)(resp.value)
	resp.value = nil
	defer resp.destroy()

	if err := CheckErr(resp); err != nil {
		return nil, err
	}

	return executor, nil
}

func FvmMachineExecuteMessage(executor *FvmMachine, message SliceRefUint8, chainLen, applyKind uint64) (FvmMachineExecuteResponseGo, error) {
	resp := (*resultFvmMachineExecuteResponse)(C.fvm_machine_execute_message(
		(*C.InnerFvmMachine_t)(executor),
		(C.slice_ref_uint8_t)(message),
		C.uint64_t(chainLen),
		C.uint64_t(applyKind),
	))
	defer resp.destroy()

	if err := CheckErr(resp); err != nil {
		return FvmMachineExecuteResponseGo{}, err
	}

	return (FvmMachineExecuteResponse)(resp.value).copy(), nil
}

func FvmMachineFlush(executor *FvmMachine) ([]byte, error) {
	resp := (*resultSliceBoxedUint8)(C.fvm_machine_flush((*C.InnerFvmMachine_t)(executor)))
	defer resp.destroy()

	if err := CheckErr(resp); err != nil {
		return nil, err
	}
	return (SliceBoxedUint8)(resp.value).copy(), nil
}

func FvmMachineDumpCache(executor *FvmMachine, blockstoreId uint64) error {
	resp := C.fvm_machine_dump_cache(executor, C.uint64_t(blockstoreId))
	defer resp.destroy()

	return CheckErr(resp)
}
