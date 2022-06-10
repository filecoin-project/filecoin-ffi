package cgo

/*
#cgo LDFLAGS: -L${SRCDIR}/..
#cgo pkg-config: ${SRCDIR}/../filcrypto.pc
#include "../filcrypto.h"
#include <stdlib.h>
*/
import "C"

func CreateFvmMachine(fvmVersion FvmRegisteredVersion, chainEpoch, baseFeeHi, baseFeeLo, baseCircSupplyHi, baseCircSupplyLo, networkVersion uint64, stateRoot SliceRefUint8, manifestCid SliceRefUint8, tracing bool, blockstoreId, externsId uint64) (*FvmMachine, error) {
	resp := C.create_fvm_machine(
		fvmVersion,
		C.uint64_t(chainEpoch),
		C.uint64_t(baseFeeHi),
		C.uint64_t(baseFeeLo),
		C.uint64_t(baseCircSupplyHi),
		C.uint64_t(baseCircSupplyLo),
		C.uint64_t(networkVersion),
		stateRoot,
		manifestCid,
		C.bool(tracing),
		C.uint64_t(blockstoreId),
		C.uint64_t(externsId),
	)
	// take out the pointer from the result to ensure it doesn't get freed
	executor := resp.value
	resp.value = nil
	defer resp.destroy()

	if err := CheckErr(resp); err != nil {
		return nil, err
	}

	return executor, nil
}

func CreateFvmDebugMachine(fvmVersion FvmRegisteredVersion, chainEpoch, baseFeeHi, baseFeeLo, baseCircSupplyHi, baseCircSupplyLo, networkVersion uint64, stateRoot SliceRefUint8, actorRedirect SliceRefUint8, tracing bool, blockstoreId, externsId uint64) (*FvmMachine, error) {
	resp := C.create_fvm_debug_machine(
		fvmVersion,
		C.uint64_t(chainEpoch),
		C.uint64_t(baseFeeHi),
		C.uint64_t(baseFeeLo),
		C.uint64_t(baseCircSupplyHi),
		C.uint64_t(baseCircSupplyLo),
		C.uint64_t(networkVersion),
		stateRoot,
		actorRedirect,
		C.bool(tracing),
		C.uint64_t(blockstoreId),
		C.uint64_t(externsId),
	)
	// take out the pointer from the result to ensure it doesn't get freed
	executor := resp.value
	resp.value = nil
	defer resp.destroy()

	if err := CheckErr(resp); err != nil {
		return nil, err
	}

	return executor, nil
}

func FvmMachineExecuteMessage(executor *FvmMachine, message SliceRefUint8, chainLen, applyKind uint64) (FvmMachineExecuteResponseGo, error) {
	resp := C.fvm_machine_execute_message(
		executor,
		message,
		C.uint64_t(chainLen),
		C.uint64_t(applyKind),
	)
	defer resp.destroy()

	if err := CheckErr(resp); err != nil {
		return FvmMachineExecuteResponseGo{}, err
	}

	return resp.value.copy(), nil
}

func FvmMachineFlush(executor *FvmMachine) ([]byte, error) {
	resp := C.fvm_machine_flush(executor)
	defer resp.destroy()

	if err := CheckErr(resp); err != nil {
		return nil, err
	}
	return resp.value.copy(), nil
}
