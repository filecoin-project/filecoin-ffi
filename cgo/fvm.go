package cgo

/*
#cgo LDFLAGS: -L${SRCDIR}/..
#cgo pkg-config: ${SRCDIR}/../filcrypto.pc
#include "../filcrypto.h"
#include <stdlib.h>

// Reservation session C ABI. These declarations mirror the FVM_BeginReservations
// and FVM_EndReservations exports defined in the Rust FFI.
// Status codes follow the FvmReservationStatus enum:
// 0 = Ok
// 1 = ErrNotImplemented
// 2 = ErrInsufficientFundsAtBegin
// 3 = ErrSessionOpen
// 4 = ErrSessionClosed
// 5 = ErrNonZeroRemainder
// 6 = ErrPlanTooLarge
// 7 = ErrOverflow
// 8 = ErrReservationInvariant
int32_t FVM_BeginReservations(const uint8_t *cbor_plan_ptr, size_t cbor_plan_len, const uint8_t **error_msg_ptr, size_t *error_msg_len);
int32_t FVM_EndReservations(const uint8_t **error_msg_ptr, size_t *error_msg_len);
void FVM_DestroyReservationErrorMessage(uint8_t *error_msg_ptr, size_t error_msg_len);
*/
import "C"
import "unsafe"

func CreateFvmMachine(fvmVersion FvmRegisteredVersion, chainEpoch, chainTimestamp, chainId, baseFeeHi, baseFeeLo, baseCircSupplyHi, baseCircSupplyLo, networkVersion uint64, stateRoot SliceRefUint8, tracing, flushAllBlocks bool, blockstoreId, externsId uint64) (*FvmMachine, error) {
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
		C.bool(flushAllBlocks),
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

func CreateFvmDebugMachine(fvmVersion FvmRegisteredVersion, chainEpoch, chainTimestamp, chainId, baseFeeHi, baseFeeLo, baseCircSupplyHi, baseCircSupplyLo, networkVersion uint64, stateRoot SliceRefUint8, actorRedirect SliceRefUint8, tracing, flushAllBlocks bool, blockstoreId, externsId uint64) (*FvmMachine, error) {
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
		C.bool(flushAllBlocks),
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

// FvmBeginReservations invokes the FVM_BeginReservations C ABI with a CBOR-encoded plan.
// It returns the raw reservation status code as defined by FvmReservationStatus,
// along with an optional, human-readable error message from the engine.
func FvmBeginReservations(plan SliceRefUint8) (int32, string) {
	var msgPtr *C.uint8_t
	var msgLen C.size_t

	status := C.FVM_BeginReservations(plan.ptr, plan.len, &msgPtr, &msgLen)

	if msgPtr == nil || msgLen == 0 {
		return int32(status), ""
	}

	// Copy the message into Go memory and free the FFI allocation.
	msgBytes := C.GoBytes(unsafe.Pointer(msgPtr), C.int(msgLen))
	C.FVM_DestroyReservationErrorMessage(msgPtr, msgLen)

	return int32(status), string(msgBytes)
}

// FvmEndReservations invokes the FVM_EndReservations C ABI and returns the raw status code.
func FvmEndReservations() (int32, string) {
	var msgPtr *C.uint8_t
	var msgLen C.size_t

	status := C.FVM_EndReservations(&msgPtr, &msgLen)

	if msgPtr == nil || msgLen == 0 {
		return int32(status), ""
	}

	msgBytes := C.GoBytes(unsafe.Pointer(msgPtr), C.int(msgLen))
	C.FVM_DestroyReservationErrorMessage(msgPtr, msgLen)

	return int32(status), string(msgBytes)
}
