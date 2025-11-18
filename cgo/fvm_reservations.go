package cgo

/*
#cgo LDFLAGS: -L${SRCDIR}/..
#cgo pkg-config: ${SRCDIR}/../filcrypto.pc
#include "../filcrypto.h"
#include <stdlib.h>
*/
import "C"
import "unsafe"

func FvmBeginReservations(plan []byte) int32 {
	var ptr *C.uint8_t
	var length C.size_t

	if len(plan) == 0 {
		ptr = &emptyUint8
		length = 0
	} else {
		ptr = (*C.uint8_t)(unsafe.Pointer(&plan[0]))
		length = C.size_t(len(plan))
	}

	return int32(C.FVM_BeginReservations(ptr, length))
}

func FvmEndReservations() int32 {
	return int32(C.FVM_EndReservations())
}
