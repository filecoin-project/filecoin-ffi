package cgo

// #cgo linux LDFLAGS: ${SRCDIR}/../libfilcrypto.a -Wl,-unresolved-symbols=ignore-all
// #cgo darwin LDFLAGS: ${SRCDIR}/../libfilcrypto.a -Wl,-undefined,dynamic_lookup
// #cgo pkg-config: ${SRCDIR}/../filcrypto.pc
// #include "../filcrypto.h"
// // Provide fallbacks when FVM is not compiled into filcrypto
// #ifndef FVM_ERROR_INVALID_HANDLE
// #define FVM_ERROR_INVALID_HANDLE -1
// #endif
// #ifndef FVM_ERROR_NOT_FOUND
// #define FVM_ERROR_NOT_FOUND -2
// #endif
// #ifndef FVM_ERROR_IO
// #define FVM_ERROR_IO -3
// #endif
// #ifndef FVM_ERROR_INVALID_ARGUMENT
// #define FVM_ERROR_INVALID_ARGUMENT -4
// #endif
// #ifndef FVM_ERROR_PANIC
// #define FVM_ERROR_PANIC -5
// #endif
import "C"
import (
	"fmt"
	"os"
	"runtime/debug"
)

const (
	ErrInvalidHandle   = C.FVM_ERROR_INVALID_HANDLE
	ErrNotFound        = C.FVM_ERROR_NOT_FOUND
	ErrIO              = C.FVM_ERROR_IO
	ErrInvalidArgument = C.FVM_ERROR_INVALID_ARGUMENT
	ErrPanic           = C.FVM_ERROR_PANIC
)

func logPanic(err interface{}) {
	fmt.Fprintf(os.Stderr, "panic in cgo externs: %s\n", err)
	debug.PrintStack()
}
