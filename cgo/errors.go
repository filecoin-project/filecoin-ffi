package cgo

// #cgo linux LDFLAGS: ${SRCDIR}/../libfilcrypto.a -Wl,-unresolved-symbols=ignore-all
// #cgo darwin LDFLAGS: ${SRCDIR}/../libfilcrypto.a -Wl,-undefined,dynamic_lookup
// #cgo pkg-config: ${SRCDIR}/../filcrypto.pc
// #include "../filcrypto.h"
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
