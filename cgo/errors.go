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
	ErrInvalidHandle   = C.ERR_INVALID_HANDLE
	ErrNotFound        = C.ERR_NOT_FOUND
	ErrIO              = C.ERR_IO
	ErrInvalidArgument = C.ERR_INVALID_ARGUMENT
	ErrPanic           = C.ERR_PANIC
)

func logPanic(err interface{}) {
	fmt.Fprintf(os.Stderr, "panic in cgo externs: %s\n", err)
	debug.PrintStack()
}
