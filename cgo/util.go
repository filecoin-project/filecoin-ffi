package cgo

/*
#cgo LDFLAGS: -L${SRCDIR}/..
#cgo pkg-config: ${SRCDIR}/../filcrypto.pc
#include "../filcrypto.h"
#include <stdlib.h>
*/
import "C"

func InitLogFd(fd int32) error {
	resp := &resultVoid{delegate: C.init_log_fd(C.int32_t(fd))}
	defer resp.destroy()
	return CheckErr(resp)
}
