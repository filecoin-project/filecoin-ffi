package cgo

/*
#cgo LDFLAGS: -L${SRCDIR}/.. -lfilcrypto
#cgo pkg-config: ${SRCDIR}/../filcrypto.pc
#include "../filcrypto.h"
#include <stdlib.h>
*/
import "C"
