package cgo

/*
#cgo LDFLAGS: -L${SRCDIR}/..
#cgo pkg-config: ${SRCDIR}/../filcrypto.pc
#include "../filcrypto.h"
#include <stdlib.h>
*/
import "C"
import (
	"errors"
	"unsafe"
)

func AsSliceRefUint8(goBytes []byte) SliceRefUint8 {
	len := len(goBytes)

	if len == 0 {
		// can't take element 0 of an empty slice
		return SliceRefUint8{
			ptr: (*C.uint8_t)(unsafe.Pointer(&goBytes)),
			len: C.size_t(len),
		}
	}
	return SliceRefUint8{
		ptr: (*C.uint8_t)(unsafe.Pointer(&goBytes[0])),
		len: C.size_t(len),
	}
}

func AsSliceRefUint(goSlice []uint) SliceRefUint {
	len := len(goSlice)

	if len == 0 {
		// can't take element 0 of an empty slice
		return SliceRefUint{
			ptr: (*C.size_t)(unsafe.Pointer(&goSlice)),
			len: C.size_t(len),
		}
	}

	return SliceRefUint{
		ptr: (*C.size_t)(unsafe.Pointer(&goSlice[0])),
		len: C.size_t(len),
	}
}

func AsByteArray32(goSlice []byte) ByteArray32 {
	var ary ByteArray32
	for idx := range goSlice[:32] {
		ary.inner.idx[idx] = C.uchar(goSlice[idx])
	}
	return ary
}

/// CheckErr returns `nil` if the `code` indicates success and an error otherwise.
func CheckErr(resp Result) error {
	if resp == nil {
		return errors.New("failed")
	}
	if resp.StatusCode() == FCPResponseStatusNoError {
		return nil
	}

	return errors.New(string(resp.ErrorMsg().Slice()))
}
