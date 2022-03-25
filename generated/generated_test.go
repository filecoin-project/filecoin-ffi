package generated

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
)

func TestAsSliceRefUint8(t *testing.T) {
	// some words
	foo := []byte("hello world")
	ref := AsSliceRefUint8(foo)
	assert.Equal(t, unsafe.Slice((*byte)(unsafe.Pointer(ref.ptr)), int(ref.len)), foo)

	// empty
	foo = []byte("")
	ref = AsSliceRefUint8(foo)
	assert.Equal(t, unsafe.Slice((*byte)(unsafe.Pointer(ref.ptr)), int(ref.len)), foo)
}

func TestAsSliceRefUint(t *testing.T) {
	// some words
	foo := []uint{0, 1, 2}
	ref := AsSliceRefUint(foo)
	assert.Equal(t, unsafe.Slice((*uint)(unsafe.Pointer(ref.ptr)), int(ref.len)), foo)

	// empty
	foo = []uint{}
	ref = AsSliceRefUint(foo)
	assert.Equal(t, unsafe.Slice((*uint)(unsafe.Pointer(ref.ptr)), int(ref.len)), foo)
}
