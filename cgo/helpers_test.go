package cgo

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
	foo := []uint{0, 1, 2}
	ref := AsSliceRefUint(foo)
	assert.Equal(t, unsafe.Slice((*uint)(unsafe.Pointer(ref.ptr)), int(ref.len)), foo)

	// empty
	foo = []uint{}
	ref = AsSliceRefUint(foo)
	assert.Equal(t, unsafe.Slice((*uint)(unsafe.Pointer(ref.ptr)), int(ref.len)), foo)
}

func TestByteArray32(t *testing.T) {
	foo := make([]byte, 32)
	for i := range foo {
		foo[i] = 1
	}
	ary := AsByteArray32(foo)
	assert.Equal(t, ary.Slice(), foo)

	ary2 := ary.Copy()
	assert.Equal(t, ary.Slice(), ary2)

	// input too short
	aryShort := AsByteArray32([]byte{0, 1, 2})
	slice := aryShort.Slice()
	for i := range slice {
		if i == 0 {
			assert.Equal(t, slice[i], byte(0))
		} else if i == 1 {
			assert.Equal(t, slice[i], byte(1))
		} else if i == 2 {
			assert.Equal(t, slice[i], byte(2))
		} else {
			assert.Equal(t, slice[i], byte(0))
		}
	}
}

func TestAllocSliceBoxedUint8(t *testing.T) {
	foo := []byte("hello world")

	boxed, err := AllocSliceBoxedUint8(foo)
	assert.Nil(t, err)
	assert.Equal(t, boxed.Slice(), foo)
}
