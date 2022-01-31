package cgo

import (
	"context"
	"unsafe"

	blocks "github.com/ipfs/go-block-format"
	"github.com/ipfs/go-cid"
	blockstore "github.com/ipfs/go-ipfs-blockstore"
)

/*
#include <stdint.h>
typedef const uint8_t* buf_t;
*/
import "C"

func toCid(k C.buf_t, k_len C.int32_t) cid.Cid {
	type cidRepr struct {
		str string
	}
	return *(*cid.Cid)(unsafe.Pointer(&cidRepr{
		str: C.GoStringN((*C.char)(unsafe.Pointer(k)), C.int(k_len)),
	}))
}

//export cgo_blockstore_get
func cgo_blockstore_get(handle C.uint64_t, k C.buf_t, k_len C.int32_t, block **C.uint8_t, size *C.int32_t) C.int32_t {
	c := toCid(k, k_len)
	bs := Lookup(uint64(handle))
	if bs == nil {
		return ErrInvalidHandle
	}
	err := bs.View(context.TODO(), c, func(data []byte) error {
		*block = (C.buf_t)(C.CBytes(data))
		*size = C.int32_t(len(data))
		return nil
	})

	switch err {
	case nil:
		return 0
	case blockstore.ErrNotFound:
		return ErrNotFound
	default:
		return ErrIO
	}
}

//export cgo_blockstore_put
func cgo_blockstore_put(handle C.uint64_t, k C.buf_t, k_len C.int32_t, block C.buf_t, block_len C.int32_t) C.int32_t {
	c := toCid(k, k_len)
	bs := Lookup(uint64(handle))
	if bs == nil {
		return ErrInvalidHandle
	}
	b, _ := blocks.NewBlockWithCid(C.GoBytes(unsafe.Pointer(block), C.int(block_len)), c)
	if bs.Put(context.TODO(), b) != nil {
		return ErrIO
	}
	return 0
}

// TODO: Implement a "put many". We should just pass a single massive buffer, or an array of
// buffers?

//export cgo_blockstore_has
func cgo_blockstore_has(handle C.uint64_t, k C.buf_t, k_len C.int32_t) C.int32_t {
	c := toCid(k, k_len)
	bs := Lookup(uint64(handle))
	if bs == nil {
		return ErrInvalidHandle
	}
	has, err := bs.Has(context.TODO(), c)
	switch err {
	case nil:
	case blockstore.ErrNotFound:
		// Some old blockstores still return this.
		return 0
	default:
		return ErrIO
	}
	if has {
		return 1
	}
	return 0
}
