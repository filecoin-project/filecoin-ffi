package cgo

import (
	"unsafe"

	blocks "github.com/ipfs/go-block-format"
	"github.com/ipfs/go-cid"
	ipld "github.com/ipfs/go-ipld-format"
)

/*
#include <stdint.h>
typedef const uint8_t* buf_t;
*/
import "C"

func toCid(k C.buf_t, kLen C.int32_t) cid.Cid {
	type cidRepr struct {
		str string
	}
	return *(*cid.Cid)(unsafe.Pointer(&cidRepr{
		str: C.GoStringN((*C.char)(unsafe.Pointer(k)), kLen),
	}))
}

//export cgo_blockstore_get
func cgo_blockstore_get(handle C.uint64_t, k C.buf_t, kLen C.int32_t, block **C.uint8_t, size *C.int32_t) (res C.int32_t) {
	defer func() {
		if rerr := recover(); rerr != nil {
			logPanic(rerr)
			res = ErrPanic
		}
	}()

	c := toCid(k, kLen)
	externs, ctx := Lookup(uint64(handle))
	if externs == nil {
		return ErrInvalidHandle
	}

	err := externs.View(ctx, c, func(data []byte) error {
		*block = (C.buf_t)(C.CBytes(data))
		*size = C.int32_t(len(data))
		return nil
	})

	switch {
	case err == nil:
		return 0
	case ipld.IsNotFound(err):
		return ErrNotFound
	default:
		return ErrIO
	}
}

//export cgo_blockstore_put
func cgo_blockstore_put(handle C.uint64_t, k C.buf_t, kLen C.int32_t, block C.buf_t, blockLen C.int32_t) (res C.int32_t) {
	defer func() {
		if rerr := recover(); rerr != nil {
			logPanic(rerr)
			res = ErrPanic
		}
	}()

	c := toCid(k, kLen)
	externs, ctx := Lookup(uint64(handle))
	if externs == nil {
		return ErrInvalidHandle
	}
	b, _ := blocks.NewBlockWithCid(C.GoBytes(unsafe.Pointer(block), blockLen), c)
	if externs.Put(ctx, b) != nil {
		return ErrIO
	}
	return 0
}

//export cgo_blockstore_put_many
func cgo_blockstore_put_many(handle C.uint64_t, lengths *C.int32_t, lengthsLen C.int32_t, blockBuf C.buf_t) (res C.int32_t) {
	defer func() {
		if rerr := recover(); rerr != nil {
			logPanic(rerr)
			res = ErrPanic
		}
	}()
	externs, ctx := Lookup(uint64(handle))
	if externs == nil {
		return ErrInvalidHandle
	}
	// Get a reference to the lengths vector without copying.
	const MAX_LEN = 1 << 30
	if lengthsLen > MAX_LEN {
		return ErrInvalidArgument
	}

	lengthsGo := unsafe.Slice(lengths, lengthsLen)
	blocksGo := make([]blocks.Block, 0, lengthsLen)
	for _, length := range lengthsGo {
		if length > MAX_LEN {
			return ErrInvalidArgument
		}
		// get the next buffer. We could use C.GoBytes, but that copies.
		buf := unsafe.Slice((*byte)(unsafe.Pointer(blockBuf)), length)

		// read the CID. This function will copy the CID internally.
		cidLen, k, err := cid.CidFromBytes(buf)
		if err != nil {
			return ErrInvalidArgument
		}
		buf = buf[cidLen:]

		// Read the block and copy it. Unfortunately, our blockstore makes no guarantees
		// about not holding onto blocks.
		block := make([]byte, len(buf))
		copy(block, buf)
		b, _ := blocks.NewBlockWithCid(block, k)

		// Add it to the batch.
		blocksGo = append(blocksGo, b)

		// Advance the block buffer.
		blockBuf = (C.buf_t)(unsafe.Pointer(uintptr(unsafe.Pointer(blockBuf)) + uintptr(length)))
	}
	if externs.PutMany(ctx, blocksGo) != nil {
		return ErrIO
	}
	return 0
}

//export cgo_blockstore_has
func cgo_blockstore_has(handle C.uint64_t, k C.buf_t, kLen C.int32_t) (res C.int32_t) {
	defer func() {
		if rerr := recover(); rerr != nil {
			logPanic(rerr)
			res = ErrPanic
		}
	}()

	c := toCid(k, kLen)
	externs, ctx := Lookup(uint64(handle))
	if externs == nil {
		return ErrInvalidHandle
	}
	has, err := externs.Has(ctx, c)
	switch {
	case err == nil:
	case ipld.IsNotFound(err):
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
