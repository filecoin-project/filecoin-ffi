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

//export cgo_blockstore_put_many
func cgo_blockstore_put_many(handle C.uint64_t, lengths *C.int32_t, lengths_len C.int32_t, block_buf C.buf_t) C.int32_t {
	bs := Lookup(uint64(handle))
	if bs == nil {
		return ErrInvalidHandle
	}
	// Get a reference to the lengths vector without copying.
	const MAX_LEN = 1 << 30
	if lengths_len > MAX_LEN {
		return ErrInvalidArgument
	}

	lengthsGo := (*[MAX_LEN]C.int32_t)(unsafe.Pointer(lengths))[:lengths_len:lengths_len]
	blocksGo := make([]blocks.Block, 0, lengths_len)
	for _, length := range lengthsGo {
		if length > MAX_LEN {
			return ErrInvalidArgument
		}
		// get the next buffer. We could use C.GoBytes, but that copies.
		buf := (*[MAX_LEN]byte)(unsafe.Pointer(block_buf))[:length:length]

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
		block_buf = (C.buf_t)(unsafe.Pointer(uintptr(unsafe.Pointer(block_buf)) + uintptr(length)))
	}
	if bs.PutMany(context.TODO(), blocksGo) != nil {
		return ErrIO
	}
	return 0
}

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
