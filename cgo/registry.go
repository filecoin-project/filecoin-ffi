package cgo

import (
	"sync"
)

var (
	mu       sync.RWMutex
	registry map[uint64]Externs
	nextId   uint64
)

// Register a new item and get a handle.
func Register(bs Externs) uint64 {
	mu.Lock()
	defer mu.Unlock()
	if registry == nil {
		registry = make(map[uint64]Externs)
	}
	id := nextId
	nextId += 1
	registry[id] = bs
	return id
}

// Unregister a blockstore.
//
// WARNING: This method must be called at most _once_ with a handle previously returned by Register.
func Unregister(handle uint64) {
	mu.Lock()
	defer mu.Unlock()

	delete(registry, handle)
}

// Lookup a blockstore by handle.
func Lookup(handle uint64) Externs {
	mu.RLock()
	externs := registry[handle]
	mu.RUnlock()

	return externs
}
