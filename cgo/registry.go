package cgo

import (
	"context"
	"sync"
)

var (
	mu       sync.RWMutex
	registry map[uint64]registeredExterns
	nextId   uint64
)

type registeredExterns struct {
	context.Context
	Externs
}

// Register a new item and get a handle.
func Register(ctx context.Context, externs Externs) uint64 {
	mu.Lock()
	defer mu.Unlock()
	if registry == nil {
		registry = make(map[uint64]registeredExterns)
	}
	id := nextId
	nextId++
	registry[id] = registeredExterns{ctx, externs}
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
func Lookup(handle uint64) (Externs, context.Context) {
	mu.RLock()
	externs := registry[handle]
	mu.RUnlock()

	return externs.Externs, externs.Context
}
