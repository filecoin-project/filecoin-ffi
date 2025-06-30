//go:build darwin && cgo && arm64 && !ffi_source

package ffi

import (
	"github.com/filecoin-project/filecoin-ffi/prebuilt/darwin-arm64"
)

type FVM = prebuilt.FVM
type FVMOpts = prebuilt.FVMOpts
type ApplyRet = prebuilt.ApplyRet

// CreateFVM creates a new FVM instance.
func CreateFVM(opts *FVMOpts) (*FVM, error) { return prebuilt.CreateFVM(opts) }
