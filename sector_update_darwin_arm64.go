//go:build darwin && arm64 && cgo && !ffi_source

package ffi

import (
	"github.com/filecoin-project/filecoin-ffi/prebuilt/darwin-arm64"
)

type FunctionsSectorUpdate = prebuilt.FunctionsSectorUpdate

var SectorUpdate = prebuilt.SectorUpdate
