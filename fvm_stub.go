//go:build nofvm

package ffi

import (
	"context"
	"errors"

	"github.com/filecoin-project/filecoin-ffi/cgo"
	"github.com/filecoin-project/go-state-types/abi"
	"github.com/filecoin-project/go-state-types/big"
	"github.com/filecoin-project/go-state-types/network"
	"github.com/ipfs/go-cid"
	"golang.org/x/xerrors"
)

type FVM struct{}

type FVMOpts struct {
	FVMVersion uint64
	Externs    cgo.Externs

	Epoch          abi.ChainEpoch
	Timestamp      uint64
	ChainID        uint64
	BaseFee        abi.TokenAmount
	BaseCircSupply abi.TokenAmount
	NetworkVersion network.Version
	StateBase      cid.Cid
	Tracing        bool
	FlushAllBlocks bool

	Debug         bool
	ActorRedirect cid.Cid
}

func CreateFVM(opts *FVMOpts) (*FVM, error) {
	return nil, errors.New("FVM support not built in this binary")
}

func (f *FVM) ApplyMessage(_ []byte, _ uint) (*ApplyRet, error) {
	return nil, errors.New("FVM support not built in this binary")
}

func (f *FVM) ApplyImplicitMessage(_ []byte) (*ApplyRet, error) {
	return nil, errors.New("FVM support not built in this binary")
}

func (f *FVM) Flush() (cid.Cid, error) {
	return cid.Undef, errors.New("FVM support not built in this binary")
}

// Minimal stubs to satisfy references
type ApplyRet struct {
	Return             []byte
	ExitCode           uint64
	GasUsed            int64
	MinerPenalty       abi.TokenAmount
	MinerTip           abi.TokenAmount
	BaseFeeBurn        abi.TokenAmount
	OverEstimationBurn abi.TokenAmount
	Refund             abi.TokenAmount
	GasRefund          int64
	GasBurned          int64
	ExecTraceBytes     []byte
	FailureInfo        string
	EventsRoot         *cid.Cid
	EventsBytes        []byte
}

// Ensure cgo.Externs referenced to avoid unused import when stubbed
var _ = func() any { return context.TODO() }

// splitBigInt splits a big.Int into high and low uint64 values.
// This is used by tests and needs to be available even when FVM is not built.
func splitBigInt(i big.Int) (hi uint64, lo uint64, err error) {
	if i.Sign() < 0 {
		return 0, 0, xerrors.Errorf("negative number: %s", i)
	}
	words := i.Bits()
	switch len(words) {
	case 2:
		hi = uint64(words[1])
		fallthrough
	case 1:
		lo = uint64(words[0])
	case 0:
	default:
		return 0, 0, xerrors.Errorf("exceeds max bigint size: %s", i)
	}
	return hi, lo, nil
}
