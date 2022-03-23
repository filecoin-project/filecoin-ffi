//go:build cgo
// +build cgo

package ffi

// #cgo linux LDFLAGS: ${SRCDIR}/libfilcrypto.a -Wl,-unresolved-symbols=ignore-all
// #cgo darwin LDFLAGS: ${SRCDIR}/libfilcrypto.a -Wl,-undefined,dynamic_lookup
// #cgo pkg-config: ${SRCDIR}/filcrypto.pc
// #include "./filcrypto.h"
import "C"
import (
	"context"
	"math"
	gobig "math/big"
	"math/bits"
	"runtime"
	"unsafe"

	"github.com/filecoin-project/filecoin-ffi/cgo"
	"github.com/filecoin-project/filecoin-ffi/generated"
	"github.com/filecoin-project/go-state-types/abi"
	"github.com/filecoin-project/go-state-types/big"
	"github.com/filecoin-project/go-state-types/network"
	"github.com/ipfs/go-cid"
	"golang.org/x/xerrors"
)

type FVM struct {
	executor unsafe.Pointer
}

const (
	applyExplicit = iota
	applyImplicit
)

type FVMOpts struct {
	FVMVersion uint64
	Externs    cgo.Externs

	Epoch          abi.ChainEpoch
	BaseFee        abi.TokenAmount
	BaseCircSupply abi.TokenAmount
	NetworkVersion network.Version
	StateBase      cid.Cid
}

// CreateFVM creates a new FVM instance.
func CreateFVM(opts *FVMOpts) (*FVM, error) {
	baseFeeHi, baseFeeLo, err := splitBigInt(opts.BaseFee)
	if err != nil {
		return nil, xerrors.Errorf("invalid basefee: %w", err)
	}
	baseCircSupplyHi, baseCircSupplyLo, err := splitBigInt(opts.BaseCircSupply)
	if err != nil {
		return nil, xerrors.Errorf("invalid circ supply: %w", err)
	}

	exHandle := cgo.Register(context.TODO(), opts.Externs)
	resp := generated.FilCreateFvmMachine(generated.FilFvmRegisteredVersion(opts.FVMVersion),
		uint64(opts.Epoch),
		baseFeeHi,
		baseFeeLo,
		baseCircSupplyHi,
		baseCircSupplyLo,
		uint64(opts.NetworkVersion),
		opts.StateBase.Bytes(),
		uint(opts.StateBase.ByteLen()),
		exHandle, exHandle,
	)
	resp.Deref()

	defer generated.FilDestroyCreateFvmMachineResponse(resp)

	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
		return nil, xerrors.New(generated.RawString(resp.ErrorMsg).Copy())
	}

	fvm := &FVM{
		executor: resp.Executor,
	}
	runtime.SetFinalizer(fvm, func(f *FVM) {
		// Just to be extra safe
		if f.executor == nil {
			return
		}

		executor := f.executor
		f.executor = nil
		generated.FilDropFvmMachine(executor)
		cgo.Unregister(exHandle)
	})

	return fvm, nil
}

func (f *FVM) ApplyMessage(msgBytes []byte, chainLen uint) (*ApplyRet, error) {
	defer runtime.KeepAlive(f)
	resp := generated.FilFvmMachineExecuteMessage(f.executor,
		msgBytes,
		uint(len(msgBytes)),
		uint64(chainLen),
		applyExplicit,
	)
	resp.Deref()

	defer generated.FilDestroyFvmMachineExecuteResponse(resp)

	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
		return nil, xerrors.New(generated.RawString(resp.ErrorMsg).Copy())
	}

	return &ApplyRet{
		Return:       copyBytes(resp.ReturnPtr, resp.ReturnLen),
		ExitCode:     resp.ExitCode,
		GasUsed:      int64(resp.GasUsed),
		MinerPenalty: reformBigInt(resp.PenaltyHi, resp.PenaltyLo),
		MinerTip:     reformBigInt(resp.MinerTipHi, resp.MinerTipLo),
	}, nil
}

func (f *FVM) ApplyImplicitMessage(msgBytes []byte) (*ApplyRet, error) {
	defer runtime.KeepAlive(f)
	resp := generated.FilFvmMachineExecuteMessage(f.executor,
		msgBytes,
		uint(len(msgBytes)),
		0, // this isn't an on-chain message, so it has no chain length.
		applyImplicit,
	)
	resp.Deref()

	defer generated.FilDestroyFvmMachineExecuteResponse(resp)

	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
		return nil, xerrors.New(generated.RawString(resp.ErrorMsg).Copy())
	}

	return &ApplyRet{
		Return:       copyBytes(resp.ReturnPtr, resp.ReturnLen),
		ExitCode:     resp.ExitCode,
		GasUsed:      int64(resp.GasUsed),
		MinerPenalty: reformBigInt(resp.PenaltyHi, resp.PenaltyLo),
		MinerTip:     reformBigInt(resp.MinerTipHi, resp.MinerTipLo),
	}, nil
}

func (f *FVM) Flush() (cid.Cid, error) {
	defer runtime.KeepAlive(f)
	resp := generated.FilFvmMachineFlush(f.executor)
	resp.Deref()

	defer generated.FilDestroyFvmMachineFlushResponse(resp)

	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
		return cid.Undef, xerrors.New(generated.RawString(resp.ErrorMsg).Copy())
	}

	// cast will copy internally.
	return cid.Cast(resp.StateRootPtr[:resp.StateRootLen])
}

type ApplyRet struct {
	Return       []byte
	ExitCode     uint64
	GasUsed      int64
	MinerPenalty abi.TokenAmount
	MinerTip     abi.TokenAmount
}

// returns hi, lo
func splitBigInt(i big.Int) (hi uint64, lo uint64, err error) {
	if i.Sign() < 0 {
		return 0, 0, xerrors.Errorf("negative number: %s", i)
	}
	words := i.Bits()
	switch bits.UintSize {
	case 32:
		switch len(words) {
		case 4:
			hi = uint64(words[3]) << 32
			fallthrough
		case 3:
			hi |= uint64(words[2])
			fallthrough
		case 2:
			lo = uint64(words[1]) << 32
			fallthrough
		case 1:
			lo |= uint64(words[0])
		case 0:
		default:
			return 0, 0, xerrors.Errorf("exceeds max bigint size: %s", i)
		}
	case 64:
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
	default:
		panic("unsupported word size")
	}
	return hi, lo, nil
}

func reformBigInt(hi, lo uint64) big.Int {
	var words []gobig.Word
	switch bits.UintSize {
	case 32:
		if hi > math.MaxUint32 {
			words = make([]gobig.Word, 4)
		} else if hi > 0 {
			words = make([]gobig.Word, 3)
		} else if lo > math.MaxUint32 {
			words = make([]gobig.Word, 2)
		} else if lo > 0 {
			words = make([]gobig.Word, 1)
		} else {
			return big.Zero()
		}
		switch len(words) {
		case 4:
			words[3] = gobig.Word(hi >> 32)
			fallthrough
		case 3:
			words[2] = gobig.Word(hi)
			fallthrough
		case 2:
			words[1] = gobig.Word(lo >> 32)
			fallthrough
		case 1:
			words[0] = gobig.Word(lo)
		}
	case 64:
		if hi > 0 {
			words = []gobig.Word{gobig.Word(lo), gobig.Word(hi)}
		} else if lo > 0 {
			words = []gobig.Word{gobig.Word(lo)}
		} else {
			return big.Zero()
		}
	default:
		panic("unsupported word size")
	}
	int := new(gobig.Int)
	int.SetBits(words)
	return big.NewFromGo(int)
}
