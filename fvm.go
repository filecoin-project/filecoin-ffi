//go:build cgo
// +build cgo

package ffi

// #cgo LDFLAGS: ${SRCDIR}/libfilcrypto.a -Wl,-unresolved-symbols=ignore-all
// #cgo pkg-config: ${SRCDIR}/filcrypto.pc
// #include "./filcrypto.h"
import "C"
import (
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

// CreateFVM
func CreateFVM(fvmVersion uint64, externs cgo.Externs, epoch abi.ChainEpoch, baseFee abi.TokenAmount, baseCircSupply abi.TokenAmount, nv network.Version, stateBase cid.Cid) (*FVM, error) {
	baseFeeHi, baseFeeLo, err := splitBigInt(baseFee)
	if err != nil {
		return nil, xerrors.Errorf("invalid basefee: %w", err)
	}
	baseCircSupplyHi, baseCircSupplyLo, err := splitBigInt(baseCircSupply)
	if err != nil {
		return nil, xerrors.Errorf("invalid circ supply: %w", err)
	}

	exHandle := cgo.Register(externs)
	resp := generated.FilCreateFvmMachine(generated.FilFvmRegisteredVersion(fvmVersion),
		uint64(epoch),
		baseFeeHi,
		baseFeeLo,
		baseCircSupplyHi,
		baseCircSupplyLo,
		uint64(nv),
		stateBase.Bytes(),
		uint(stateBase.ByteLen()),
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
	resp := generated.FilFvmMachineExecuteMessage(f.executor,
		msgBytes,
		uint(len(msgBytes)),
		uint64(chainLen),
		// TODO: make this a type somewhere
		0,
	)
	resp.Deref()

	defer generated.FilDestroyFvmMachineExecuteResponse(resp)

	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
		return nil, xerrors.New(generated.RawString(resp.ErrorMsg).Copy())
	}

	return &ApplyRet{
		// TODO: i don't understand when a deref is needed, one may be needed before this
		Return:       copyBytes(resp.ReturnPtr, resp.ReturnLen),
		ExitCode:     resp.ExitCode,
		GasUsed:      int64(resp.GasUsed),
		MinerPenalty: reformBigInt(resp.PenaltyHi, resp.PenaltyLo),
		MinerTip:     reformBigInt(resp.MinerTipHi, resp.MinerTipLo),
	}, nil
}

func (f *FVM) ApplyImplicitMessage(msgBytes []byte) (*ApplyRet, error) {
	resp := generated.FilFvmMachineExecuteMessage(f.executor,
		msgBytes,
		uint(len(msgBytes)),
		0,
		// TODO: make this a type somewhere
		1,
	)
	resp.Deref()

	defer generated.FilDestroyFvmMachineExecuteResponse(resp)

	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
		return nil, xerrors.New(generated.RawString(resp.ErrorMsg).Copy())
	}

	return &ApplyRet{
		// TODO: i don't understand when a deref is needed, one may be needed before this
		Return:       copyBytes(resp.ReturnPtr, resp.ReturnLen),
		ExitCode:     resp.ExitCode,
		GasUsed:      int64(resp.GasUsed),
		MinerPenalty: reformBigInt(resp.PenaltyHi, resp.PenaltyLo),
		MinerTip:     reformBigInt(resp.MinerTipHi, resp.MinerTipLo),
	}, nil
}

func (f *FVM) Flush() (cid.Cid, error) {
	resp := generated.FilFvmMachineFlush(f.executor)
	resp.Deref()

	defer generated.FilDestroyFvmMachineFlushResponse(resp)

	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
		return cid.Undef, xerrors.New(generated.RawString(resp.ErrorMsg).Copy())
	}

	return cid.Cast(resp.StateRootPtr)
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
			hi = uint64(words[3]) << bits.UintSize
			fallthrough
		case 3:
			hi |= uint64(words[2])
			fallthrough
		case 2:
			lo = uint64(words[1]) << bits.UintSize
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
		if hi > math.MaxUint {
			words = make([]gobig.Word, 4)
		} else if hi > 0 {
			words = make([]gobig.Word, 3)
		} else if lo > math.MaxUint {
			words = make([]gobig.Word, 2)
		} else if lo > 0 {
			words = make([]gobig.Word, 1)
		} else {
			return big.Zero()
		}
		switch len(words) {
		case 4:
			words[3] = gobig.Word(hi >> bits.UintSize)
			fallthrough
		case 3:
			words[2] = gobig.Word(hi)
			fallthrough
		case 2:
			words[1] = gobig.Word(lo >> bits.UintSize)
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
