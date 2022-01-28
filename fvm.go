//go:build cgo
// +build cgo

package ffi

// #cgo LDFLAGS: ${SRCDIR}/libfilcrypto.a
// #cgo pkg-config: ${SRCDIR}/filcrypto.pc
// #include "./filcrypto.h"
import "C"
import (
	"runtime"
	"unsafe"

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
func CreateFVM(fvmVersion uint64, epoch abi.ChainEpoch, baseFee abi.TokenAmount, baseCircSupply abi.TokenAmount, nv network.Version, stateBase cid.Cid) (*FVM, error) {
	baseFeeHi, baseFeeLo := splitBigInt(baseFee)
	baseCircSupplyHi, baseCircSupplyLo := splitBigInt(baseCircSupply)

	resp := generated.FilCreateFvmMachine(generated.FilFvmRegisteredVersion(fvmVersion),
		uint64(epoch),
		baseFeeHi,
		baseFeeLo,
		baseCircSupplyHi,
		baseCircSupplyLo,
		uint64(nv),
		stateBase.Bytes(),
		uint(stateBase.ByteLen()),
		// TODO: what do these?
		0,
		0,
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
	})

	return fvm, nil
}

func (f *FVM) ApplyMessage(msgBytes []byte) (*ApplyRet, error) {
	resp := generated.FilFvmMachineExecuteMessage(f.executor,
		msgBytes,
		uint(len(msgBytes)),
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
func splitBigInt(i big.Int) (uint64, uint64) {
	// todo: make 64 a const
	hi := big.Rsh(i, 64)
	// TODO: this is horrible, but big.Int doesn't have a nice way to just get the lower 64 bytes?
	// Result of Uint64() is undefined if int is bigger than 64 bytes. Hopefully I'm missing something.
	return hi.Uint64(), big.Sub(i, big.Lsh(hi, 64)).Uint64()
}

func reformBigInt(hi, lo uint64) big.Int {
	ret := big.NewInt(int64(hi))
	ret = big.Lsh(ret, 64)
	return big.Add(ret, big.NewInt(int64(lo)))
}
