//go:build cgo && (amd64 || arm64 || riscv64) && fvm
// +build cgo
// +build amd64 arm64 riscv64
// +build fvm

package ffi

// #cgo linux LDFLAGS: ${SRCDIR}/libfilcrypto.a -Wl,-unresolved-symbols=ignore-all
// #cgo darwin LDFLAGS: ${SRCDIR}/libfilcrypto.a -Wl,-undefined,dynamic_lookup
// #cgo pkg-config: ${SRCDIR}/filcrypto.pc
// #include "./filcrypto.h"
import "C"
import (
	"context"
	"fmt"
	gobig "math/big"
	"runtime"

	"github.com/filecoin-project/filecoin-ffi/cgo"
	"github.com/filecoin-project/go-state-types/abi"
	"github.com/filecoin-project/go-state-types/big"
	"github.com/filecoin-project/go-state-types/network"
	"github.com/ipfs/go-cid"
	"golang.org/x/xerrors"
)

type FVM struct {
	executor *cgo.FvmMachine
}

var (
	ErrReservationsNotImplemented     = fmt.Errorf("fvm reservations not implemented")
	ErrReservationsInsufficientFunds  = fmt.Errorf("fvm reservation insufficient funds at begin")
	ErrReservationsSessionOpen        = fmt.Errorf("fvm reservation session already open")
	ErrReservationsSessionClosed      = fmt.Errorf("fvm reservation session closed")
	ErrReservationsNonZeroRemainder   = fmt.Errorf("fvm reservation non-zero remainder at end")
	ErrReservationsPlanTooLarge       = fmt.Errorf("fvm reservation plan too large")
	ErrReservationsOverflow           = fmt.Errorf("fvm reservation arithmetic overflow")
	ErrReservationsInvariantViolation = fmt.Errorf("fvm reservation invariant violation")
)

func ReservationStatusToError(code int32) error {
	switch code {
	case 0:
		return nil
	case 1:
		return ErrReservationsNotImplemented
	case 2:
		return ErrReservationsInsufficientFunds
	case 3:
		return ErrReservationsSessionOpen
	case 4:
		return ErrReservationsSessionClosed
	case 5:
		return ErrReservationsNonZeroRemainder
	case 6:
		return ErrReservationsPlanTooLarge
	case 7:
		return ErrReservationsOverflow
	case 8:
		return ErrReservationsInvariantViolation
	default:
		return fmt.Errorf("unknown FVM reservation status code: %d", code)
	}
}

const (
	applyExplicit = iota
	applyImplicit
)

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
	var executor *cgo.FvmMachine
	if !opts.Debug {
		executor, err = cgo.CreateFvmMachine(cgo.FvmRegisteredVersion(opts.FVMVersion),
			uint64(opts.Epoch),
			opts.Timestamp,
			opts.ChainID,
			baseFeeHi,
			baseFeeLo,
			baseCircSupplyHi,
			baseCircSupplyLo,
			uint64(opts.NetworkVersion),
			cgo.AsSliceRefUint8(opts.StateBase.Bytes()),
			opts.Tracing,
			opts.FlushAllBlocks,
			exHandle, exHandle,
		)
	} else {
		executor, err = cgo.CreateFvmDebugMachine(cgo.FvmRegisteredVersion(opts.FVMVersion),
			uint64(opts.Epoch),
			opts.Timestamp,
			opts.ChainID,
			baseFeeHi,
			baseFeeLo,
			baseCircSupplyHi,
			baseCircSupplyLo,
			uint64(opts.NetworkVersion),
			cgo.AsSliceRefUint8(opts.StateBase.Bytes()),
			cgo.AsSliceRefUint8(opts.ActorRedirect.Bytes()),
			true,
			opts.FlushAllBlocks,
			exHandle, exHandle,
		)
	}

	if err != nil {
		return nil, err
	}

	fvm := &FVM{
		executor: executor,
	}
	runtime.SetFinalizer(fvm, func(f *FVM) {
		// Just to be extra safe
		if f.executor == nil {
			return
		}

		executor := f.executor
		f.executor = nil
		executor.Destroy()
		cgo.Unregister(exHandle)
	})

	return fvm, nil
}

// BeginReservations starts a reservation session for the given CBOR-encoded plan.
// It returns a typed error based on the underlying FVM reservation status code,
// optionally wrapped with a short human-readable message from the engine.
func (f *FVM) BeginReservations(plan []byte) error {
	defer runtime.KeepAlive(f)
	status, msg := cgo.FvmBeginReservations(f.executor, cgo.AsSliceRefUint8(plan))
	baseErr := ReservationStatusToError(status)
	if baseErr == nil {
		return nil
	}
	if msg == "" {
		return baseErr
	}
	return fmt.Errorf("%w: %s", baseErr, msg)
}

// EndReservations ends the active reservation session.
// It returns a typed error based on the underlying FVM reservation status code,
// optionally wrapped with a short human-readable message from the engine.
func (f *FVM) EndReservations() error {
	defer runtime.KeepAlive(f)
	status, msg := cgo.FvmEndReservations(f.executor)
	baseErr := ReservationStatusToError(status)
	if baseErr == nil {
		return nil
	}
	if msg == "" {
		return baseErr
	}
	return fmt.Errorf("%w: %s", baseErr, msg)
}

func (f *FVM) ApplyMessage(msgBytes []byte, chainLen uint) (*ApplyRet, error) {
	// NOTE: we need to call KeepAlive here (and below) because go doesn't guarantee that the
	// receiver will live to the end of the function. If we don't do this, go _will_ garbage
	// collect the FVM, causing us to run the finalizer while we're in the middle of using the
	// FVM.
	defer runtime.KeepAlive(f)
	resp, err := cgo.FvmMachineExecuteMessage(
		f.executor,
		cgo.AsSliceRefUint8(msgBytes),
		uint64(chainLen),
		applyExplicit,
	)
	if err != nil {
		return nil, err
	}

	return buildResponse(resp)
}

func (f *FVM) ApplyImplicitMessage(msgBytes []byte) (*ApplyRet, error) {
	defer runtime.KeepAlive(f)
	resp, err := cgo.FvmMachineExecuteMessage(
		f.executor,
		cgo.AsSliceRefUint8(msgBytes),
		0, // this isn't an on-chain message, so it has no chain length.
		applyImplicit,
	)
	if err != nil {
		return nil, err
	}

	return buildResponse(resp)
}

func buildResponse(resp cgo.FvmMachineExecuteResponseGo) (*ApplyRet, error) {
	var eventsRoot *cid.Cid
	if len(resp.EventsRoot) > 0 {
		if eventsRootCid, err := cid.Cast(resp.EventsRoot); err != nil {
			return nil, fmt.Errorf("failed to cast events root CID: %w", err)
		} else {
			eventsRoot = &eventsRootCid
		}
	}

	return &ApplyRet{
		Return:             resp.ReturnVal,
		ExitCode:           resp.ExitCode,
		GasUsed:            int64(resp.GasUsed),
		MinerPenalty:       reformBigInt(resp.PenaltyHi, resp.PenaltyLo),
		MinerTip:           reformBigInt(resp.MinerTipHi, resp.MinerTipLo),
		BaseFeeBurn:        reformBigInt(resp.BaseFeeBurnHi, resp.BaseFeeBurnLo),
		OverEstimationBurn: reformBigInt(resp.OverEstimationBurnHi, resp.OverEstimationBurnLo),
		Refund:             reformBigInt(resp.RefundHi, resp.RefundLo),
		GasRefund:          int64(resp.GasRefund),
		GasBurned:          int64(resp.GasBurned),
		ExecTraceBytes:     resp.ExecTrace,
		FailureInfo:        resp.FailureInfo,
		EventsRoot:         eventsRoot,
		EventsBytes:        resp.Events,
	}, nil
}

func (f *FVM) Flush() (cid.Cid, error) {
	defer runtime.KeepAlive(f)
	stateRoot, err := cgo.FvmMachineFlush(f.executor)
	if err != nil {
		return cid.Undef, err
	}

	return cid.Cast(stateRoot)
}

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

// NOTE: We only support 64bit platforms

// returns hi, lo
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

func reformBigInt(hi, lo uint64) big.Int {
	var words []gobig.Word
	if hi > 0 {
		words = []gobig.Word{gobig.Word(lo), gobig.Word(hi)}
	} else if lo > 0 {
		words = []gobig.Word{gobig.Word(lo)}
	} else {
		return big.Zero()
	}
	int := new(gobig.Int)
	int.SetBits(words)
	return big.NewFromGo(int)
}
