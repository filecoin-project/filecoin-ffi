package cgo

import (
	"context"

	"github.com/filecoin-project/go-address"
	"github.com/filecoin-project/go-state-types/abi"
	"github.com/ipfs/go-cid"
	blockstore "github.com/ipfs/go-ipfs-blockstore"
)

type ConsensusFault struct {
	// Address of the miner at fault (always an ID address).
	Target address.Address
	// Epoch of the fault, which is the higher epoch of the two blocks causing it.
	Epoch abi.ChainEpoch
	// Type of fault.
	Type ConsensusFaultType
}

type ConsensusFaultType int64

const (
	ConsensusFaultNone             ConsensusFaultType = 0
	ConsensusFaultDoubleForkMining ConsensusFaultType = 1
	ConsensusFaultParentGrinding   ConsensusFaultType = 2
	ConsensusFaultTimeOffsetMining ConsensusFaultType = 3
)

type Externs interface {
	GetChainRandomness(ctx context.Context, epoch abi.ChainEpoch) ([32]byte, error)
	GetBeaconRandomness(ctx context.Context, epoch abi.ChainEpoch) ([32]byte, error)
	VerifyConsensusFault(ctx context.Context, h1, h2, extra []byte) (*ConsensusFault, int64)
	TipsetCid(ctx context.Context, epoch abi.ChainEpoch) (cid.Cid, error)

	blockstore.Blockstore
	blockstore.Viewer
}
