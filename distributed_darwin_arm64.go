//go:build darwin && arm64 && cgo && !ffi_source

package ffi

import (
	prebuilt "github.com/filecoin-project/filecoin-ffi/prebuilt/darwin-arm64"
	"github.com/filecoin-project/go-state-types/abi"
	"github.com/filecoin-project/go-state-types/proof"

	. "github.com/filecoin-project/filecoin-ffi/types"
)

type FallbackChallenges = prebuilt.FallbackChallenges
type PartitionProof = prebuilt.PartitionProof

// GenerateWinningPoStSectorChallenge
func GeneratePoStFallbackSectorChallenges(
	proofType abi.RegisteredPoStProof,
	minerID abi.ActorID,
	randomness abi.PoStRandomness,
	sectorIds []abi.SectorNumber,
) (*FallbackChallenges, error) {
	return prebuilt.GeneratePoStFallbackSectorChallenges(proofType, minerID, randomness, sectorIds)
}

func GenerateSingleVanillaProof(
	replica PrivateSectorInfo,
	challenges []uint64,
) ([]byte, error) {

	return prebuilt.GenerateSingleVanillaProof(replica, challenges)
}

func GenerateWinningPoStWithVanilla(
	proofType abi.RegisteredPoStProof,
	minerID abi.ActorID,
	randomness abi.PoStRandomness,
	proofs [][]byte,
) ([]proof.PoStProof, error) {
	return prebuilt.GenerateWindowPoStWithVanilla(proofType, minerID, randomness, proofs)
}

func GenerateWindowPoStWithVanilla(
	proofType abi.RegisteredPoStProof,
	minerID abi.ActorID,
	randomness abi.PoStRandomness,
	proofs [][]byte,
) ([]proof.PoStProof, error) {
	return prebuilt.GenerateWindowPoStWithVanilla(proofType, minerID, randomness, proofs)
}

func GenerateSinglePartitionWindowPoStWithVanilla(
	proofType abi.RegisteredPoStProof,
	minerID abi.ActorID,
	randomness abi.PoStRandomness,
	proofs [][]byte,
	partitionIndex uint,
) (*PartitionProof, error) {
	return prebuilt.GenerateSinglePartitionWindowPoStWithVanilla(proofType, minerID, randomness, proofs, partitionIndex)
}

func MergeWindowPoStPartitionProofs(
	proofType abi.RegisteredPoStProof,
	partitionProofs []PartitionProof,
) (*proof.PoStProof, error) {
	return prebuilt.MergeWindowPoStPartitionProofs(proofType, partitionProofs)
}
