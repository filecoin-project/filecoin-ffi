//go:build cgo
// +build cgo

package ffi

import (
	"github.com/filecoin-project/filecoin-ffi/cgo"
	"github.com/filecoin-project/go-state-types/abi"
	"github.com/filecoin-project/go-state-types/proof"
)

type FallbackChallenges struct {
	Sectors    []abi.SectorNumber
	Challenges map[abi.SectorNumber][]uint64
}

// GenerateWinningPoStSectorChallenge
func GeneratePoStFallbackSectorChallenges(
	proofType abi.RegisteredPoStProof,
	minerID abi.ActorID,
	randomness abi.PoStRandomness,
	sectorIds []abi.SectorNumber,
) (*FallbackChallenges, error) {
	proverID, err := toProverID(minerID)
	if err != nil {
		return nil, err
	}

	pp, err := toFilRegisteredPoStProof(proofType)
	if err != nil {
		return nil, err
	}

	// this should be a simple cast..
	sectorIdsRaw := make([]uint64, len(sectorIds))
	for i := range sectorIds {
		sectorIdsRaw[i] = uint64(sectorIds[i])
	}

	randomnessBytes := cgo.AsByteArray32(randomness)
	ids, challenges, err := cgo.GenerateFallbackSectorChallenges(pp, &randomnessBytes, cgo.AsSliceRefUint64(sectorIdsRaw), &proverID)
	if err != nil {
		return nil, err
	}

	out := FallbackChallenges{
		Sectors:    make([]abi.SectorNumber, len(ids)),
		Challenges: make(map[abi.SectorNumber][]uint64),
	}
	for idx := range ids {
		secNum := abi.SectorNumber(ids[idx])
		out.Sectors[idx] = secNum
		out.Challenges[secNum] = challenges[idx]
	}

	return &out, nil
}

func GenerateSingleVanillaProof(
	replica PrivateSectorInfo,
	challenges []uint64,
) ([]byte, error) {

	rep, err := toFilPrivateReplicaInfo(replica)
	if err != nil {
		return nil, err
	}

	return cgo.GenerateSingleVanillaProof(rep, cgo.AsSliceRefUint64(challenges))
}

func GenerateWinningPoStWithVanilla(
	proofType abi.RegisteredPoStProof,
	minerID abi.ActorID,
	randomness abi.PoStRandomness,
	proofs [][]byte,
) ([]proof.PoStProof, error) {
	pp, err := toFilRegisteredPoStProof(proofType)
	if err != nil {
		return nil, err
	}

	proverID, err := toProverID(minerID)
	if err != nil {
		return nil, err
	}
	fproofs, cleanup := toVanillaProofs(proofs)
	defer cleanup()

	randomnessBytes := cgo.AsByteArray32(randomness)
	resp, err := cgo.GenerateWinningPoStWithVanilla(pp, &randomnessBytes, &proverID, cgo.AsSliceRefSliceBoxedUint8(fproofs))
	if err != nil {
		return nil, err
	}

	out, err := fromFilPoStProofs(resp)
	if err != nil {
		return nil, err
	}

	return out, nil
}

func GenerateWindowPoStWithVanilla(
	proofType abi.RegisteredPoStProof,
	minerID abi.ActorID,
	randomness abi.PoStRandomness,
	proofs [][]byte,
) ([]proof.PoStProof, error) {
	pp, err := toFilRegisteredPoStProof(proofType)
	if err != nil {
		return nil, err
	}

	proverID, err := toProverID(minerID)
	if err != nil {
		return nil, err
	}
	fproofs, cleaner := toVanillaProofs(proofs)
	defer cleaner()

	randomnessBytes := cgo.AsByteArray32(randomness)
	rawProofs, _, err := cgo.GenerateWindowPoStWithVanilla(pp, &randomnessBytes, &proverID, cgo.AsSliceRefSliceBoxedUint8(fproofs))
	if err != nil {
		return nil, err
	}

	out, err := fromFilPoStProofs(rawProofs)
	if err != nil {
		return nil, err
	}

	return out, nil
}

type PartitionProof proof.PoStProof

func GenerateSinglePartitionWindowPoStWithVanilla(
	proofType abi.RegisteredPoStProof,
	minerID abi.ActorID,
	randomness abi.PoStRandomness,
	proofs [][]byte,
	partitionIndex uint,
) (*PartitionProof, error) {
	pp, err := toFilRegisteredPoStProof(proofType)
	if err != nil {
		return nil, err
	}

	proverID, err := toProverID(minerID)
	if err != nil {
		return nil, err
	}
	fproofs, cleaner := toVanillaProofs(proofs)
	defer cleaner()

	randomnessBytes := cgo.AsByteArray32(randomness)
	resp, _, err := cgo.GenerateSingleWindowPoStWithVanilla(
		pp,
		&randomnessBytes,
		&proverID,
		cgo.AsSliceRefSliceBoxedUint8(fproofs),
		partitionIndex,
	)
	if err != nil {
		return nil, err
	}

	dpp, err := fromFilRegisteredPoStProof(resp.RegisteredProof)
	if err != nil {
		return nil, err
	}

	out := PartitionProof{
		PoStProof:  dpp,
		ProofBytes: resp.Proof,
	}

	return &out, nil
}

func MergeWindowPoStPartitionProofs(
	proofType abi.RegisteredPoStProof,
	partitionProofs []PartitionProof,
) (*proof.PoStProof, error) {
	pp, err := toFilRegisteredPoStProof(proofType)
	if err != nil {
		return nil, err
	}

	fproofs, cleaner := toPartitionProofs(partitionProofs)
	defer cleaner()

	resp, err := cgo.MergeWindowPoStPartitionProofs(pp, cgo.AsSliceRefSliceBoxedUint8(fproofs))
	if err != nil {
		return nil, err
	}

	dpp, err := fromFilRegisteredPoStProof(resp.RegisteredProof)
	if err != nil {
		return nil, err
	}

	out := proof.PoStProof{
		PoStProof:  dpp,
		ProofBytes: resp.Proof,
	}

	return &out, nil
}

func toPartitionProofs(src []PartitionProof) ([]cgo.SliceBoxedUint8, func()) {
	out := make([]cgo.SliceBoxedUint8, len(src))
	for idx := range out {
		out[idx] = cgo.AllocSliceBoxedUint8(src[idx].ProofBytes)
	}

	return out, makeCleanerSBU(out, len(src))
}
