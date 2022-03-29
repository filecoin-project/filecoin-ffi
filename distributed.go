//go:build cgo
// +build cgo

package ffi

import (
	"github.com/filecoin-project/filecoin-ffi/cgo"
	"github.com/filecoin-project/go-state-types/abi"
	// "github.com/filecoin-project/specs-actors/v5/actors/runtime/proof"
	// "github.com/pkg/errors"
)

type FallbackChallenges struct {
	Sectors    []abi.SectorNumber
	Challenges map[abi.SectorNumber][]uint64
}

// type VanillaProof []byte

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

// func GenerateSingleVanillaProof(
// 	replica PrivateSectorInfo,
// 	challenges []uint64,
// ) ([]byte, error) {

// 	rep, free, err := toFilPrivateReplicaInfo(replica)
// 	if err != nil {
// 		return nil, err
// 	}
// 	defer free()

// 	var challengesSlice cgo.SliceRefUint64T
// 	challengesSlice.Len = cgo.SizeT(len(challenges))
// 	challengesSlice.Ptr = (*[]cgo.Uint64T)(unsafe.Pointer(&challenges[0]))

// 	resp := cgo.GenerateSingleVanillaProof(rep, challengesSlice)
// 	resp.Deref()
// 	defer cgo.DestroyGenerateSingleVanillaProofResponse(resp)

// 	if resp.StatusCode != cgo.FCPResponseStatusFCPNoError {
// 		return nil, errors.New(cgo.RawString(resp.ErrorMsg).Copy())
// 	}

// 	resp.VanillaProof.Deref()

// 	return copyBytes(resp.VanillaProof.ProofPtr, resp.VanillaProof.ProofLen), nil
// }

// func GenerateWinningPoStWithVanilla(
// 	proofType abi.RegisteredPoStProof,
// 	minerID abi.ActorID,
// 	randomness abi.PoStRandomness,
// 	proofs [][]byte,
// ) ([]proof.PoStProof, error) {
// 	pp, err := toFilRegisteredPoStProof(proofType)
// 	if err != nil {
// 		return nil, err
// 	}

// 	proverID, err := toProverID(minerID)
// 	if err != nil {
// 		return nil, err
// 	}
// 	fproofs, discard := toVanillaProofs(proofs)
// 	defer discard()

// 	resp := cgo.GenerateWinningPostWithVanilla(
// 		pp,
// 		toByteArray32(randomness),
// 		proverID,
// 		fproofs, uint(len(proofs)),
// 	)
// 	resp.Deref()
// 	resp.ProofsPtr = make([]cgo.PoStProof, resp.ProofsLen)
// 	resp.Deref()

// 	defer cgo.DestroyGenerateWinningPostResponse(resp)

// 	if resp.StatusCode != cgo.FCPResponseStatusFCPNoError {
// 		return nil, errors.New(cgo.RawString(resp.ErrorMsg).Copy())
// 	}

// 	out, err := fromFilPoStProofs(resp.ProofsPtr)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return out, nil
// }

// func GenerateWindowPoStWithVanilla(
// 	proofType abi.RegisteredPoStProof,
// 	minerID abi.ActorID,
// 	randomness abi.PoStRandomness,
// 	proofs [][]byte,
// ) ([]proof.PoStProof, error) {
// 	pp, err := toFilRegisteredPoStProof(proofType)
// 	if err != nil {
// 		return nil, err
// 	}

// 	proverID, err := toProverID(minerID)
// 	if err != nil {
// 		return nil, err
// 	}
// 	fproofs, discard := toVanillaProofs(proofs)
// 	defer discard()

// 	resp := cgo.GenerateWindowPostWithVanilla(
// 		pp,
// 		toByteArray32(randomness),
// 		proverID,
// 		fproofs, uint(len(proofs)),
// 	)
// 	resp.Deref()
// 	resp.ProofsPtr = make([]cgo.PoStProof, resp.ProofsLen)
// 	resp.Deref()

// 	defer cgo.DestroyGenerateWindowPostResponse(resp)

// 	if resp.StatusCode != cgo.FCPResponseStatusFCPNoError {
// 		return nil, errors.New(cgo.RawString(resp.ErrorMsg).Copy())
// 	}

// 	out, err := fromFilPoStProofs(resp.ProofsPtr)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return out, nil
// }

// type PartitionProof proof.PoStProof

// func GenerateSinglePartitionWindowPoStWithVanilla(
// 	proofType abi.RegisteredPoStProof,
// 	minerID abi.ActorID,
// 	randomness abi.PoStRandomness,
// 	proofs [][]byte,
// 	partitionIndex uint,
// ) (*PartitionProof, error) {
// 	pp, err := toFilRegisteredPoStProof(proofType)
// 	if err != nil {
// 		return nil, err
// 	}

// 	proverID, err := toProverID(minerID)
// 	if err != nil {
// 		return nil, err
// 	}
// 	fproofs, discard := toVanillaProofs(proofs)
// 	defer discard()

// 	resp := cgo.GenerateSingleWindowPostWithVanilla(
// 		pp,
// 		toByteArray32(randomness),
// 		proverID,
// 		fproofs, uint(len(proofs)),
// 		partitionIndex,
// 	)
// 	resp.Deref()
// 	resp.PartitionProof.Deref()

// 	defer cgo.DestroyGenerateSingleWindowPostWithVanillaResponse(resp)

// 	if resp.StatusCode != cgo.FCPResponseStatusFCPNoError {
// 		return nil, errors.New(cgo.RawString(resp.ErrorMsg).Copy())
// 	}

// 	dpp, err := fromFilRegisteredPoStProof(resp.PartitionProof.RegisteredProof)
// 	if err != nil {
// 		return nil, err
// 	}

// 	out := PartitionProof{
// 		PoStProof:  dpp,
// 		ProofBytes: copyBytes(resp.PartitionProof.ProofPtr, resp.PartitionProof.ProofLen),
// 	}

// 	return &out, nil
// }

// func MergeWindowPoStPartitionProofs(
// 	proofType abi.RegisteredPoStProof,
// 	partitionProofs []PartitionProof,
// ) (*proof.PoStProof, error) {
// 	pp, err := toFilRegisteredPoStProof(proofType)
// 	if err != nil {
// 		return nil, err
// 	}

// 	fproofs, discard, err := toPartitionProofs(partitionProofs)
// 	defer discard()
// 	if err != nil {
// 		return nil, err
// 	}

// 	resp := cgo.MergeWindowPostPartitionProofs(
// 		pp,
// 		fproofs, uint(len(fproofs)),
// 	)
// 	resp.Deref()
// 	resp.Proof.Deref()

// 	defer cgo.DestroyMergeWindowPostPartitionProofsResponse(resp)

// 	if resp.StatusCode != cgo.FCPResponseStatusFCPNoError {
// 		return nil, errors.New(cgo.RawString(resp.ErrorMsg).Copy())
// 	}

// 	dpp, err := fromFilRegisteredPoStProof(resp.Proof.RegisteredProof)
// 	if err != nil {
// 		return nil, err
// 	}

// 	out := proof.PoStProof{
// 		PoStProof:  dpp,
// 		ProofBytes: copyBytes(resp.Proof.ProofPtr, resp.Proof.ProofLen),
// 	}

// 	return &out, nil
// }
