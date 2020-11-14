//+build cgo

package ffi

import (
	"github.com/filecoin-project/filecoin-ffi/generated"
	"github.com/filecoin-project/go-state-types/abi"
	"github.com/filecoin-project/specs-actors/actors/runtime/proof"
	"github.com/pkg/errors"
)

type FallbackChallenges struct {
	Sectors    []abi.SectorNumber
	Challenges map[abi.SectorNumber][]uint64
}

type VanillaProof []byte

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

	secIds := make([]uint64, len(sectorIds))
	for i, sid := range sectorIds {
		secIds[i] = uint64(sid)
	}

	resp := generated.FilGenerateFallbackSectorChallenges(
		pp, to32ByteArray(randomness), secIds, uint(len(secIds)),
		proverID,
	)
	resp.Deref()
	resp.IdsPtr = resp.IdsPtr[:resp.IdsLen]
	resp.ChallengesPtr = resp.ChallengesPtr[:resp.ChallengesLen]

	defer generated.FilDestroyGenerateFallbackSectorChallengesResponse(resp)

	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
		return nil, errors.New(generated.RawString(resp.ErrorMsg).Copy())
	}

	// copy from C memory space to Go

	var out FallbackChallenges
	out.Sectors = make([]abi.SectorNumber, resp.IdsLen)
	out.Challenges = make(map[abi.SectorNumber][]uint64)
	stride := int(resp.ChallengesStride)
	for idx := range resp.IdsPtr {
		secNum := abi.SectorNumber(resp.IdsPtr[idx])
		out.Sectors[idx] = secNum
		out.Challenges[secNum] = append([]uint64{}, resp.ChallengesPtr[idx*stride:(idx+1)*stride]...)
	}

	return &out, nil
}

func GenerateSingleVanillaProof(
	replica PrivateSectorInfo,
	challange []uint64,
) ([]byte, error) {

	rep, free, err := toFilPrivateReplicaInfo(replica)
	if err != nil {
		return nil, err
	}
	defer free()

	resp := generated.FilGenerateSingleVanillaProof(rep, challange, uint(len(challange)))
	resp.Deref()
	defer generated.FilDestroyGenerateSingleVanillaProofResponse(resp)

	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
		return nil, errors.New(generated.RawString(resp.ErrorMsg).Copy())
	}

	resp.VanillaProof.Deref()

	return copyBytes(resp.VanillaProof.ProofPtr, resp.VanillaProof.ProofLen), nil
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
	fproofs, discard := toVanillaProofs(proofs)
	defer discard()

	resp := generated.FilGenerateWinningPostWithVanilla(
		pp,
		to32ByteArray(randomness),
		proverID,
		fproofs, uint(len(proofs)),
	)
	resp.Deref()
	resp.ProofsPtr = make([]generated.FilPoStProof, resp.ProofsLen)
	resp.Deref()

	defer generated.FilDestroyGenerateWinningPostResponse(resp)

	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
		return nil, errors.New(generated.RawString(resp.ErrorMsg).Copy())
	}

	out, err := fromFilPoStProofs(resp.ProofsPtr)
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
	fproofs, discard := toVanillaProofs(proofs)
	defer discard()

	resp := generated.FilGenerateWindowPostWithVanilla(
		pp,
		to32ByteArray(randomness),
		proverID,
		fproofs, uint(len(proofs)),
	)
	resp.Deref()
	resp.ProofsPtr = make([]generated.FilPoStProof, resp.ProofsLen)
	resp.Deref()

	defer generated.FilDestroyGenerateWindowPostResponse(resp)

	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
		return nil, errors.New(generated.RawString(resp.ErrorMsg).Copy())
	}

	out, err := fromFilPoStProofs(resp.ProofsPtr)
	if err != nil {
		return nil, err
	}

	return out, nil
}
