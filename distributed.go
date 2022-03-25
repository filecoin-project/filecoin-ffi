//go:build cgo
// +build cgo

package ffi

// import (
// 	"unsafe"

// 	"github.com/filecoin-project/filecoin-ffi/generated"
// 	"github.com/filecoin-project/go-state-types/abi"
// 	"github.com/filecoin-project/specs-actors/v5/actors/runtime/proof"
// 	"github.com/pkg/errors"
// )

// type FallbackChallenges struct {
// 	Sectors    []abi.SectorNumber
// 	Challenges map[abi.SectorNumber][]uint64
// }

// type VanillaProof []byte

// /// UnsafeByteSlice converts the ptr into a byte slice without copying.
// func UnsafeByteSlice(ptr unsafe.Pointer, len int) []byte {
// 	// It is a workaround for non-copying-wrapping of native memory.
// 	// C-encoder never pushes output block longer than ((2 << 25) + 502).
// 	// TODO: use unsafe.Slice, when it becomes available in go 1.17 (see https://golang.org/issue/13656).
// 	return (*[1 << 30]byte)(ptr)[:len:len]
// }

// /// UnsafeString converts the ptr into a string without copying.
// func UnsafeString(ptr unsafe.Pointer, len int) string {
// 	return string(UnsafeByteSlice(ptr, len))
// }

// func CastToUint64Slice(ptr []generated.Uint64T, len generated.SizeT) []uint64 {
// 	return (*[1 << 30]uint64)(unsafe.Pointer(&ptr[0]))[:len:len]
// }

// /// CheckErr returns `nil` if the `code` indicates success and an error otherwise.
// func CheckErr(code generated.FCPResponseStatusT, msg *generated.SliceBoxedUint8T) error {
// 	if code == generated.FCPRESPONSESTATUSNOERROR {
// 		return nil
// 	}

// 	return errors.New(UnsafeString(unsafe.Pointer(&msg.Ptr[0]), int(msg.Len)))
// }

// // GenerateWinningPoStSectorChallenge
// func GeneratePoStFallbackSectorChallenges(
// 	proofType abi.RegisteredPoStProof,
// 	minerID abi.ActorID,
// 	randomness abi.PoStRandomness,
// 	sectorIds []abi.SectorNumber,
// ) (*FallbackChallenges, error) {
// 	proverID, err := toProverID(minerID)
// 	if err != nil {
// 		return nil, err
// 	}

// 	pp, err := toFilRegisteredPoStProof(proofType)
// 	if err != nil {
// 		return nil, err
// 	}

// 	var secIds generated.SliceRefUint64T
// 	secIds.Len = generated.SizeT(len(sectorIds))
// 	secIds.Ptr = *(*[]generated.Uint64T)(unsafe.Pointer(&sectorIds[0]))

// 	resp := generated.GenerateFallbackSectorChallenges(
// 		pp, toByteArray32(randomness), secIds, proverID,
// 	)
// 	resp.Deref()

// 	defer generated.DestroyGenerateFallbackSectorChallengesResponse(resp)
// 	if err := CheckErr(resp.StatusCode, &resp.ErrorMsg); err != nil {
// 		return nil, err
// 	}

// 	// copy from C memory space to Go

// 	ids := resp.Value.Ids.Ptr[:int(resp.Value.Ids.Len)]
// 	challenges := CastToUint64Slice(resp.Value.Challenges.Ptr, resp.Value.Challenges.Len)

// 	var out FallbackChallenges
// 	out.Sectors = make([]abi.SectorNumber, len(ids))
// 	out.Challenges = make(map[abi.SectorNumber][]uint64)
// 	stride := int(resp.Value.ChallengesStride)
// 	for idx := range ids {
// 		secNum := abi.SectorNumber(ids[idx])
// 		out.Sectors[idx] = secNum
// 		out.Challenges[secNum] = append([]uint64{}, challenges[idx*stride:(idx+1)*stride]...)
// 	}

// 	return &out, nil
// }

// func GenerateSingleVanillaProof(
// 	replica PrivateSectorInfo,
// 	challenges []uint64,
// ) ([]byte, error) {

// 	rep, free, err := toFilPrivateReplicaInfo(replica)
// 	if err != nil {
// 		return nil, err
// 	}
// 	defer free()

// 	var challengesSlice generated.SliceRefUint64T
// 	challengesSlice.Len = generated.SizeT(len(challenges))
// 	challengesSlice.Ptr = (*[]generated.Uint64T)(unsafe.Pointer(&challenges[0]))

// 	resp := generated.GenerateSingleVanillaProof(rep, challengesSlice)
// 	resp.Deref()
// 	defer generated.DestroyGenerateSingleVanillaProofResponse(resp)

// 	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
// 		return nil, errors.New(generated.RawString(resp.ErrorMsg).Copy())
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

// 	resp := generated.GenerateWinningPostWithVanilla(
// 		pp,
// 		toByteArray32(randomness),
// 		proverID,
// 		fproofs, uint(len(proofs)),
// 	)
// 	resp.Deref()
// 	resp.ProofsPtr = make([]generated.PoStProof, resp.ProofsLen)
// 	resp.Deref()

// 	defer generated.DestroyGenerateWinningPostResponse(resp)

// 	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
// 		return nil, errors.New(generated.RawString(resp.ErrorMsg).Copy())
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

// 	resp := generated.GenerateWindowPostWithVanilla(
// 		pp,
// 		toByteArray32(randomness),
// 		proverID,
// 		fproofs, uint(len(proofs)),
// 	)
// 	resp.Deref()
// 	resp.ProofsPtr = make([]generated.PoStProof, resp.ProofsLen)
// 	resp.Deref()

// 	defer generated.DestroyGenerateWindowPostResponse(resp)

// 	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
// 		return nil, errors.New(generated.RawString(resp.ErrorMsg).Copy())
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

// 	resp := generated.GenerateSingleWindowPostWithVanilla(
// 		pp,
// 		toByteArray32(randomness),
// 		proverID,
// 		fproofs, uint(len(proofs)),
// 		partitionIndex,
// 	)
// 	resp.Deref()
// 	resp.PartitionProof.Deref()

// 	defer generated.DestroyGenerateSingleWindowPostWithVanillaResponse(resp)

// 	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
// 		return nil, errors.New(generated.RawString(resp.ErrorMsg).Copy())
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

// 	resp := generated.MergeWindowPostPartitionProofs(
// 		pp,
// 		fproofs, uint(len(fproofs)),
// 	)
// 	resp.Deref()
// 	resp.Proof.Deref()

// 	defer generated.DestroyMergeWindowPostPartitionProofsResponse(resp)

// 	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
// 		return nil, errors.New(generated.RawString(resp.ErrorMsg).Copy())
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
