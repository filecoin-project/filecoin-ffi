//go:build cgo
// +build cgo

package ffi

// import (
// 	"github.com/filecoin-project/filecoin-ffi/generated"
// 	commcid "github.com/filecoin-project/go-fil-commcid"
// 	"github.com/filecoin-project/go-state-types/abi"
// 	"github.com/filecoin-project/specs-actors/v7/actors/runtime/proof"
// 	"github.com/ipfs/go-cid"
// 	"github.com/pkg/errors"
// 	"golang.org/x/xerrors"
// )

// func toFilRegisteredUpdateProof(p abi.RegisteredUpdateProof) (generated.RegisteredUpdateProofT, error) {
// 	switch p {
// 	case abi.RegisteredUpdateProof_StackedDrg2KiBV1:
// 		return generated.RegisteredUpdateProofStackedDrg2KiBV1, nil
// 	case abi.RegisteredUpdateProof_StackedDrg8MiBV1:
// 		return generated.RegisteredUpdateProofStackedDrg8MiBV1, nil
// 	case abi.RegisteredUpdateProof_StackedDrg512MiBV1:
// 		return generated.RegisteredUpdateProofStackedDrg512MiBV1, nil
// 	case abi.RegisteredUpdateProof_StackedDrg32GiBV1:
// 		return generated.RegisteredUpdateProofStackedDrg32GiBV1, nil
// 	case abi.RegisteredUpdateProof_StackedDrg64GiBV1:
// 		return generated.RegisteredUpdateProofStackedDrg64GiBV1, nil
// 	default:
// 		return 0, errors.Errorf("no mapping to abi.RegisteredUpdateProof value available for: %v", p)
// 	}
// }

// //nolint:deadcode,unused
// func fromFilRegisteredUpdateProof(p generated.RegisteredUpdateProofT) (abi.RegisteredUpdateProof, error) {
// 	switch p {
// 	case generated.RegisteredUpdateProofStackedDrg2KiBV1:
// 		return abi.RegisteredUpdateProof_StackedDrg2KiBV1, nil
// 	case generated.RegisteredUpdateProofStackedDrg8MiBV1:
// 		return abi.RegisteredUpdateProof_StackedDrg8MiBV1, nil
// 	case generated.RegisteredUpdateProofStackedDrg512MiBV1:
// 		return abi.RegisteredUpdateProof_StackedDrg512MiBV1, nil
// 	case generated.RegisteredUpdateProofStackedDrg32GiBV1:
// 		return abi.RegisteredUpdateProof_StackedDrg32GiBV1, nil
// 	case generated.RegisteredUpdateProofStackedDrg64GiBV1:
// 		return abi.RegisteredUpdateProof_StackedDrg64GiBV1, nil
// 	default:
// 		return 0, errors.Errorf("no mapping to abi.RegisteredUpdateProof value available for: %v", p)
// 	}
// }

// type FunctionsSectorUpdate struct{}

// var SectorUpdate = FunctionsSectorUpdate{}

// func (FunctionsSectorUpdate) EncodeInto(
// 	proofType abi.RegisteredUpdateProof,
// 	newReplicaPath string,
// 	newReplicaCachePath string,
// 	sectorKeyPath string,
// 	sectorKeyCachePath string,
// 	stagedDataPath string,
// 	pieces []abi.PieceInfo,
// ) (sealedCID cid.Cid, unsealedCID cid.Cid, err error) {
// 	up, err := toFilRegisteredUpdateProof(proofType)
// 	if err != nil {
// 		return cid.Undef, cid.Undef, err
// 	}

// 	filPublicPieceInfos, filPublicPieceInfosLen, err := toFilPublicPieceInfos(pieces)
// 	if err != nil {
// 		return cid.Undef, cid.Undef, err
// 	}

// 	resp := generated.EmptySectorUpdateEncodeInto(
// 		up,
// 		newReplicaPath,
// 		newReplicaCachePath,
// 		sectorKeyPath,
// 		sectorKeyCachePath,
// 		stagedDataPath,
// 		filPublicPieceInfos, filPublicPieceInfosLen,
// 	)
// 	resp.Deref()
// 	defer generated.DestroyEmptySectorUpdateEncodeIntoResponse(resp)

// 	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
// 		return cid.Undef, cid.Undef, errors.New(generated.RawString(resp.ErrorMsg).Copy())
// 	}

// 	commR, errCommrSize := commcid.ReplicaCommitmentV1ToCID(resp.CommRNew[:])
// 	if errCommrSize != nil {
// 		return cid.Undef, cid.Undef, errCommrSize
// 	}
// 	commD, errCommdSize := commcid.DataCommitmentV1ToCID(resp.CommDNew[:])
// 	if errCommdSize != nil {
// 		return cid.Undef, cid.Undef, errCommdSize
// 	}

// 	return commR, commD, nil
// }

// func (FunctionsSectorUpdate) DecodeFrom(
// 	proofType abi.RegisteredUpdateProof,
// 	outDataPath string,
// 	replicaPath string,
// 	sectorKeyPath string,
// 	sectorKeyCachePath string,
// 	unsealedCID cid.Cid,
// ) error {
// 	up, err := toFilRegisteredUpdateProof(proofType)
// 	if err != nil {
// 		return err
// 	}

// 	commD, err := to32ByteCommD(unsealedCID)
// 	if err != nil {
// 		return err
// 	}

// 	resp := generated.EmptySectorUpdateDecodeFrom(
// 		up,
// 		outDataPath,
// 		replicaPath,
// 		sectorKeyPath,
// 		sectorKeyCachePath,
// 		commD,
// 	)
// 	resp.Deref()
// 	defer generated.DestroyEmptySectorUpdateDecodeFromResponse(resp)

// 	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
// 		return errors.New(generated.RawString(resp.ErrorMsg).Copy())
// 	}

// 	return nil
// }

// func (FunctionsSectorUpdate) RemoveData(
// 	proofType abi.RegisteredUpdateProof,
// 	sectorKeyPath string,
// 	sectorKeyCachePath string,
// 	replicaPath string,
// 	replicaCachePath string,
// 	dataPath string,
// 	unsealedCID cid.Cid,
// ) error {
// 	up, err := toFilRegisteredUpdateProof(proofType)
// 	if err != nil {
// 		return err
// 	}

// 	commD, err := to32ByteCommD(unsealedCID)
// 	if err != nil {
// 		return err
// 	}

// 	resp := generated.EmptySectorUpdateRemoveEncodedData(
// 		up,
// 		sectorKeyPath,
// 		sectorKeyCachePath,
// 		replicaPath,
// 		replicaCachePath,
// 		dataPath,
// 		commD,
// 	)
// 	resp.Deref()
// 	defer generated.DestroyEmptySectorUpdateRemoveEncodedDataResponse(resp)

// 	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
// 		return errors.New(generated.RawString(resp.ErrorMsg).Copy())
// 	}

// 	return nil
// }

// func (FunctionsSectorUpdate) GenerateUpdateVanillaProofs(
// 	proofType abi.RegisteredUpdateProof,
// 	oldSealedCID cid.Cid,
// 	newSealedCID cid.Cid,
// 	unsealedCID cid.Cid,
// 	newReplicaPath string,
// 	newReplicaCachePath string,
// 	sectorKeyPath string,
// 	sectorKeyCachePath string,
// ) ([][]byte, error) {
// 	up, err := toFilRegisteredUpdateProof(proofType)
// 	if err != nil {
// 		return nil, err
// 	}

// 	commRold, err := to32ByteCommR(oldSealedCID)
// 	if err != nil {
// 		return nil, xerrors.Errorf("transforming old CommR: %w", err)
// 	}
// 	commRnew, err := to32ByteCommR(newSealedCID)
// 	if err != nil {
// 		return nil, xerrors.Errorf("transforming new CommR: %w", err)
// 	}
// 	commD, err := to32ByteCommD(unsealedCID)
// 	if err != nil {
// 		return nil, xerrors.Errorf("transforming new CommD: %w", err)
// 	}

// 	resp := generated.GenerateEmptySectorUpdatePartitionProofs(
// 		up,
// 		commRold,
// 		commRnew,
// 		commD,
// 		sectorKeyPath,
// 		sectorKeyCachePath,
// 		newReplicaPath,
// 		newReplicaCachePath,
// 	)
// 	resp.Deref()
// 	defer generated.DestroyGenerateEmptySectorUpdatePartitionProofResponse(resp)

// 	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
// 		return nil, errors.New(generated.RawString(resp.ErrorMsg).Copy())
// 	}
// 	resp.ProofsPtr = make([]generated.PartitionProof, resp.ProofsLen)
// 	resp.Deref() // deref again after initializing length

// 	proofs := make([][]byte, resp.ProofsLen)
// 	for i, v := range resp.ProofsPtr {
// 		v.Deref()

// 		proofs[i] = copyBytes(v.ProofPtr, v.ProofLen)
// 	}

// 	return proofs, nil
// }

// func (FunctionsSectorUpdate) VerifyVanillaProofs(
// 	proofType abi.RegisteredUpdateProof,
// 	oldSealedCID cid.Cid,
// 	newSealedCID cid.Cid,
// 	unsealedCID cid.Cid,
// 	vanillaProofs [][]byte,
// ) (bool, error) {
// 	up, err := toFilRegisteredUpdateProof(proofType)
// 	if err != nil {
// 		return false, err
// 	}

// 	commRold, err := to32ByteCommR(oldSealedCID)
// 	if err != nil {
// 		return false, xerrors.Errorf("transorming old CommR: %w", err)
// 	}
// 	commRnew, err := to32ByteCommR(newSealedCID)
// 	if err != nil {
// 		return false, xerrors.Errorf("transorming new CommR: %w", err)
// 	}
// 	commD, err := to32ByteCommD(unsealedCID)
// 	if err != nil {
// 		return false, xerrors.Errorf("transorming new CommD: %w", err)
// 	}

// 	proofs, cleanup := toUpdateVanillaProofs(vanillaProofs)
// 	defer cleanup()

// 	resp := generated.VerifyEmptySectorUpdatePartitionProofs(
// 		up,
// 		uint(len(proofs)),
// 		proofs, // swapped, gotcha
// 		commRold,
// 		commRnew,
// 		commD,
// 	)
// 	resp.Deref()
// 	defer generated.DestroyVerifyEmptySectorUpdatePartitionProofResponse(resp)

// 	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
// 		return false, errors.New(generated.RawString(resp.ErrorMsg).Copy())
// 	}
// 	return resp.IsValid, nil
// }

// func (FunctionsSectorUpdate) GenerateUpdateProofWithVanilla(
// 	proofType abi.RegisteredUpdateProof,
// 	oldSealedCID cid.Cid,
// 	newSealedCID cid.Cid,
// 	unsealedCID cid.Cid,
// 	vanillaProofs [][]byte,
// ) ([]byte, error) {
// 	up, err := toFilRegisteredUpdateProof(proofType)
// 	if err != nil {
// 		return nil, err
// 	}

// 	commRold, err := to32ByteCommR(oldSealedCID)
// 	if err != nil {
// 		return nil, xerrors.Errorf("transorming old CommR: %w", err)
// 	}
// 	commRnew, err := to32ByteCommR(newSealedCID)
// 	if err != nil {
// 		return nil, xerrors.Errorf("transorming new CommR: %w", err)
// 	}
// 	commD, err := to32ByteCommD(unsealedCID)
// 	if err != nil {
// 		return nil, xerrors.Errorf("transorming new CommD: %w", err)
// 	}

// 	proofs, cleanup := toUpdateVanillaProofs(vanillaProofs)
// 	defer cleanup()

// 	resp := generated.GenerateEmptySectorUpdateProofWithVanilla(
// 		up,
// 		proofs,
// 		uint(len(proofs)),
// 		commRold,
// 		commRnew,
// 		commD,
// 	)
// 	resp.Deref()
// 	defer generated.DestroyEmptySectorUpdateGenerateProofResponse(resp)

// 	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
// 		return nil, errors.New(generated.RawString(resp.ErrorMsg).Copy())
// 	}
// 	return copyBytes(resp.ProofPtr, resp.ProofLen), nil
// }

// type Bytes = generated.ArrayUint8T

// func toUpdateVanillaProofs(src [][]byte) ([]Bytes, func()) {
// 	allocs := make([]AllocationManager, len(src))

// 	out := make([]Bytes, len(src))
// 	for idx := range out {
// 		out[idx] = Bytes {
// 			ProofLen: uint(len(src[idx])),
// 			ProofPtr: src[idx],
// 		}

// 		_, allocs[idx] = out[idx].PassRef()
// 	}

// 	return out, func() {
// 		for idx := range allocs {
// 			allocs[idx].Free()
// 		}
// 	}
// }

// func (FunctionsSectorUpdate) GenerateUpdateProof(
// 	proofType abi.RegisteredUpdateProof,
// 	oldSealedCID cid.Cid,
// 	newSealedCID cid.Cid,
// 	unsealedCID cid.Cid,
// 	newReplicaPath string,
// 	newReplicaCachePath string,
// 	sectorKeyPath string,
// 	sectorKeyCachePath string,
// ) ([]byte, error) {
// 	up, err := toFilRegisteredUpdateProof(proofType)
// 	if err != nil {
// 		return nil, err
// 	}

// 	commRold, err := to32ByteCommR(oldSealedCID)
// 	if err != nil {
// 		return nil, xerrors.Errorf("transorming old CommR: %w", err)
// 	}
// 	commRnew, err := to32ByteCommR(newSealedCID)
// 	if err != nil {
// 		return nil, xerrors.Errorf("transorming new CommR: %w", err)
// 	}
// 	commD, err := to32ByteCommD(unsealedCID)
// 	if err != nil {
// 		return nil, xerrors.Errorf("transorming new CommD: %w", err)
// 	}

// 	resp := generated.GenerateEmptySectorUpdateProof(
// 		up,
// 		commRold,
// 		commRnew,
// 		commD,
// 		sectorKeyPath,
// 		sectorKeyCachePath,
// 		newReplicaPath,
// 		newReplicaCachePath,
// 	)
// 	resp.Deref()
// 	defer generated.DestroyEmptySectorUpdateGenerateProofResponse(resp)

// 	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
// 		return nil, errors.New(generated.RawString(resp.ErrorMsg).Copy())
// 	}
// 	return copyBytes(resp.ProofPtr, resp.ProofLen), nil
// }

// func (FunctionsSectorUpdate) VerifyUpdateProof(info proof.ReplicaUpdateInfo) (bool, error) {
// 	up, err := toFilRegisteredUpdateProof(info.UpdateProofType)
// 	if err != nil {
// 		return false, err
// 	}

// 	commRold, err := to32ByteCommR(info.OldSealedSectorCID)
// 	if err != nil {
// 		return false, xerrors.Errorf("transforming old CommR: %w", err)
// 	}
// 	commRnew, err := to32ByteCommR(info.NewSealedSectorCID)
// 	if err != nil {
// 		return false, xerrors.Errorf("tranfsorming new CommR: %w", err)
// 	}
// 	commD, err := to32ByteCommD(info.NewUnsealedSectorCID)
// 	if err != nil {
// 		return false, xerrors.Errorf("transforming new CommD: %w", err)
// 	}

// 	resp := generated.VerifyEmptySectorUpdateProof(
// 		up,
// 		info.Proof,
// 		uint(len(info.Proof)),
// 		commRold,
// 		commRnew,
// 		commD,
// 	)
// 	resp.Deref()
// 	defer generated.DestroyEmptySectorUpdateVerifyProofResponse(resp)

// 	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
// 		return false, errors.New(generated.RawString(resp.ErrorMsg).Copy())
// 	}
// 	return resp.IsValid, nil
// }
