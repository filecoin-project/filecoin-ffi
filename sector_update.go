//go:build cgo
// +build cgo

package ffi

import (
	"github.com/filecoin-project/filecoin-ffi/generated"
	commcid "github.com/filecoin-project/go-fil-commcid"
	"github.com/filecoin-project/go-state-types/abi"
	"github.com/filecoin-project/go-state-types/builtin/v8/miner"
	"github.com/ipfs/go-cid"
	"github.com/pkg/errors"
	"golang.org/x/xerrors"
)

func toFilRegisteredUpdateProof(p abi.RegisteredUpdateProof) (generated.FilRegisteredUpdateProof, error) {
	switch p {
	case abi.RegisteredUpdateProof_StackedDrg2KiBV1:
		return generated.FilRegisteredUpdateProofStackedDrg2KiBV1, nil
	case abi.RegisteredUpdateProof_StackedDrg8MiBV1:
		return generated.FilRegisteredUpdateProofStackedDrg8MiBV1, nil
	case abi.RegisteredUpdateProof_StackedDrg512MiBV1:
		return generated.FilRegisteredUpdateProofStackedDrg512MiBV1, nil
	case abi.RegisteredUpdateProof_StackedDrg32GiBV1:
		return generated.FilRegisteredUpdateProofStackedDrg32GiBV1, nil
	case abi.RegisteredUpdateProof_StackedDrg64GiBV1:
		return generated.FilRegisteredUpdateProofStackedDrg64GiBV1, nil
	default:
		return 0, errors.Errorf("no mapping to abi.RegisteredUpdateProof value available for: %v", p)
	}
}

//nolint:deadcode,unused
func fromFilRegisteredUpdateProof(p generated.FilRegisteredUpdateProof) (abi.RegisteredUpdateProof, error) {
	switch p {
	case generated.FilRegisteredUpdateProofStackedDrg2KiBV1:
		return abi.RegisteredUpdateProof_StackedDrg2KiBV1, nil
	case generated.FilRegisteredUpdateProofStackedDrg8MiBV1:
		return abi.RegisteredUpdateProof_StackedDrg8MiBV1, nil
	case generated.FilRegisteredUpdateProofStackedDrg512MiBV1:
		return abi.RegisteredUpdateProof_StackedDrg512MiBV1, nil
	case generated.FilRegisteredUpdateProofStackedDrg32GiBV1:
		return abi.RegisteredUpdateProof_StackedDrg32GiBV1, nil
	case generated.FilRegisteredUpdateProofStackedDrg64GiBV1:
		return abi.RegisteredUpdateProof_StackedDrg64GiBV1, nil
	default:
		return 0, errors.Errorf("no mapping to abi.RegisteredUpdateProof value available for: %v", p)
	}
}

type FunctionsSectorUpdate struct{}

var SectorUpdate = FunctionsSectorUpdate{}

func (FunctionsSectorUpdate) EncodeInto(
	proofType abi.RegisteredUpdateProof,
	newReplicaPath string,
	newReplicaCachePath string,
	sectorKeyPath string,
	sectorKeyCachePath string,
	stagedDataPath string,
	pieces []abi.PieceInfo,
) (sealedCID cid.Cid, unsealedCID cid.Cid, err error) {
	up, err := toFilRegisteredUpdateProof(proofType)
	if err != nil {
		return cid.Undef, cid.Undef, err
	}

	filPublicPieceInfos, filPublicPieceInfosLen, err := toFilPublicPieceInfos(pieces)
	if err != nil {
		return cid.Undef, cid.Undef, err
	}

	resp := generated.FilEmptySectorUpdateEncodeInto(
		up,
		newReplicaPath,
		newReplicaCachePath,
		sectorKeyPath,
		sectorKeyCachePath,
		stagedDataPath,
		filPublicPieceInfos, filPublicPieceInfosLen,
	)
	resp.Deref()
	defer generated.FilDestroyEmptySectorUpdateEncodeIntoResponse(resp)

	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
		return cid.Undef, cid.Undef, errors.New(generated.RawString(resp.ErrorMsg).Copy())
	}

	commR, errCommrSize := commcid.ReplicaCommitmentV1ToCID(resp.CommRNew[:])
	if errCommrSize != nil {
		return cid.Undef, cid.Undef, errCommrSize
	}
	commD, errCommdSize := commcid.DataCommitmentV1ToCID(resp.CommDNew[:])
	if errCommdSize != nil {
		return cid.Undef, cid.Undef, errCommdSize
	}

	return commR, commD, nil
}

func (FunctionsSectorUpdate) DecodeFrom(
	proofType abi.RegisteredUpdateProof,
	outDataPath string,
	replicaPath string,
	sectorKeyPath string,
	sectorKeyCachePath string,
	unsealedCID cid.Cid,
) error {
	up, err := toFilRegisteredUpdateProof(proofType)
	if err != nil {
		return err
	}

	commD, err := to32ByteCommD(unsealedCID)
	if err != nil {
		return err
	}

	resp := generated.FilEmptySectorUpdateDecodeFrom(
		up,
		outDataPath,
		replicaPath,
		sectorKeyPath,
		sectorKeyCachePath,
		commD,
	)
	resp.Deref()
	defer generated.FilDestroyEmptySectorUpdateDecodeFromResponse(resp)

	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
		return errors.New(generated.RawString(resp.ErrorMsg).Copy())
	}

	return nil
}

func (FunctionsSectorUpdate) RemoveData(
	proofType abi.RegisteredUpdateProof,
	sectorKeyPath string,
	sectorKeyCachePath string,
	replicaPath string,
	replicaCachePath string,
	dataPath string,
	unsealedCID cid.Cid,
) error {
	up, err := toFilRegisteredUpdateProof(proofType)
	if err != nil {
		return err
	}

	commD, err := to32ByteCommD(unsealedCID)
	if err != nil {
		return err
	}

	resp := generated.FilEmptySectorUpdateRemoveEncodedData(
		up,
		sectorKeyPath,
		sectorKeyCachePath,
		replicaPath,
		replicaCachePath,
		dataPath,
		commD,
	)
	resp.Deref()
	defer generated.FilDestroyEmptySectorUpdateRemoveEncodedDataResponse(resp)

	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
		return errors.New(generated.RawString(resp.ErrorMsg).Copy())
	}

	return nil
}

func (FunctionsSectorUpdate) GenerateUpdateVanillaProofs(
	proofType abi.RegisteredUpdateProof,
	oldSealedCID cid.Cid,
	newSealedCID cid.Cid,
	unsealedCID cid.Cid,
	newReplicaPath string,
	newReplicaCachePath string,
	sectorKeyPath string,
	sectorKeyCachePath string,
) ([][]byte, error) {
	up, err := toFilRegisteredUpdateProof(proofType)
	if err != nil {
		return nil, err
	}

	commRold, err := to32ByteCommR(oldSealedCID)
	if err != nil {
		return nil, xerrors.Errorf("transforming old CommR: %w", err)
	}
	commRnew, err := to32ByteCommR(newSealedCID)
	if err != nil {
		return nil, xerrors.Errorf("transforming new CommR: %w", err)
	}
	commD, err := to32ByteCommD(unsealedCID)
	if err != nil {
		return nil, xerrors.Errorf("transforming new CommD: %w", err)
	}

	resp := generated.FilGenerateEmptySectorUpdatePartitionProofs(
		up,
		commRold,
		commRnew,
		commD,
		sectorKeyPath,
		sectorKeyCachePath,
		newReplicaPath,
		newReplicaCachePath,
	)
	resp.Deref()
	defer generated.FilDestroyGenerateEmptySectorUpdatePartitionProofResponse(resp)

	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
		return nil, errors.New(generated.RawString(resp.ErrorMsg).Copy())
	}
	resp.ProofsPtr = make([]generated.FilPartitionProof, resp.ProofsLen)
	resp.Deref() // deref again after initializing length

	proofs := make([][]byte, resp.ProofsLen)
	for i, v := range resp.ProofsPtr {
		v.Deref()

		proofs[i] = copyBytes(v.ProofPtr, v.ProofLen)
	}

	return proofs, nil
}

func (FunctionsSectorUpdate) VerifyVanillaProofs(
	proofType abi.RegisteredUpdateProof,
	oldSealedCID cid.Cid,
	newSealedCID cid.Cid,
	unsealedCID cid.Cid,
	vanillaProofs [][]byte,
) (bool, error) {
	up, err := toFilRegisteredUpdateProof(proofType)
	if err != nil {
		return false, err
	}

	commRold, err := to32ByteCommR(oldSealedCID)
	if err != nil {
		return false, xerrors.Errorf("transorming old CommR: %w", err)
	}
	commRnew, err := to32ByteCommR(newSealedCID)
	if err != nil {
		return false, xerrors.Errorf("transorming new CommR: %w", err)
	}
	commD, err := to32ByteCommD(unsealedCID)
	if err != nil {
		return false, xerrors.Errorf("transorming new CommD: %w", err)
	}

	proofs, cleanup := toUpdateVanillaProofs(vanillaProofs)
	defer cleanup()

	resp := generated.FilVerifyEmptySectorUpdatePartitionProofs(
		up,
		uint(len(proofs)),
		proofs, // swapped, gotcha
		commRold,
		commRnew,
		commD,
	)
	resp.Deref()
	defer generated.FilDestroyVerifyEmptySectorUpdatePartitionProofResponse(resp)

	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
		return false, errors.New(generated.RawString(resp.ErrorMsg).Copy())
	}
	return resp.IsValid, nil
}

func (FunctionsSectorUpdate) GenerateUpdateProofWithVanilla(
	proofType abi.RegisteredUpdateProof,
	oldSealedCID cid.Cid,
	newSealedCID cid.Cid,
	unsealedCID cid.Cid,
	vanillaProofs [][]byte,
) ([]byte, error) {
	up, err := toFilRegisteredUpdateProof(proofType)
	if err != nil {
		return nil, err
	}

	commRold, err := to32ByteCommR(oldSealedCID)
	if err != nil {
		return nil, xerrors.Errorf("transorming old CommR: %w", err)
	}
	commRnew, err := to32ByteCommR(newSealedCID)
	if err != nil {
		return nil, xerrors.Errorf("transorming new CommR: %w", err)
	}
	commD, err := to32ByteCommD(unsealedCID)
	if err != nil {
		return nil, xerrors.Errorf("transorming new CommD: %w", err)
	}

	proofs, cleanup := toUpdateVanillaProofs(vanillaProofs)
	defer cleanup()

	resp := generated.FilGenerateEmptySectorUpdateProofWithVanilla(
		up,
		proofs,
		uint(len(proofs)),
		commRold,
		commRnew,
		commD,
	)
	resp.Deref()
	defer generated.FilDestroyEmptySectorUpdateGenerateProofResponse(resp)

	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
		return nil, errors.New(generated.RawString(resp.ErrorMsg).Copy())
	}
	return copyBytes(resp.ProofPtr, resp.ProofLen), nil
}

func toUpdateVanillaProofs(src [][]byte) ([]generated.FilPartitionProof, func()) {
	allocs := make([]AllocationManager, len(src))

	out := make([]generated.FilPartitionProof, len(src))
	for idx := range out {
		out[idx] = generated.FilPartitionProof{
			ProofLen: uint(len(src[idx])),
			ProofPtr: src[idx],
		}

		_, allocs[idx] = out[idx].PassRef()
	}

	return out, func() {
		for idx := range allocs {
			allocs[idx].Free()
		}
	}
}

func (FunctionsSectorUpdate) GenerateUpdateProof(
	proofType abi.RegisteredUpdateProof,
	oldSealedCID cid.Cid,
	newSealedCID cid.Cid,
	unsealedCID cid.Cid,
	newReplicaPath string,
	newReplicaCachePath string,
	sectorKeyPath string,
	sectorKeyCachePath string,
) ([]byte, error) {
	up, err := toFilRegisteredUpdateProof(proofType)
	if err != nil {
		return nil, err
	}

	commRold, err := to32ByteCommR(oldSealedCID)
	if err != nil {
		return nil, xerrors.Errorf("transorming old CommR: %w", err)
	}
	commRnew, err := to32ByteCommR(newSealedCID)
	if err != nil {
		return nil, xerrors.Errorf("transorming new CommR: %w", err)
	}
	commD, err := to32ByteCommD(unsealedCID)
	if err != nil {
		return nil, xerrors.Errorf("transorming new CommD: %w", err)
	}

	resp := generated.FilGenerateEmptySectorUpdateProof(
		up,
		commRold,
		commRnew,
		commD,
		sectorKeyPath,
		sectorKeyCachePath,
		newReplicaPath,
		newReplicaCachePath,
	)
	resp.Deref()
	defer generated.FilDestroyEmptySectorUpdateGenerateProofResponse(resp)

	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
		return nil, errors.New(generated.RawString(resp.ErrorMsg).Copy())
	}
	return copyBytes(resp.ProofPtr, resp.ProofLen), nil
}

func (FunctionsSectorUpdate) VerifyUpdateProof(info miner.ReplicaUpdateInfo) (bool, error) {
	up, err := toFilRegisteredUpdateProof(info.UpdateProofType)
	if err != nil {
		return false, err
	}

	commRold, err := to32ByteCommR(info.OldSealedSectorCID)
	if err != nil {
		return false, xerrors.Errorf("transforming old CommR: %w", err)
	}
	commRnew, err := to32ByteCommR(info.NewSealedSectorCID)
	if err != nil {
		return false, xerrors.Errorf("tranfsorming new CommR: %w", err)
	}
	commD, err := to32ByteCommD(info.NewUnsealedSectorCID)
	if err != nil {
		return false, xerrors.Errorf("transforming new CommD: %w", err)
	}

	resp := generated.FilVerifyEmptySectorUpdateProof(
		up,
		info.Proof,
		uint(len(info.Proof)),
		commRold,
		commRnew,
		commD,
	)
	resp.Deref()
	defer generated.FilDestroyEmptySectorUpdateVerifyProofResponse(resp)

	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
		return false, errors.New(generated.RawString(resp.ErrorMsg).Copy())
	}
	return resp.IsValid, nil
}
