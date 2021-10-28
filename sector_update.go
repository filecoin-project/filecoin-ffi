package ffi

import (
	"github.com/filecoin-project/filecoin-ffi/generated"
	commcid "github.com/filecoin-project/go-fil-commcid"
	"github.com/filecoin-project/go-state-types/abi"
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

func (_ FunctionsSectorUpdate) EncodeInto(
	proofType abi.RegisteredUpdateProof,
	newReplicaPath string,
	newReplicaCachePath string,
	sectorKePath string,
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
		sectorKePath,
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

func (_ FunctionsSectorUpdate) DecodeFrom(
	proofType abi.RegisteredUpdateProof,
	outDataPath string,
	replicaPath string,
	sectorKePath string,
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
		sectorKePath,
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

func (_ FunctionsSectorUpdate) RemoveData(
	proofType abi.RegisteredUpdateProof,
	sectorKePath string,
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
		sectorKePath,
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

func (_ FunctionsSectorUpdate) GenerateUpdateProof(
	proofType abi.RegisteredUpdateProof,
	oldSealedCID cid.Cid,
	newSealedCID cid.Cid,
	unsealedCID cid.Cid,
	newReplicaPath string,
	newReplicaCachePath string,
	sectorKePath string,
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
		sectorKePath,
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

func (_ FunctionsSectorUpdate) VerifyUpdateProof(
	proofType abi.RegisteredUpdateProof,
	proof []byte,
	oldSealedCID cid.Cid,
	newSealedCID cid.Cid,
	unsealedCID cid.Cid,
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

	resp := generated.FilVerifyEmptySectorUpdateProof(
		up,
		proof,
		uint(len(proof)),
		commRold,
		commRnew,
		commD,
		"this should not be needed REMOVE ME",
	)
	resp.Deref()
	defer generated.FilDestroyEmptySectorUpdateVerifyProofResponse(resp)

	if resp.StatusCode != generated.FCPResponseStatusFCPNoError {
		return false, errors.New(generated.RawString(resp.ErrorMsg).Copy())
	}
	return resp.IsValid, nil
}
