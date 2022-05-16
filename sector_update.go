//go:build cgo
// +build cgo

package ffi

import (
	"github.com/filecoin-project/filecoin-ffi/cgo"
	commcid "github.com/filecoin-project/go-fil-commcid"
	"github.com/filecoin-project/go-state-types/abi"
	"github.com/filecoin-project/go-state-types/proof"
	"github.com/ipfs/go-cid"
	"github.com/pkg/errors"
	"golang.org/x/xerrors"
)

func toFilRegisteredUpdateProof(p abi.RegisteredUpdateProof) (cgo.RegisteredUpdateProof, error) {
	switch p {
	case abi.RegisteredUpdateProof_StackedDrg2KiBV1:
		return cgo.RegisteredUpdateProofStackedDrg2KiBV1, nil
	case abi.RegisteredUpdateProof_StackedDrg8MiBV1:
		return cgo.RegisteredUpdateProofStackedDrg8MiBV1, nil
	case abi.RegisteredUpdateProof_StackedDrg512MiBV1:
		return cgo.RegisteredUpdateProofStackedDrg512MiBV1, nil
	case abi.RegisteredUpdateProof_StackedDrg32GiBV1:
		return cgo.RegisteredUpdateProofStackedDrg32GiBV1, nil
	case abi.RegisteredUpdateProof_StackedDrg64GiBV1:
		return cgo.RegisteredUpdateProofStackedDrg64GiBV1, nil
	default:
		return 0, errors.Errorf("no mapping to abi.RegisteredUpdateProof value available for: %v", p)
	}
}

//nolint:deadcode,unused
func fromFilRegisteredUpdateProof(p cgo.RegisteredUpdateProof) (abi.RegisteredUpdateProof, error) {
	switch p {
	case cgo.RegisteredUpdateProofStackedDrg2KiBV1:
		return abi.RegisteredUpdateProof_StackedDrg2KiBV1, nil
	case cgo.RegisteredUpdateProofStackedDrg8MiBV1:
		return abi.RegisteredUpdateProof_StackedDrg8MiBV1, nil
	case cgo.RegisteredUpdateProofStackedDrg512MiBV1:
		return abi.RegisteredUpdateProof_StackedDrg512MiBV1, nil
	case cgo.RegisteredUpdateProofStackedDrg32GiBV1:
		return abi.RegisteredUpdateProof_StackedDrg32GiBV1, nil
	case cgo.RegisteredUpdateProofStackedDrg64GiBV1:
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

	filPublicPieceInfos, err := toFilPublicPieceInfos(pieces)
	if err != nil {
		return cid.Undef, cid.Undef, err
	}

	commRRaw, commDRaw, err := cgo.EmptySectorUpdateEncodeInto(
		up,
		cgo.AsSliceRefUint8([]byte(newReplicaPath)),
		cgo.AsSliceRefUint8([]byte(newReplicaCachePath)),
		cgo.AsSliceRefUint8([]byte(sectorKeyPath)),
		cgo.AsSliceRefUint8([]byte(sectorKeyCachePath)),
		cgo.AsSliceRefUint8([]byte(stagedDataPath)),
		cgo.AsSliceRefPublicPieceInfo(filPublicPieceInfos),
	)
	if err != nil {
		return cid.Undef, cid.Undef, err
	}

	commR, errCommrSize := commcid.ReplicaCommitmentV1ToCID(commRRaw)
	if errCommrSize != nil {
		return cid.Undef, cid.Undef, errCommrSize
	}
	commD, errCommdSize := commcid.DataCommitmentV1ToCID(commDRaw)
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

	return cgo.EmptySectorUpdateDecodeFrom(
		up,
		cgo.AsSliceRefUint8([]byte(outDataPath)),
		cgo.AsSliceRefUint8([]byte(replicaPath)),
		cgo.AsSliceRefUint8([]byte(sectorKeyPath)),
		cgo.AsSliceRefUint8([]byte(sectorKeyCachePath)),
		&commD,
	)
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

	return cgo.EmptySectorUpdateRemoveEncodedData(
		up,
		cgo.AsSliceRefUint8([]byte(sectorKeyPath)),
		cgo.AsSliceRefUint8([]byte(sectorKeyCachePath)),
		cgo.AsSliceRefUint8([]byte(replicaPath)),
		cgo.AsSliceRefUint8([]byte(replicaCachePath)),
		cgo.AsSliceRefUint8([]byte(dataPath)),
		&commD,
	)
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

	return cgo.GenerateEmptySectorUpdatePartitionProofs(
		up,
		&commRold,
		&commRnew,
		&commD,
		cgo.AsSliceRefUint8([]byte(sectorKeyPath)),
		cgo.AsSliceRefUint8([]byte(sectorKeyCachePath)),
		cgo.AsSliceRefUint8([]byte(newReplicaPath)),
		cgo.AsSliceRefUint8([]byte(newReplicaCachePath)),
	)
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

	return cgo.VerifyEmptySectorUpdatePartitionProofs(
		up,
		cgo.AsSliceRefSliceBoxedUint8(proofs),
		&commRold,
		&commRnew,
		&commD,
	)
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

	return cgo.GenerateEmptySectorUpdateProofWithVanilla(
		up,
		cgo.AsSliceRefSliceBoxedUint8(proofs),
		&commRold,
		&commRnew,
		&commD,
	)
}

func toUpdateVanillaProofs(src [][]byte) ([]cgo.SliceBoxedUint8, func()) {
	out := make([]cgo.SliceBoxedUint8, len(src))
	for idx := range out {
		out[idx] = cgo.AllocSliceBoxedUint8(src[idx])
	}

	return out, func() {
		for idx := range out {
			out[idx].Destroy()
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

	return cgo.GenerateEmptySectorUpdateProof(
		up,
		&commRold,
		&commRnew,
		&commD,
		cgo.AsSliceRefUint8([]byte(sectorKeyPath)),
		cgo.AsSliceRefUint8([]byte(sectorKeyCachePath)),
		cgo.AsSliceRefUint8([]byte(newReplicaPath)),
		cgo.AsSliceRefUint8([]byte(newReplicaCachePath)),
	)
}

func (FunctionsSectorUpdate) VerifyUpdateProof(info proof.ReplicaUpdateInfo) (bool, error) {
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

	return cgo.VerifyEmptySectorUpdateProof(
		up,
		cgo.AsSliceRefUint8(info.Proof),
		&commRold,
		&commRnew,
		&commD,
	)
}
