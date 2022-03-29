package cgo

/*
#cgo LDFLAGS: -L${SRCDIR}/..
#cgo pkg-config: ${SRCDIR}/../filcrypto.pc
#include "../filcrypto.h"
#include <stdlib.h>
*/
import "C"

func VerifySeal(registeredProof RegisteredSealProof, commR *ByteArray32, commD *ByteArray32, proverId *ByteArray32, ticket *ByteArray32, seed *ByteArray32, sectorId uint64, proof SliceRefUint8) (bool, error) {
	resp := C.verify_seal(registeredProof, commR, commD, proverId, ticket, seed, C.uint64_t(sectorId), proof)
	defer resp.Destroy()

	if err := CheckErr(resp); err != nil {
		return false, err
	}

	return bool(resp.value), nil
}

func VerifyAggregateSealProof(registeredProof RegisteredSealProof, registeredAggregation RegisteredAggregationProof, proverId *ByteArray32, proof SliceRefUint8, commitInputs SliceRefAggregationInputs) (bool, error) {
	resp := C.verify_aggregate_seal_proof(registeredProof, registeredAggregation, proverId, proof, commitInputs)
	defer resp.Destroy()

	if err := CheckErr(resp); err != nil {
		return false, err
	}
	return bool(resp.value), nil
}

func VerifyWinningPoSt(randomness *ByteArray32, replicas SliceRefPublicReplicaInfo, proofs SliceRefPoStProof, proverId *ByteArray32) (bool, error) {
	resp := C.verify_winning_post(randomness, replicas, proofs, proverId)
	defer resp.Destroy()

	if err := CheckErr(resp); err != nil {
		return false, err
	}

	return bool(resp.value), nil
}

func VerifyWindowPoSt(randomness *ByteArray32, replicas SliceRefPublicReplicaInfo, proofs SliceRefPoStProof, proverId *ByteArray32) (bool, error) {
	resp := C.verify_window_post(randomness, replicas, proofs, proverId)
	defer resp.Destroy()

	if err := CheckErr(resp); err != nil {
		return false, err
	}

	return bool(resp.value), nil
}

func GeneratePieceCommitment(registeredProof RegisteredSealProof, pieceFdRaw int32, unpaddedPieceSize uint64) ([]byte, error) {
	resp := C.generate_piece_commitment(registeredProof, C.int32_t(pieceFdRaw), C.uint64_t(unpaddedPieceSize))
	defer resp.Destroy()

	if err := CheckErr(resp); err != nil {
		return nil, err
	}

	return resp.value.comm_p.Copy(), nil
}

func GenerateDataCommitment(registeredProof RegisteredSealProof, pieces SliceRefPublicPieceInfo) ([]byte, error) {
	resp := C.generate_data_commitment(registeredProof, pieces)
	defer resp.Destroy()

	if err := CheckErr(resp); err != nil {
		return nil, err
	}

	return resp.value.Copy(), nil
}
