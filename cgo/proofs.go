package cgo

/*
#cgo LDFLAGS: -L${SRCDIR}/..
#cgo pkg-config: ${SRCDIR}/../filcrypto.pc
#include "../filcrypto.h"
#include <stdlib.h>
*/
import "C"

func VerifySeal(registeredProof RegisteredSealProof, commR *ByteArray32, commD *ByteArray32, proverId *ByteArray32, ticket *ByteArray32, seed *ByteArray32, sectorId uint64, proof SliceRefUint8) (bool, error) {
	resp := (*resultBool)(C.verify_seal(
		(C.RegisteredSealProof_t)(registeredProof),
		(*C.uint8_32_array_t)(commR),
		(*C.uint8_32_array_t)(commD),
		(*C.uint8_32_array_t)(proverId),
		(*C.uint8_32_array_t)(ticket),
		(*C.uint8_32_array_t)(seed),
		C.uint64_t(sectorId),
		(C.slice_ref_uint8_t)(proof)))
	defer resp.destroy()

	if err := CheckErr(resp); err != nil {
		return false, err
	}

	return bool(resp.value), nil
}

func VerifyAggregateSealProof(registeredProof RegisteredSealProof, registeredAggregation RegisteredAggregationProof, proverId *ByteArray32, proof SliceRefUint8, commitInputs SliceRefAggregationInputs) (bool, error) {
	resp := (*resultBool)(C.verify_aggregate_seal_proof(
		(C.RegisteredSealProof_t)(registeredProof),
		(C.RegisteredAggregationProof_t)(registeredAggregation),
		(*C.uint8_32_array_t)(proverId),
		(C.slice_ref_uint8_t)(proof),
		(C.slice_ref_AggregationInputs_t)(commitInputs)))
	defer resp.destroy()

	if err := CheckErr(resp); err != nil {
		return false, err
	}
	return bool(resp.value), nil
}

func VerifyWinningPoSt(randomness *ByteArray32, replicas SliceRefPublicReplicaInfo, proofs SliceRefPoStProof, proverId *ByteArray32) (bool, error) {
	resp := (*resultBool)(C.verify_winning_post(
		(*C.uint8_32_array_t)(randomness),
		(C.slice_ref_PublicReplicaInfo_t)(replicas),
		(C.slice_ref_PoStProof_t)(proofs),
		(*C.uint8_32_array_t)(proverId)))
	defer resp.destroy()

	if err := CheckErr(resp); err != nil {
		return false, err
	}

	return bool(resp.value), nil
}

func VerifyWindowPoSt(randomness *ByteArray32, replicas SliceRefPublicReplicaInfo, proofs SliceRefPoStProof, proverId *ByteArray32) (bool, error) {
	resp := (*resultBool)(C.verify_window_post(
		(*C.uint8_32_array_t)(randomness),
		(C.slice_ref_PublicReplicaInfo_t)(replicas),
		(C.slice_ref_PoStProof_t)(proofs),
		(*C.uint8_32_array_t)(proverId)))
	defer resp.destroy()

	if err := CheckErr(resp); err != nil {
		return false, err
	}

	return bool(resp.value), nil
}

func GeneratePieceCommitment(registeredProof RegisteredSealProof, pieceFdRaw int32, unpaddedPieceSize uint64) ([]byte, error) {
	resp := (*resultGeneratePieceCommitment)(C.generate_piece_commitment(
		(C.RegisteredSealProof_t)(registeredProof),
		C.int32_t(pieceFdRaw),
		C.uint64_t(unpaddedPieceSize)))
	defer resp.destroy()

	if err := CheckErr(resp); err != nil {
		return nil, err
	}

	return (*ByteArray32)(&resp.value.comm_p).copy(), nil
}

func GenerateDataCommitment(registeredProof RegisteredSealProof, pieces SliceRefPublicPieceInfo) ([]byte, error) {
	resp := (*resultByteArray32)(C.generate_data_commitment(
		(C.RegisteredSealProof_t)(registeredProof),
		(C.slice_ref_PublicPieceInfo_t)(pieces)))
	defer resp.destroy()

	if err := CheckErr(resp); err != nil {
		return nil, err
	}

	return (*ByteArray32)(&resp.value).copy(), nil
}

func WriteWithAlignment(registeredProof RegisteredSealProof, srcFd int32, srcSize uint64, dstFd int32, existingPieceSizes SliceRefUint64) (uint64, uint64, []byte, error) {
	resp := (*resultWriteWithAlignment)(C.write_with_alignment(
		(C.RegisteredSealProof_t)(registeredProof),
		C.int32_t(srcFd),
		C.uint64_t(srcSize),
		C.int32_t(dstFd),
		(C.slice_ref_uint64_t)(existingPieceSizes)))
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return 0, 0, nil, err
	}

	return uint64(resp.value.left_alignment_unpadded),
		uint64(resp.value.total_write_unpadded),
		(*ByteArray32)(&resp.value.comm_p).copy(),
		nil
}

func WriteWithoutAlignment(registeredProof RegisteredSealProof, srcFd int32, srcSize uint64, dstFd int32) (uint64, []byte, error) {
	resp := (*resultWriteWithoutAlignment)(C.write_without_alignment(
		(C.RegisteredSealProof_t)(registeredProof),
		C.int32_t(srcFd),
		C.uint64_t(srcSize),
		C.int32_t(dstFd)))
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return 0, nil, err
	}

	return uint64(resp.value.total_write_unpadded),
		(*ByteArray32)(&resp.value.comm_p).copy(),
		nil
}

func SealPreCommitPhase1(registeredProof RegisteredSealProof, cacheDirPath SliceRefUint8, stagedSectorPath SliceRefUint8, sealedSectorPath SliceRefUint8, sectorId uint64, proverId *ByteArray32, ticket *ByteArray32, pieces SliceRefPublicPieceInfo) ([]byte, error) {
	resp := (*resultSliceBoxedUint8)(C.seal_pre_commit_phase1(
		(C.RegisteredSealProof_t)(registeredProof),
		(C.slice_ref_uint8_t)(cacheDirPath),
		(C.slice_ref_uint8_t)(stagedSectorPath),
		(C.slice_ref_uint8_t)(sealedSectorPath),
		C.uint64_t(sectorId),
		(*C.uint8_32_array_t)(proverId),
		(*C.uint8_32_array_t)(ticket),
		(C.slice_ref_PublicPieceInfo_t)(pieces)))
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return nil, err
	}
	return (SliceBoxedUint8)(resp.value).copy(), nil
}

func SealPreCommitPhase2(sealPreCommitPhase1Output SliceRefUint8, cacheDirPath SliceRefUint8, sealedSectorPath SliceRefUint8) ([]byte, []byte, error) {
	resp := (*resultSealPreCommitPhase2)(C.seal_pre_commit_phase2(
		(C.slice_ref_uint8_t)(sealPreCommitPhase1Output),
		(C.slice_ref_uint8_t)(cacheDirPath),
		(C.slice_ref_uint8_t)(sealedSectorPath)))
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return nil, nil, err
	}
	return (*ByteArray32)(&resp.value.comm_r).copy(), (*ByteArray32)(&resp.value.comm_d).copy(), nil
}

func SealCommitPhase1(registeredProof RegisteredSealProof, commR *ByteArray32, commD *ByteArray32, cacheDirPath SliceRefUint8, replicaPath SliceRefUint8, sectorId uint64, proverId *ByteArray32, ticket *ByteArray32, seed *ByteArray32, pieces SliceRefPublicPieceInfo) ([]byte, error) {
	resp := (*resultSliceBoxedUint8)(C.seal_commit_phase1(
		(C.RegisteredSealProof_t)(registeredProof),
		(*C.uint8_32_array_t)(commR),
		(*C.uint8_32_array_t)(commD),
		(C.slice_ref_uint8_t)(cacheDirPath),
		(C.slice_ref_uint8_t)(replicaPath),
		C.uint64_t(sectorId),
		(*C.uint8_32_array_t)(proverId),
		(*C.uint8_32_array_t)(ticket),
		(*C.uint8_32_array_t)(seed),
		(C.slice_ref_PublicPieceInfo_t)(pieces)))
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return nil, err
	}

	return (SliceBoxedUint8)(resp.value).copy(), nil
}

func SealCommitPhase2(sealCommitPhase1Output SliceRefUint8, sectorId uint64, proverId *ByteArray32) ([]byte, error) {
	resp := (*resultSliceBoxedUint8)(C.seal_commit_phase2(
		(C.slice_ref_uint8_t)(sealCommitPhase1Output),
		C.uint64_t(sectorId),
		(*C.uint8_32_array_t)(proverId)))
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return nil, err
	}
	return (SliceBoxedUint8)(resp.value).copy(), nil
}

func SealCommitPhase2CircuitProofs(sealCommitPhase1Output SliceRefUint8, sectorId uint64) ([]byte, error) {
	resp := (*resultSliceBoxedUint8)(C.seal_commit_phase2_circuit_proofs(
		(C.slice_ref_uint8_t)(sealCommitPhase1Output),
		C.uint64_t(sectorId)))
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return nil, err
	}
	return (SliceBoxedUint8)(resp.value).copy(), nil
}

func AggregateSealProofs(registeredProof RegisteredSealProof, registeredAggregation RegisteredAggregationProof, commRs SliceRefByteArray32, seeds SliceRefByteArray32, sealCommitResponses SliceRefSliceBoxedUint8) ([]byte, error) {
	resp := (*resultSliceBoxedUint8)(C.aggregate_seal_proofs(
		(C.RegisteredSealProof_t)(registeredProof),
		(C.RegisteredAggregationProof_t)(registeredAggregation),
		(C.slice_ref_uint8_32_array_t)(commRs),
		(C.slice_ref_uint8_32_array_t)(seeds),
		(C.slice_ref_slice_boxed_uint8_t)(sealCommitResponses)))
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return nil, err
	}
	return (SliceBoxedUint8)(resp.value).copy(), nil
}

func UnsealRange(registeredProof RegisteredSealProof, cacheDirPath SliceRefUint8, sealedSectorFdRaw int32, unsealOutputFdRaw int32, sectorId uint64, proverId *ByteArray32, ticket *ByteArray32, commD *ByteArray32, unpaddedByteIndex uint64, unpaddedBytesAmount uint64) error {
	resp := (*resultVoid)(C.unseal_range(
		(C.RegisteredSealProof_t)(registeredProof),
		(C.slice_ref_uint8_t)(cacheDirPath),
		C.int32_t(sealedSectorFdRaw),
		C.int32_t(unsealOutputFdRaw),
		C.uint64_t(sectorId),
		(*C.uint8_32_array_t)(proverId),
		(*C.uint8_32_array_t)(ticket),
		(*C.uint8_32_array_t)(commD),
		C.uint64_t(unpaddedByteIndex),
		C.uint64_t(unpaddedBytesAmount)))
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return err
	}
	return nil
}

func GenerateWinningPoStSectorChallenge(registeredProof RegisteredPoStProof, randomness *ByteArray32, sectorSetLen uint64, proverId *ByteArray32) ([]uint64, error) {
	resp := (*resultSliceBoxedUint64)(C.generate_winning_post_sector_challenge(
		(C.RegisteredPoStProof_t)(registeredProof),
		(*C.uint8_32_array_t)(randomness),
		C.uint64_t(sectorSetLen),
		(*C.uint8_32_array_t)(proverId)))
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return nil, err
	}
	return (SliceBoxedUint64)(resp.value).copy(), nil
}

func GenerateWinningPoSt(randomness *ByteArray32, replicas SliceRefPrivateReplicaInfo, proverId *ByteArray32) ([]PoStProofGo, error) {
	resp := (*resultSliceBoxedPoStProof)(C.generate_winning_post(
		(*C.uint8_32_array_t)(randomness),
		(C.slice_ref_PrivateReplicaInfo_t)(replicas),
		(*C.uint8_32_array_t)(proverId)))
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return nil, err
	}
	return (SliceBoxedPoStProof)(resp.value).copy(), nil
}

func GenerateWindowPoSt(randomness *ByteArray32, replicas SliceRefPrivateReplicaInfo, proverId *ByteArray32) ([]PoStProofGo, []uint64, error) {
	resp := (*resultGenerateWindowPoSt)(C.generate_window_post(
		(*C.uint8_32_array_t)(randomness),
		(C.slice_ref_PrivateReplicaInfo_t)(replicas),
		(*C.uint8_32_array_t)(proverId)))
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		faults := (SliceBoxedUint64)(resp.value.faulty_sectors).copy()
		return nil, faults, err
	}

	proofs := (SliceBoxedPoStProof)(resp.value.proofs).copy()
	return proofs, []uint64{}, nil
}

func GetGpuDevices() ([]string, error) {
	resp := (*resultSliceBoxedSliceBoxedUint8)(C.get_gpu_devices())
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return nil, err
	}

	return (SliceBoxedSliceBoxedUint8)(resp.value).copyAsStrings(), nil
}

func GetSealVersion(registeredProof RegisteredSealProof) (string, error) {
	resp := (*resultSliceBoxedUint8)(C.get_seal_version(
		(C.RegisteredSealProof_t)(registeredProof)))
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return "", err
	}

	return string((SliceBoxedUint8)(resp.value).copy()), nil
}

func GetPoStVersion(registeredProof RegisteredPoStProof) (string, error) {
	resp := (*resultSliceBoxedUint8)(C.get_post_version(
		(C.RegisteredPoStProof_t)(registeredProof)))
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return "", err
	}

	return string((SliceBoxedUint8)(resp.value).copy()), nil
}

func GetNumPartitionForFallbackPost(registeredProof RegisteredPoStProof, numSectors uint) (uint, error) {
	resp := (*resultUint)(C.get_num_partition_for_fallback_post(
		(C.RegisteredPoStProof_t)(registeredProof),
		C.size_t(numSectors)))
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return 0, err
	}

	return uint(resp.value), nil
}

func ClearCache(sectorSize uint64, cacheDirPath SliceRefUint8) error {
	resp := (*resultVoid)(C.clear_cache(
		C.uint64_t(sectorSize),
		(C.slice_ref_uint8_t)(cacheDirPath)))
	defer resp.destroy()
	return CheckErr(resp)
}

func ClearSyntheticProofs(sectorSize uint64, cacheDirPath SliceRefUint8) error {
	resp := (*resultVoid)(C.clear_synthetic_proofs(
		C.uint64_t(sectorSize),
		(C.slice_ref_uint8_t)(cacheDirPath)))
	defer resp.destroy()
	return CheckErr(resp)
}

func GenerateSynthProofs(
	registered_proof RegisteredSealProof,
	comm_r, comm_d ByteArray32,
	cache_dir_path, replica_path SliceRefUint8,
	sector_id uint64,
	prover_id, ticket ByteArray32,
	pieces SliceRefPublicPieceInfo,
) error {
	resp := (*resultVoid)(C.generate_synth_proofs(
		(C.RegisteredSealProof_t)(registered_proof),
		(*C.uint8_32_array_t)(&comm_r),
		(*C.uint8_32_array_t)(&comm_d),
		(C.slice_ref_uint8_t)(cache_dir_path),
		(C.slice_ref_uint8_t)(replica_path),
		C.uint64_t(sector_id),
		(*C.uint8_32_array_t)(&prover_id),
		(*C.uint8_32_array_t)(&ticket),
		(C.slice_ref_PublicPieceInfo_t)(pieces)))
	defer resp.destroy()
	return CheckErr(resp)
}

func Fauxrep(registeredProf RegisteredSealProof, cacheDirPath SliceRefUint8, sealedSectorPath SliceRefUint8) ([]byte, error) {
	resp := (*resultByteArray32)(C.fauxrep(
		(C.RegisteredSealProof_t)(registeredProf),
		(C.slice_ref_uint8_t)(cacheDirPath),
		(C.slice_ref_uint8_t)(sealedSectorPath)))
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return nil, err
	}
	return (*ByteArray32)(&resp.value).copy(), nil
}

func Fauxrep2(registeredProf RegisteredSealProof, cacheDirPath SliceRefUint8, existingPAuxPath SliceRefUint8) ([]byte, error) {
	resp := (*resultByteArray32)(C.fauxrep2(
		(C.RegisteredSealProof_t)(registeredProf),
		(C.slice_ref_uint8_t)(cacheDirPath),
		(C.slice_ref_uint8_t)(existingPAuxPath)))
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return nil, err
	}
	return (*ByteArray32)(&resp.value).copy(), nil
}

// sector update

func EmptySectorUpdateEncodeInto(registeredProof RegisteredUpdateProof, newReplicaPath SliceRefUint8, newCacheDirPath SliceRefUint8, sectorKeyPath SliceRefUint8, sectorKeyCacheDirPath SliceRefUint8, stagedDataPath SliceRefUint8, pieces SliceRefPublicPieceInfo) ([]byte, []byte, error) {
	resp := (*resultEmptySectorUpdateEncodeInto)(C.empty_sector_update_encode_into(
		(C.RegisteredUpdateProof_t)(registeredProof),
		(C.slice_ref_uint8_t)(newReplicaPath),
		(C.slice_ref_uint8_t)(newCacheDirPath),
		(C.slice_ref_uint8_t)(sectorKeyPath),
		(C.slice_ref_uint8_t)(sectorKeyCacheDirPath),
		(C.slice_ref_uint8_t)(stagedDataPath),
		(C.slice_ref_PublicPieceInfo_t)(pieces)))
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return nil, nil, err
	}
	return (*ByteArray32)(&resp.value.comm_r_new).copy(), (*ByteArray32)(&resp.value.comm_d_new).copy(), nil
}

func EmptySectorUpdateDecodeFrom(registeredProof RegisteredUpdateProof, outDataPath SliceRefUint8, replicaPath SliceRefUint8, sectorKeyPath SliceRefUint8, sectorKeyCacheDirPath SliceRefUint8, commDNew *ByteArray32) error {
	resp := (*resultVoid)(C.empty_sector_update_decode_from(
		(C.RegisteredUpdateProof_t)(registeredProof),
		(C.slice_ref_uint8_t)(outDataPath),
		(C.slice_ref_uint8_t)(replicaPath),
		(C.slice_ref_uint8_t)(sectorKeyPath),
		(C.slice_ref_uint8_t)(sectorKeyCacheDirPath),
		(*C.uint8_32_array_t)(commDNew)))
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return err
	}
	return nil
}

func EmptySectorUpdateRemoveEncodedData(registeredProof RegisteredUpdateProof, sectorKeyPath, sectorKeyCacheDirPath, replicaPath, replicaCachePath, dataPath SliceRefUint8, commDNew *ByteArray32) error {
	resp := (*resultVoid)(C.empty_sector_update_remove_encoded_data(
		(C.RegisteredUpdateProof_t)(registeredProof),
		(C.slice_ref_uint8_t)(sectorKeyPath),
		(C.slice_ref_uint8_t)(sectorKeyCacheDirPath),
		(C.slice_ref_uint8_t)(replicaPath),
		(C.slice_ref_uint8_t)(replicaCachePath),
		(C.slice_ref_uint8_t)(dataPath),
		(*C.uint8_32_array_t)(commDNew)))
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return err
	}
	return nil
}

func GenerateEmptySectorUpdatePartitionProofs(registeredProof RegisteredUpdateProof, commROld, commRNew, commDNew *ByteArray32, sectorKeyPath, sectorKeyCacheDirPath, replicaPath, replicaCachePath SliceRefUint8) ([][]byte, error) {
	resp := (*resultSliceBoxedSliceBoxedUint8)(C.generate_empty_sector_update_partition_proofs(
		(C.RegisteredUpdateProof_t)(registeredProof),
		(*C.uint8_32_array_t)(commROld),
		(*C.uint8_32_array_t)(commRNew),
		(*C.uint8_32_array_t)(commDNew),
		(C.slice_ref_uint8_t)(sectorKeyPath),
		(C.slice_ref_uint8_t)(sectorKeyCacheDirPath),
		(C.slice_ref_uint8_t)(replicaPath),
		(C.slice_ref_uint8_t)(replicaCachePath)))
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return nil, err
	}
	return (SliceBoxedSliceBoxedUint8)(resp.value).copyAsBytes(), nil
}

func VerifyEmptySectorUpdatePartitionProofs(registeredProof RegisteredUpdateProof, proofs SliceRefSliceBoxedUint8, commROld, commRNew, commDNew *ByteArray32) (bool, error) {
	resp := (*resultBool)(C.verify_empty_sector_update_partition_proofs(
		(C.RegisteredUpdateProof_t)(registeredProof),
		(C.slice_ref_slice_boxed_uint8_t)(proofs),
		(*C.uint8_32_array_t)(commROld),
		(*C.uint8_32_array_t)(commRNew),
		(*C.uint8_32_array_t)(commDNew)))
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return false, err
	}

	return bool(resp.value), nil
}

func GenerateEmptySectorUpdateProofWithVanilla(registeredProof RegisteredUpdateProof, vanillaProofs SliceRefSliceBoxedUint8, commROld, commRNew, commDNew *ByteArray32) ([]byte, error) {
	resp := (*resultSliceBoxedUint8)(C.generate_empty_sector_update_proof_with_vanilla(
		(C.RegisteredUpdateProof_t)(registeredProof),
		(C.slice_ref_slice_boxed_uint8_t)(vanillaProofs),
		(*C.uint8_32_array_t)(commROld),
		(*C.uint8_32_array_t)(commRNew),
		(*C.uint8_32_array_t)(commDNew)))
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return nil, err
	}

	return (SliceBoxedUint8)(resp.value).copy(), nil
}

func GenerateEmptySectorUpdateProof(registeredProof RegisteredUpdateProof, commROld, commRNew, commDNew *ByteArray32, sectorKeyPath, sectorKeyCacheDirPath, replicaPath, replicaCachePath SliceRefUint8) ([]byte, error) {
	resp := (*resultSliceBoxedUint8)(C.generate_empty_sector_update_proof(
		(C.RegisteredUpdateProof_t)(registeredProof),
		(*C.uint8_32_array_t)(commROld),
		(*C.uint8_32_array_t)(commRNew),
		(*C.uint8_32_array_t)(commDNew),
		(C.slice_ref_uint8_t)(sectorKeyPath),
		(C.slice_ref_uint8_t)(sectorKeyCacheDirPath),
		(C.slice_ref_uint8_t)(replicaPath),
		(C.slice_ref_uint8_t)(replicaCachePath)))
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return nil, err
	}

	return (SliceBoxedUint8)(resp.value).copy(), nil
}

func VerifyEmptySectorUpdateProof(registeredProof RegisteredUpdateProof, proof SliceRefUint8, commROld, commRNew, commDNew *ByteArray32) (bool, error) {
	resp := (*resultBool)(C.verify_empty_sector_update_proof(
		(C.RegisteredUpdateProof_t)(registeredProof),
		(C.slice_ref_uint8_t)(proof),
		(*C.uint8_32_array_t)(commROld),
		(*C.uint8_32_array_t)(commRNew),
		(*C.uint8_32_array_t)(commDNew)))
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return false, err
	}

	return bool(resp.value), nil
}

// -- distributed

func GenerateFallbackSectorChallenges(registeredProof RegisteredPoStProof, randomness *ByteArray32, sectorIds SliceRefUint64, proverId *ByteArray32) ([]uint64, [][]uint64, error) {
	resp := (*resultGenerateFallbackSectorChallenges)(C.generate_fallback_sector_challenges(
		(C.RegisteredPoStProof_t)(registeredProof),
		(*C.uint8_32_array_t)(randomness),
		(C.slice_ref_uint64_t)(sectorIds),
		(*C.uint8_32_array_t)(proverId)))
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return nil, nil, err
	}

	return (SliceBoxedUint64)(resp.value.ids).copy(), (SliceBoxedSliceBoxedUint64)(resp.value.challenges).copy(), nil
}

func GenerateSingleVanillaProof(replica PrivateReplicaInfo, challenges SliceRefUint64) ([]byte, error) {
	resp := (*resultSliceBoxedUint8)(C.generate_single_vanilla_proof(
		(C.PrivateReplicaInfo_t)(replica),
		(C.slice_ref_uint64_t)(challenges)))
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return nil, err
	}

	return (SliceBoxedUint8)(resp.value).copy(), nil
}

func GenerateWinningPoStWithVanilla(registeredProof RegisteredPoStProof, randomness, proverId *ByteArray32, vanillaProofs SliceRefSliceBoxedUint8) ([]PoStProofGo, error) {
	resp := (*resultSliceBoxedPoStProof)(C.generate_winning_post_with_vanilla(
		(C.RegisteredPoStProof_t)(registeredProof),
		(*C.uint8_32_array_t)(randomness),
		(*C.uint8_32_array_t)(proverId),
		(C.slice_ref_slice_boxed_uint8_t)(vanillaProofs)))
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return nil, err
	}

	return (SliceBoxedPoStProof)(resp.value).copy(), nil
}

func GenerateWindowPoStWithVanilla(registeredProof RegisteredPoStProof, randomness, proverId *ByteArray32, vanillaProofs SliceRefSliceBoxedUint8) ([]PoStProofGo, []uint64, error) {
	resp := (*resultGenerateWindowPoSt)(C.generate_window_post_with_vanilla(
		(C.RegisteredPoStProof_t)(registeredProof),
		(*C.uint8_32_array_t)(randomness),
		(*C.uint8_32_array_t)(proverId),
		(C.slice_ref_slice_boxed_uint8_t)(vanillaProofs)))
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return nil, nil, err
	}

	return (SliceBoxedPoStProof)(resp.value.proofs).copy(), (SliceBoxedUint64)(resp.value.faulty_sectors).copy(), nil
}

func GenerateSingleWindowPoStWithVanilla(registeredProof RegisteredPoStProof, randomness, proverId *ByteArray32, vanillaProofs SliceRefSliceBoxedUint8, partitionIndex uint) (PartitionSnarkProofGo, []uint64, error) {
	resp := (*resultGenerateSingleWindowPoStWithVanilla)(C.generate_single_window_post_with_vanilla(
		(C.RegisteredPoStProof_t)(registeredProof),
		(*C.uint8_32_array_t)(randomness),
		(*C.uint8_32_array_t)(proverId),
		(C.slice_ref_slice_boxed_uint8_t)(vanillaProofs),
		C.size_t(partitionIndex)))
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return PartitionSnarkProofGo{}, nil, err
	}

	return (PartitionSnarkProof)(resp.value.partition_proof).copy(), (SliceBoxedUint64)(resp.value.faulty_sectors).copy(), nil
}

func MergeWindowPoStPartitionProofs(registeredProof RegisteredPoStProof, partitionProofs SliceRefSliceBoxedUint8) (PoStProofGo, error) {
	resp := (*resultPoStProof)(C.merge_window_post_partition_proofs(
		(C.RegisteredPoStProof_t)(registeredProof),
		(C.slice_ref_slice_boxed_uint8_t)(partitionProofs)))
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return PoStProofGo{}, err
	}

	return (PoStProof)(resp.value).copy(), nil
}

func GenerateSDR(registeredProof RegisteredPoStProof, outDir SliceRefUint8, replicaID *ByteArray32) error {
	resp := (*resultVoid)(C.generate_sdr(
		(C.RegisteredPoStProof_t)(registeredProof),
		(C.slice_ref_uint8_t)(outDir),
		(*C.uint8_32_array_t)(replicaID)))
	defer resp.destroy()

	return CheckErr(resp)
}

func GenerateTreeRLast(registeredProof RegisteredPoStProof, replicaPath, outDir SliceRefUint8) ([]byte, error) {
	resp := (*resultByteArray32)(C.generate_tree_r_last(
		(C.RegisteredPoStProof_t)(registeredProof),
		(C.slice_ref_uint8_t)(replicaPath),
		(C.slice_ref_uint8_t)(outDir)))
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return nil, err
	}

	return (*ByteArray32)(&resp.value).copy(), nil
}

func GenerateTreeC(registeredProof RegisteredPoStProof, inputDir, outDir SliceRefUint8) ([]byte, error) {
	resp := (*resultByteArray32)(C.generate_tree_c(
		(C.RegisteredPoStProof_t)(registeredProof),
		(C.slice_ref_uint8_t)(inputDir),
		(C.slice_ref_uint8_t)(outDir)))
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return nil, err
	}

	return (*ByteArray32)(&resp.value).copy(), nil
}

func EmptySectorUpdateDecodeFromRange(registeredProof RegisteredUpdateProof, commD, commR *ByteArray32, inputFd, sectorKeyFd, outputFd int32, nodesOffset, numNodes uint64) error {
	resp := (*resultVoid)(C.empty_sector_update_decode_from_range(
		(C.RegisteredUpdateProof_t)(registeredProof),
		(*C.uint8_32_array_t)(commD),
		(*C.uint8_32_array_t)(commR),
		C.int(inputFd),
		C.int(sectorKeyFd),
		C.int(outputFd),
		C.uint64_t(nodesOffset),
		C.uint64_t(numNodes)))
	defer resp.destroy()

	return CheckErr(resp)
}
