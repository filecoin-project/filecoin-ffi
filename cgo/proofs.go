package cgo

/*
#cgo LDFLAGS: -L${SRCDIR}/..
#cgo pkg-config: ${SRCDIR}/../filcrypto.pc
#include "../filcrypto.h"
#include <stdlib.h>
*/
import "C"

func VerifySeal(registeredProof RegisteredSealProof, commR *ByteArray32, commD *ByteArray32, proverId *ByteArray32, ticket *ByteArray32, seed *ByteArray32, sectorId uint64, proof SliceRefUint8) (bool, error) {
	resp := &resultBool{delegate: C.verify_seal(registeredProof, commR.delegate, commD.delegate, proverId.delegate, ticket.delegate, seed.delegate, C.uint64_t(sectorId), proof)}
	defer resp.destroy()

	if err := CheckErr(resp); err != nil {
		return false, err
	}

	return bool(resp.delegate.value), nil
}

func VerifyAggregateSealProof(registeredProof RegisteredSealProof, registeredAggregation RegisteredAggregationProof, proverId *ByteArray32, proof SliceRefUint8, commitInputs SliceRefAggregationInputs) (bool, error) {
	resp := &resultBool{delegate: C.verify_aggregate_seal_proof(registeredProof, registeredAggregation, proverId.delegate, proof, commitInputs)}
	defer resp.destroy()

	if err := CheckErr(resp); err != nil {
		return false, err
	}
	return bool(resp.delegate.value), nil
}

func VerifyWinningPoSt(randomness *ByteArray32, replicas SliceRefPublicReplicaInfo, proofs SliceRefPoStProof, proverId *ByteArray32) (bool, error) {
	resp := &resultBool{delegate: C.verify_winning_post(randomness.delegate, replicas, proofs, proverId.delegate)}
	defer resp.destroy()

	if err := CheckErr(resp); err != nil {
		return false, err
	}

	return bool(resp.delegate.value), nil
}

func VerifyWindowPoSt(randomness *ByteArray32, replicas SliceRefPublicReplicaInfo, proofs SliceRefPoStProof, proverId *ByteArray32) (bool, error) {
	resp := &resultBool{delegate: C.verify_window_post(randomness.delegate, replicas, proofs, proverId.delegate)}
	defer resp.destroy()

	if err := CheckErr(resp); err != nil {
		return false, err
	}

	return bool(resp.delegate.value), nil
}

func GeneratePieceCommitment(registeredProof RegisteredSealProof, pieceFdRaw int32, unpaddedPieceSize uint64) ([]byte, error) {
	resp := &resultGeneratePieceCommitment{delegate: C.generate_piece_commitment(registeredProof, C.int32_t(pieceFdRaw), C.uint64_t(unpaddedPieceSize))}
	defer resp.destroy()

	if err := CheckErr(resp); err != nil {
		return nil, err
	}

	commp := ByteArray32{delegate: &resp.delegate.value.comm_p}
	return commp.copy(), nil
}

func GenerateDataCommitment(registeredProof RegisteredSealProof, pieces SliceRefPublicPieceInfo) ([]byte, error) {
	resp := &resultByteArray32{delegate: C.generate_data_commitment(registeredProof, pieces)}
	defer resp.destroy()

	if err := CheckErr(resp); err != nil {
		return nil, err
	}

	value := ByteArray32{delegate: &resp.delegate.value}
	return value.copy(), nil
}

func WriteWithAlignment(registeredProof RegisteredSealProof, srcFd int32, srcSize uint64, dstFd int32, existingPieceSizes SliceRefUint64) (uint64, uint64, []byte, error) {
	resp := &resultWriteWithAlignment{delegate: C.write_with_alignment(registeredProof, C.int32_t(srcFd), C.uint64_t(srcSize), C.int32_t(dstFd), existingPieceSizes)}
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return 0, 0, nil, err
	}

	commp := ByteArray32{delegate: &resp.delegate.value.comm_p}
	return uint64(resp.delegate.value.left_alignment_unpadded), uint64(resp.delegate.value.total_write_unpadded), commp.copy(), nil
}

func WriteWithoutAlignment(registeredProof RegisteredSealProof, srcFd int32, srcSize uint64, dstFd int32) (uint64, []byte, error) {
	resp := &resultWriteWithoutAlignment{delegate: C.write_without_alignment(registeredProof, C.int32_t(srcFd), C.uint64_t(srcSize), C.int32_t(dstFd))}
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return 0, nil, err
	}

	commp := ByteArray32{delegate: &resp.delegate.value.comm_p}
	return uint64(resp.delegate.value.total_write_unpadded), commp.copy(), nil
}

func SealPreCommitPhase1(registeredProof RegisteredSealProof, cacheDirPath SliceRefUint8, stagedSectorPath SliceRefUint8, sealedSectorPath SliceRefUint8, sectorId uint64, proverId *ByteArray32, ticket *ByteArray32, pieces SliceRefPublicPieceInfo) ([]byte, error) {
	resp := &resultSliceBoxedUint8{delegate: C.seal_pre_commit_phase1(registeredProof, cacheDirPath, stagedSectorPath, sealedSectorPath, C.uint64_t(sectorId), proverId.delegate, ticket.delegate, pieces)}
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return nil, err
	}
	return SliceBoxedUint8{delegate: resp.delegate.value}.copy(), nil
}

func SealPreCommitPhase2(sealPreCommitPhase1Output SliceRefUint8, cacheDirPath SliceRefUint8, sealedSectorPath SliceRefUint8) ([]byte, []byte, error) {
	resp := &resultSealPreCommitPhase2{delegate: C.seal_pre_commit_phase2(sealPreCommitPhase1Output, cacheDirPath, sealedSectorPath)}
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return nil, nil, err
	}

	commr := ByteArray32{delegate: &resp.delegate.value.comm_r}
	commd := ByteArray32{delegate: &resp.delegate.value.comm_d}
	return commr.copy(), commd.copy(), nil
}

func SealCommitPhase1(registeredProof RegisteredSealProof, commR *ByteArray32, commD *ByteArray32, cacheDirPath SliceRefUint8, replicaPath SliceRefUint8, sectorId uint64, proverId *ByteArray32, ticket *ByteArray32, seed *ByteArray32, pieces SliceRefPublicPieceInfo) ([]byte, error) {
	resp := &resultSliceBoxedUint8{delegate: C.seal_commit_phase1(registeredProof, commR.delegate, commD.delegate, cacheDirPath, replicaPath, C.uint64_t(sectorId), proverId.delegate, ticket.delegate, seed.delegate, pieces)}
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return nil, err
	}

	return SliceBoxedUint8{delegate: resp.delegate.value}.copy(), nil
}

func SealCommitPhase2(sealCommitPhase1Output SliceRefUint8, sectorId uint64, proverId *ByteArray32) ([]byte, error) {
	resp := &resultSliceBoxedUint8{delegate: C.seal_commit_phase2(sealCommitPhase1Output, C.uint64_t(sectorId), proverId.delegate)}
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return nil, err
	}
	return SliceBoxedUint8{delegate: resp.delegate.value}.copy(), nil
}

func SealCommitPhase2CircuitProofs(sealCommitPhase1Output SliceRefUint8, sectorId uint64) ([]byte, error) {
	resp := &resultSliceBoxedUint8{delegate: C.seal_commit_phase2_circuit_proofs(sealCommitPhase1Output, C.uint64_t(sectorId))}
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return nil, err
	}
	return SliceBoxedUint8{delegate: resp.delegate.value}.copy(), nil
}

func AggregateSealProofs(registeredProof RegisteredSealProof, registeredAggregation RegisteredAggregationProof, commRs SliceRefByteArray32, seeds SliceRefByteArray32, sealCommitResponses SliceRefSliceBoxedUint8) ([]byte, error) {
	resp := &resultSliceBoxedUint8{delegate: C.aggregate_seal_proofs(registeredProof, registeredAggregation, commRs, seeds, sealCommitResponses)}
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return nil, err
	}
	return SliceBoxedUint8{delegate: resp.delegate.value}.copy(), nil
}

func UnsealRange(registeredProof RegisteredSealProof, cacheDirPath SliceRefUint8, sealedSectorFdRaw int32, unsealOutputFdRaw int32, sectorId uint64, proverId *ByteArray32, ticket *ByteArray32, commD *ByteArray32, unpaddedByteIndex uint64, unpaddedBytesAmount uint64) error {
	resp := &resultVoid{delegate: C.unseal_range(registeredProof, cacheDirPath, C.int32_t(sealedSectorFdRaw), C.int32_t(unsealOutputFdRaw), C.uint64_t(sectorId), proverId.delegate, ticket.delegate, commD.delegate, C.uint64_t(unpaddedByteIndex), C.uint64_t(unpaddedBytesAmount))}
	defer resp.destroy()
	return CheckErr(resp)
}

func GenerateWinningPoStSectorChallenge(registeredProof RegisteredPoStProof, randomness *ByteArray32, sectorSetLen uint64, proverId *ByteArray32) ([]uint64, error) {
	resp := &resultSliceBoxedUint64{delegate: C.generate_winning_post_sector_challenge(registeredProof, randomness.delegate, C.uint64_t(sectorSetLen), proverId.delegate)}
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return nil, err
	}
	return SliceBoxedUint64{delegate: resp.delegate.value}.copy(), nil
}

func GenerateWinningPoSt(randomness *ByteArray32, replicas SliceRefPrivateReplicaInfo, proverId *ByteArray32) ([]PoStProofGo, error) {
	resp := &resultSliceBoxedPoStProof{delegate: C.generate_winning_post(randomness.delegate, replicas, proverId.delegate)}
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return nil, err
	}
	return SliceBoxedPoStProof{delegate: resp.delegate.value}.copy(), nil
}

func GenerateWindowPoSt(randomness *ByteArray32, replicas SliceRefPrivateReplicaInfo, proverId *ByteArray32) ([]PoStProofGo, []uint64, error) {
	resp := &resultGenerateWindowPoSt{delegate: C.generate_window_post(randomness.delegate, replicas, proverId.delegate)}
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		faults := SliceBoxedUint64{delegate: resp.delegate.value.faulty_sectors}.copy()
		return nil, faults, err
	}

	proofs := SliceBoxedPoStProof{delegate: resp.delegate.value.proofs}.copy()
	return proofs, []uint64{}, nil
}

func GetGpuDevices() ([]string, error) {
	resp := &resultSliceBoxedSliceBoxedUint8{delegate: C.get_gpu_devices()}
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return nil, err
	}

	return SliceBoxedSliceBoxedUint8{delegate: resp.delegate.value}.copyAsStrings(), nil
}

func GetSealVersion(registeredProof RegisteredSealProof) (string, error) {
	resp := &resultSliceBoxedUint8{delegate: C.get_seal_version(registeredProof)}
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return "", err
	}

	return string(SliceBoxedUint8{delegate: resp.delegate.value}.copy()), nil
}

func GetPoStVersion(registeredProof RegisteredPoStProof) (string, error) {
	resp := &resultSliceBoxedUint8{delegate: C.get_post_version(registeredProof)}
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return "", err
	}

	return string(SliceBoxedUint8{delegate: resp.delegate.value}.copy()), nil
}

func GetNumPartitionForFallbackPost(registeredProof RegisteredPoStProof, numSectors uint) (uint, error) {
	resp := &resultUint{delegate: C.get_num_partition_for_fallback_post(registeredProof, C.size_t(numSectors))}
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return 0, err
	}

	return uint(resp.delegate.value), nil
}

func ClearCache(sectorSize uint64, cacheDirPath SliceRefUint8) error {
	resp := &resultVoid{delegate: C.clear_cache(C.uint64_t(sectorSize), cacheDirPath)}
	defer resp.destroy()
	return CheckErr(resp)
}

func ClearSyntheticProofs(sectorSize uint64, cacheDirPath SliceRefUint8) error {
	resp := &resultVoid{delegate: C.clear_synthetic_proofs(C.uint64_t(sectorSize), cacheDirPath)}
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
	resp := &resultVoid{
		delegate: C.generate_synth_proofs(registered_proof,
			comm_r.delegate,
			comm_d.delegate,
			cache_dir_path,
			replica_path,
			C.uint64_t(sector_id),
			prover_id.delegate,
			ticket.delegate,
			pieces,
		),
	}
	defer resp.destroy()
	return CheckErr(resp)
}

func Fauxrep(registeredProf RegisteredSealProof, cacheDirPath SliceRefUint8, sealedSectorPath SliceRefUint8) ([]byte, error) {
	resp := &resultByteArray32{delegate: C.fauxrep(registeredProf, cacheDirPath, sealedSectorPath)}
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return nil, err
	}
	v := ByteArray32{delegate: &resp.delegate.value}
	return v.copy(), nil
}

func Fauxrep2(registeredProf RegisteredSealProof, cacheDirPath SliceRefUint8, existingPAuxPath SliceRefUint8) ([]byte, error) {
	resp := &resultByteArray32{delegate: C.fauxrep2(registeredProf, cacheDirPath, existingPAuxPath)}
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return nil, err
	}
	v := ByteArray32{delegate: &resp.delegate.value}
	return v.copy(), nil
}

// sector update

func EmptySectorUpdateEncodeInto(registeredProof RegisteredUpdateProof, newReplicaPath SliceRefUint8, newCacheDirPath SliceRefUint8, sectorKeyPath SliceRefUint8, sectorKeyCacheDirPath SliceRefUint8, stagedDataPath SliceRefUint8, pieces SliceRefPublicPieceInfo) ([]byte, []byte, error) {
	resp := &resultEmptySectorUpdateEncodeInto{
		delegate: C.empty_sector_update_encode_into(registeredProof, newReplicaPath, newCacheDirPath, sectorKeyPath, sectorKeyCacheDirPath, stagedDataPath, pieces),
	}
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return nil, nil, err
	}
	commrNew := ByteArray32{delegate: &resp.delegate.value.comm_r_new}
	commdNew := ByteArray32{delegate: &resp.delegate.value.comm_d_new}
	return commrNew.copy(), commdNew.copy(), nil
}

func EmptySectorUpdateDecodeFrom(registeredProof RegisteredUpdateProof, outDataPath SliceRefUint8, replicaPath SliceRefUint8, sectorKeyPath SliceRefUint8, sectorKeyCacheDirPath SliceRefUint8, commDNew *ByteArray32) error {
	resp := &resultVoid{
		delegate: C.empty_sector_update_decode_from(registeredProof, outDataPath, replicaPath, sectorKeyPath, sectorKeyCacheDirPath, commDNew.delegate),
	}
	defer resp.destroy()
	return CheckErr(resp)
}

func EmptySectorUpdateRemoveEncodedData(registeredProof RegisteredUpdateProof, sectorKeyPath, sectorKeyCacheDirPath, replicaPath, replicaCachePath, dataPath SliceRefUint8, commDNew *ByteArray32) error {
	resp := &resultVoid{
		delegate: C.empty_sector_update_remove_encoded_data(registeredProof, sectorKeyPath, sectorKeyCacheDirPath, replicaPath, replicaCachePath, dataPath, commDNew.delegate),
	}
	defer resp.destroy()
	return CheckErr(resp)
}

func GenerateEmptySectorUpdatePartitionProofs(registeredProof RegisteredUpdateProof, commROld, commRNew, commDNew *ByteArray32, sectorKeyPath, sectorKeyCacheDirPath, replicaPath, replicaCachePath SliceRefUint8) ([][]byte, error) {
	resp := &resultSliceBoxedSliceBoxedUint8{
		delegate: C.generate_empty_sector_update_partition_proofs(registeredProof, commROld.delegate, commRNew.delegate, commDNew.delegate, sectorKeyPath, sectorKeyCacheDirPath, replicaPath, replicaCachePath),
	}
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return nil, err
	}
	return SliceBoxedSliceBoxedUint8{delegate: resp.delegate.value}.copyAsBytes(), nil
}

func VerifyEmptySectorUpdatePartitionProofs(registeredProof RegisteredUpdateProof, proofs SliceRefSliceBoxedUint8, commROld, commRNew, commDNew *ByteArray32) (bool, error) {
	resp := &resultBool{delegate: C.verify_empty_sector_update_partition_proofs(registeredProof, proofs, commROld.delegate, commRNew.delegate, commDNew.delegate)}
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return false, err
	}

	return bool(resp.delegate.value), nil
}

func GenerateEmptySectorUpdateProofWithVanilla(registeredProof RegisteredUpdateProof, vanillaProofs SliceRefSliceBoxedUint8, commROld, commRNew, commDNew *ByteArray32) ([]byte, error) {
	resp := &resultSliceBoxedUint8{delegate: C.generate_empty_sector_update_proof_with_vanilla(registeredProof, vanillaProofs, commROld.delegate, commRNew.delegate, commDNew.delegate)}
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return nil, err
	}

	return SliceBoxedUint8{delegate: resp.delegate.value}.copy(), nil
}

func GenerateEmptySectorUpdateProof(registeredProof RegisteredUpdateProof, commROld, commRNew, commDNew *ByteArray32, sectorKeyPath, sectorKeyCacheDirPath, replicaPath, replicaCachePath SliceRefUint8) ([]byte, error) {
	resp := &resultSliceBoxedUint8{delegate: C.generate_empty_sector_update_proof(registeredProof, commROld.delegate, commRNew.delegate, commDNew.delegate, sectorKeyPath, sectorKeyCacheDirPath, replicaPath, replicaCachePath)}
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return nil, err
	}

	return SliceBoxedUint8{delegate: resp.delegate.value}.copy(), nil
}

func VerifyEmptySectorUpdateProof(registeredProof RegisteredUpdateProof, proof SliceRefUint8, commROld, commRNew, commDNew *ByteArray32) (bool, error) {
	resp := &resultBool{delegate: C.verify_empty_sector_update_proof(registeredProof, proof, commROld.delegate, commRNew.delegate, commDNew.delegate)}
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return false, err
	}

	return bool(resp.delegate.value), nil
}

// -- distributed

func GenerateFallbackSectorChallenges(registeredProof RegisteredPoStProof, randomness *ByteArray32, sectorIds SliceRefUint64, proverId *ByteArray32) ([]uint64, [][]uint64, error) {
	resp := &resultGenerateFallbackSectorChallenges{delegate: C.generate_fallback_sector_challenges(registeredProof, randomness.delegate, sectorIds, proverId.delegate)}
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return nil, nil, err
	}

	return SliceBoxedUint64{delegate: resp.delegate.value.ids}.copy(), SliceBoxedSliceBoxedUint64{delegate: resp.delegate.value.challenges}.copy(), nil
}

func GenerateSingleVanillaProof(replica PrivateReplicaInfo, challenges SliceRefUint64) ([]byte, error) {
	resp := &resultSliceBoxedUint8{delegate: C.generate_single_vanilla_proof(replica.delegate, challenges)}
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return nil, err
	}

	return SliceBoxedUint8{delegate: resp.delegate.value}.copy(), nil
}

func GenerateWinningPoStWithVanilla(registeredProof RegisteredPoStProof, randomness, proverId *ByteArray32, vanillaProofs SliceRefSliceBoxedUint8) ([]PoStProofGo, error) {
	resp := &resultSliceBoxedPoStProof{delegate: C.generate_winning_post_with_vanilla(registeredProof, randomness.delegate, proverId.delegate, vanillaProofs)}
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return nil, err
	}

	return SliceBoxedPoStProof{delegate: resp.delegate.value}.copy(), nil
}

func GenerateWindowPoStWithVanilla(registeredProof RegisteredPoStProof, randomness, proverId *ByteArray32, vanillaProofs SliceRefSliceBoxedUint8) ([]PoStProofGo, []uint64, error) {
	resp := &resultGenerateWindowPoSt{delegate: C.generate_window_post_with_vanilla(registeredProof, randomness.delegate, proverId.delegate, vanillaProofs)}
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return nil, nil, err
	}

	return SliceBoxedPoStProof{delegate: resp.delegate.value.proofs}.copy(), SliceBoxedUint64{delegate: resp.delegate.value.faulty_sectors}.copy(), nil
}

func GenerateSingleWindowPoStWithVanilla(registeredProof RegisteredPoStProof, randomness, proverId *ByteArray32, vanillaProofs SliceRefSliceBoxedUint8, partitionIndex uint) (PartitionSnarkProofGo, []uint64, error) {
	resp := &resultGenerateSingleWindowPoStWithVanilla{delegate: C.generate_single_window_post_with_vanilla(registeredProof, randomness.delegate, proverId.delegate, vanillaProofs, C.size_t(partitionIndex))}
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return PartitionSnarkProofGo{}, nil, err
	}

	return PartitionSnarkProof{delegate: resp.delegate.value.partition_proof}.copy(), SliceBoxedUint64{delegate: resp.delegate.value.faulty_sectors}.copy(), nil
}

func MergeWindowPoStPartitionProofs(registeredProof RegisteredPoStProof, partitionProofs SliceRefSliceBoxedUint8) (PoStProofGo, error) {
	resp := &resultPoStProof{delegate: C.merge_window_post_partition_proofs(registeredProof, partitionProofs)}
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return PoStProofGo{}, err
	}

	return PoStProof{delegate: resp.delegate.value}.copy(), nil
}

// PoRep primitives

func GenerateSDR(registeredProof RegisteredPoStProof, outDir SliceRefUint8, replicaID *ByteArray32) error {
	resp := &resultVoid{delegate: C.generate_sdr(registeredProof, outDir, replicaID.delegate)}
	defer resp.destroy()

	return CheckErr(resp)
}

func GenerateTreeRLast(registeredProof RegisteredPoStProof, replicaPath, outDir SliceRefUint8) ([]byte, error) {
	resp := &resultByteArray32{delegate: C.generate_tree_r_last(registeredProof, replicaPath, outDir)}
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return nil, err
	}

	v := ByteArray32{delegate: &resp.delegate.value}
	return v.copy(), nil
}

func GenerateTreeC(registeredProof RegisteredPoStProof, inputDir, outDir SliceRefUint8) ([]byte, error) {
	resp := &resultByteArray32{delegate: C.generate_tree_c(registeredProof, inputDir, outDir)}
	defer resp.destroy()
	if err := CheckErr(resp); err != nil {
		return nil, err
	}

	v := ByteArray32{delegate: &resp.delegate.value}
	return v.copy(), nil
}

func EmptySectorUpdateDecodeFromRange(registeredProof RegisteredUpdateProof, commD, commR *ByteArray32, inputFd, sectorKeyFd, outputFd int32, nodesOffset, numNodes uint64) error {
	resp := &resultVoid{
		delegate: C.empty_sector_update_decode_from_range(registeredProof, commD.delegate, commR.delegate, C.int(inputFd), C.int(sectorKeyFd), C.int(outputFd), C.uint64_t(nodesOffset), C.uint64_t(numNodes)),
	}
	defer resp.destroy()
	return CheckErr(resp)
}
