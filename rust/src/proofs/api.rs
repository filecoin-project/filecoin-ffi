use filecoin_proofs_api::seal::{
    add_piece, aggregate_seal_commit_proofs, clear_cache, compute_comm_d, fauxrep, fauxrep2,
    generate_piece_commitment, get_seal_inputs, seal_commit_phase1, seal_commit_phase2,
    seal_pre_commit_phase1, seal_pre_commit_phase2, verify_aggregate_seal_commit_proofs,
    verify_seal, write_and_preprocess, SealCommitPhase2Output, SealPreCommitPhase2Output,
};
use filecoin_proofs_api::update::{
    empty_sector_update_decode_from, empty_sector_update_encode_into,
    empty_sector_update_remove_encoded_data, generate_empty_sector_update_proof,
    generate_empty_sector_update_proof_with_vanilla, generate_partition_proofs,
    verify_empty_sector_update_proof, verify_partition_proofs,
};
use filecoin_proofs_api::{
    PartitionProofBytes, PartitionSnarkProof, PieceInfo, PrivateReplicaInfo, RegisteredPoStProof,
    RegisteredSealProof, SectorId, StorageProofsError, UnpaddedByteIndex, UnpaddedBytesAmount,
};

use anyhow::anyhow;
use blstrs::Scalar as Fr;
use log::error;
use rayon::prelude::*;

use super::helpers::{to_private_replica_info_map, to_public_replica_info_map};
use super::types::*;
use crate::util::types::{
    catch_panic_response, catch_panic_response_raw, fil_Array, fil_Bytes, FCPResponseStatus,
};

// A byte serialized representation of a vanilla proof.
pub type VanillaProof = Vec<u8>;

/// TODO: document
#[no_mangle]
#[cfg(not(target_os = "windows"))]
pub unsafe extern "C" fn fil_write_with_alignment(
    registered_proof: fil_RegisteredSealProof,
    src_fd: libc::c_int,
    src_size: u64,
    dst_fd: libc::c_int,
    existing_piece_sizes: fil_Array<u64>,
) -> *mut fil_WriteWithAlignmentResponse {
    catch_panic_response("write_with_alignment", || {
        let piece_sizes: Vec<UnpaddedBytesAmount> = existing_piece_sizes
            .into_iter()
            .map(UnpaddedBytesAmount)
            .collect();

        let n = UnpaddedBytesAmount(src_size);

        let (info, written) = add_piece(
            registered_proof.into(),
            FileDescriptorRef::new(src_fd),
            FileDescriptorRef::new(dst_fd),
            n,
            &piece_sizes,
        )?;

        Ok(fil_WriteWithAlignment {
            comm_p: info.commitment,
            left_alignment_unpadded: (written - n).into(),
            total_write_unpadded: written.into(),
        })
    })
}

/// TODO: document
#[no_mangle]
#[cfg(not(target_os = "windows"))]
pub unsafe extern "C" fn fil_write_without_alignment(
    registered_proof: fil_RegisteredSealProof,
    src_fd: libc::c_int,
    src_size: u64,
    dst_fd: libc::c_int,
) -> *mut fil_WriteWithoutAlignmentResponse {
    catch_panic_response("write_without_alignment", || {
        let (info, written) = write_and_preprocess(
            registered_proof.into(),
            FileDescriptorRef::new(src_fd),
            FileDescriptorRef::new(dst_fd),
            UnpaddedBytesAmount(src_size),
        )?;

        Ok(fil_WriteWithoutAlignment {
            comm_p: info.commitment,
            total_write_unpadded: written.into(),
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn fil_fauxrep(
    registered_proof: fil_RegisteredSealProof,
    cache_dir_path: &fil_Bytes,
    sealed_sector_path: &fil_Bytes,
) -> *mut fil_FauxRepResponse {
    catch_panic_response("fauxrep", || {
        let res = fauxrep(
            registered_proof.into(),
            cache_dir_path.as_path()?,
            sealed_sector_path.as_path()?,
        )?;
        Ok(res.into())
    })
}

#[no_mangle]
pub unsafe extern "C" fn fil_fauxrep2(
    registered_proof: fil_RegisteredSealProof,
    cache_dir_path: &fil_Bytes,
    existing_p_aux_path: &fil_Bytes,
) -> *mut fil_FauxRepResponse {
    catch_panic_response("fauxrep2", || {
        let result = fauxrep2(
            registered_proof.into(),
            cache_dir_path.as_path()?,
            existing_p_aux_path.as_path()?,
        )?;

        Ok(result.into())
    })
}

/// TODO: document
#[no_mangle]
pub unsafe extern "C" fn fil_seal_pre_commit_phase1(
    registered_proof: fil_RegisteredSealProof,
    cache_dir_path: &fil_Bytes,
    staged_sector_path: &fil_Bytes,
    sealed_sector_path: &fil_Bytes,
    sector_id: u64,
    prover_id: fil_32ByteArray,
    ticket: fil_32ByteArray,
    pieces: &fil_Array<fil_PublicPieceInfo>,
) -> *mut fil_SealPreCommitPhase1Response {
    catch_panic_response("seal_pre_commit_phase1", || {
        let public_pieces: Vec<PieceInfo> = pieces.iter().map(Into::into).collect();

        let result = seal_pre_commit_phase1(
            registered_proof.into(),
            cache_dir_path.as_path()?,
            staged_sector_path.as_path()?,
            sealed_sector_path.as_path()?,
            prover_id.inner,
            SectorId::from(sector_id),
            ticket.inner,
            &public_pieces,
        )?;
        let result = serde_json::to_vec(&result)?;

        Ok(result.into())
    })
}

/// TODO: document
#[no_mangle]
pub unsafe extern "C" fn fil_seal_pre_commit_phase2(
    seal_pre_commit_phase1_output: fil_Bytes,
    cache_dir_path: &fil_Bytes,
    sealed_sector_path: &fil_Bytes,
) -> *mut fil_SealPreCommitPhase2Response {
    catch_panic_response("seal_pre_commit_phase2", || {
        let phase_1_output = serde_json::from_slice(&seal_pre_commit_phase1_output)?;

        let output = seal_pre_commit_phase2(
            phase_1_output,
            cache_dir_path.as_path()?,
            sealed_sector_path.as_path()?,
        )?;

        Ok(fil_SealPreCommitPhase2 {
            comm_r: output.comm_r,
            comm_d: output.comm_d,
            registered_proof: output.registered_proof.into(),
        })
    })
}

/// TODO: document
#[no_mangle]
pub unsafe extern "C" fn fil_seal_commit_phase1(
    registered_proof: fil_RegisteredSealProof,
    comm_r: fil_32ByteArray,
    comm_d: fil_32ByteArray,
    cache_dir_path: &fil_Bytes,
    replica_path: &fil_Bytes,
    sector_id: u64,
    prover_id: fil_32ByteArray,
    ticket: fil_32ByteArray,
    seed: fil_32ByteArray,
    pieces: &fil_Array<fil_PublicPieceInfo>,
) -> *mut fil_SealCommitPhase1Response {
    catch_panic_response("seal_commit_phase1", || {
        let spcp2o = SealPreCommitPhase2Output {
            registered_proof: registered_proof.into(),
            comm_r: comm_r.inner,
            comm_d: comm_d.inner,
        };

        let public_pieces: Vec<PieceInfo> = pieces.iter().map(Into::into).collect();

        let output = seal_commit_phase1(
            cache_dir_path.as_path()?,
            replica_path.as_path()?,
            prover_id.inner,
            SectorId::from(sector_id),
            ticket.inner,
            seed.inner,
            spcp2o,
            &public_pieces,
        )?;

        let result = serde_json::to_vec(&output)?;
        Ok(result.into())
    })
}

#[no_mangle]
pub unsafe extern "C" fn fil_seal_commit_phase2(
    seal_commit_phase1_output: &fil_Bytes,
    sector_id: u64,
    prover_id: fil_32ByteArray,
) -> *mut fil_SealCommitPhase2Response {
    catch_panic_response("seal_commit_phase2", || {
        let scp1o = serde_json::from_slice(seal_commit_phase1_output)?;
        let result = seal_commit_phase2(scp1o, prover_id.inner, SectorId::from(sector_id))?;

        Ok(fil_SealCommitPhase2 {
            proof: result.proof.into(),
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn fil_aggregate_seal_proofs(
    registered_proof: fil_RegisteredSealProof,
    registered_aggregation: fil_RegisteredAggregationProof,
    comm_rs: fil_Array<fil_32ByteArray>,
    seeds: fil_Array<fil_32ByteArray>,
    seal_commit_responses: fil_Array<fil_SealCommitPhase2>,
) -> *mut fil_AggregateProof {
    catch_panic_response("aggregate_seal_proofs", || {
        let outputs: Vec<SealCommitPhase2Output> =
            seal_commit_responses.iter().map(Into::into).collect();

        let comm_rs: Vec<[u8; 32]> = comm_rs.into_iter().map(|x| x.inner).collect();
        let seeds: Vec<[u8; 32]> = seeds.into_iter().map(|x| x.inner).collect();

        let result = aggregate_seal_commit_proofs(
            registered_proof.into(),
            registered_aggregation.into(),
            &comm_rs,
            &seeds,
            &outputs,
        )?;

        Ok(result.into())
    })
}

/// Retrieves the seal inputs based on the provided input, used for aggregation verification.
fn convert_aggregation_inputs(
    registered_proof: fil_RegisteredSealProof,
    prover_id: fil_32ByteArray,
    input: &fil_AggregationInputs,
) -> anyhow::Result<Vec<Vec<Fr>>> {
    get_seal_inputs(
        registered_proof.into(),
        input.comm_r.inner,
        input.comm_d.inner,
        prover_id.inner,
        SectorId::from(input.sector_id),
        input.ticket.inner,
        input.seed.inner,
    )
}

/// Verifies the output of an aggregated seal.
#[no_mangle]
pub unsafe extern "C" fn fil_verify_aggregate_seal_proof(
    registered_proof: fil_RegisteredSealProof,
    registered_aggregation: fil_RegisteredAggregationProof,
    prover_id: fil_32ByteArray,
    proof: &fil_Bytes,
    commit_inputs: &fil_Array<fil_AggregationInputs>,
) -> *mut fil_VerifyAggregateSealProofResponse {
    catch_panic_response("verify_aggregate_seal_proof", || {
        let inputs: Vec<Vec<Fr>> = commit_inputs
            .par_iter()
            .map(|input| convert_aggregation_inputs(registered_proof, prover_id, input))
            .try_reduce(Vec::new, |mut acc, current| {
                acc.extend(current);
                Ok(acc)
            })?;

        let proof_bytes: Vec<u8> = proof.to_vec();

        let comm_rs: Vec<[u8; 32]> = commit_inputs
            .iter()
            .map(|input| input.comm_r.inner)
            .collect();
        let seeds: Vec<[u8; 32]> = commit_inputs.iter().map(|input| input.seed.inner).collect();

        let result = verify_aggregate_seal_commit_proofs(
            registered_proof.into(),
            registered_aggregation.into(),
            proof_bytes,
            &comm_rs,
            &seeds,
            inputs,
        )?;

        Ok(result)
    })
}

/// TODO: document
#[no_mangle]
pub unsafe extern "C" fn fil_unseal_range(
    registered_proof: fil_RegisteredSealProof,
    cache_dir_path: &fil_Bytes,
    sealed_sector_fd_raw: libc::c_int,
    unseal_output_fd_raw: libc::c_int,
    sector_id: u64,
    prover_id: fil_32ByteArray,
    ticket: fil_32ByteArray,
    comm_d: fil_32ByteArray,
    unpadded_byte_index: u64,
    unpadded_bytes_amount: u64,
) -> *mut fil_UnsealRangeResponse {
    catch_panic_response("unseal_range", || {
        use filepath::FilePath;
        use std::os::unix::io::{FromRawFd, IntoRawFd};

        let sealed_sector = std::fs::File::from_raw_fd(sealed_sector_fd_raw);
        let mut unseal_output = std::fs::File::from_raw_fd(unseal_output_fd_raw);

        filecoin_proofs_api::seal::get_unsealed_range_mapped(
            registered_proof.into(),
            cache_dir_path.as_path()?,
            sealed_sector.path().unwrap(),
            &mut unseal_output,
            prover_id.inner,
            SectorId::from(sector_id),
            comm_d.inner,
            ticket.inner,
            UnpaddedByteIndex(unpadded_byte_index),
            UnpaddedBytesAmount(unpadded_bytes_amount),
        )?;

        // keep all file descriptors alive until unseal_range returns
        let _ = sealed_sector.into_raw_fd();
        let _ = unseal_output.into_raw_fd();

        Ok(())
    })
}

/// Verifies the output of seal.
#[no_mangle]
pub unsafe extern "C" fn fil_verify_seal(
    registered_proof: fil_RegisteredSealProof,
    comm_r: fil_32ByteArray,
    comm_d: fil_32ByteArray,
    prover_id: fil_32ByteArray,
    ticket: fil_32ByteArray,
    seed: fil_32ByteArray,
    sector_id: u64,
    proof: &fil_Bytes,
) -> *mut super::types::fil_VerifySealResponse {
    catch_panic_response("verify_seal", || {
        let proof_bytes: Vec<u8> = proof.to_vec();

        let result = verify_seal(
            registered_proof.into(),
            comm_r.inner,
            comm_d.inner,
            prover_id.inner,
            SectorId::from(sector_id),
            ticket.inner,
            seed.inner,
            &proof_bytes,
        )?;

        Ok(result)
    })
}

/// TODO: document
#[no_mangle]
pub unsafe extern "C" fn fil_generate_winning_post_sector_challenge(
    registered_proof: fil_RegisteredPoStProof,
    randomness: fil_32ByteArray,
    sector_set_len: u64,
    prover_id: fil_32ByteArray,
) -> *mut fil_GenerateWinningPoStSectorChallenge {
    catch_panic_response("generate_winning_post_sector_challenge", || {
        let result = filecoin_proofs_api::post::generate_winning_post_sector_challenge(
            registered_proof.into(),
            &randomness.inner,
            sector_set_len,
            prover_id.inner,
        )?;

        Ok(result.into_iter().map(u64::from).collect::<Vec<_>>().into())
    })
}

/// TODO: document
#[no_mangle]
pub unsafe extern "C" fn fil_generate_fallback_sector_challenges(
    registered_proof: fil_RegisteredPoStProof,
    randomness: fil_32ByteArray,
    sector_ids: &fil_Array<u64>,
    prover_id: fil_32ByteArray,
) -> *mut fil_GenerateFallbackSectorChallengesResponse {
    catch_panic_response("generate_fallback_sector_challenges", || {
        let pub_sectors: Vec<SectorId> = sector_ids.iter().copied().map(Into::into).collect();

        let output = filecoin_proofs_api::post::generate_fallback_sector_challenges(
            registered_proof.into(),
            &randomness.inner,
            &pub_sectors,
            prover_id.inner,
        )?;

        let sector_ids: Vec<u64> = output
            .clone()
            .into_iter()
            .map(|(id, _challenges)| u64::from(id))
            .collect();
        let mut challenges_stride = 0;
        let mut challenges_stride_mismatch = false;
        let challenges: Vec<u64> = output
            .into_iter()
            .flat_map(|(_id, challenges)| {
                if challenges_stride == 0 {
                    challenges_stride = challenges.len();
                }

                if !challenges_stride_mismatch && challenges_stride != challenges.len() {
                    error!(
                        "All challenge strides must be equal: {} != {}",
                        challenges_stride,
                        challenges.len()
                    );
                    challenges_stride_mismatch = true;
                }

                challenges
            })
            .collect();

        if challenges_stride_mismatch {
            return Err(anyhow!("Challenge stride mismatch"));
        }
        Ok(fil_GenerateFallbackSectorChallenges {
            ids: sector_ids.into(),
            challenges: challenges.into(),
            challenges_stride,
        })
    })
}

/// TODO: document
#[no_mangle]
pub unsafe extern "C" fn fil_generate_single_vanilla_proof(
    replica: fil_PrivateReplicaInfo,
    challenges: &fil_Array<u64>,
) -> *mut fil_GenerateSingleVanillaProofResponse {
    catch_panic_response("generate_single_vanilla_proof", || {
        let sector_id = SectorId::from(replica.sector_id);
        let cache_dir_path = replica.cache_dir_path.as_path().expect("invalid cache dir");
        let replica_path = replica
            .replica_path
            .as_path()
            .expect("invalid replica path");

        let replica_v1 = PrivateReplicaInfo::new(
            replica.registered_proof.into(),
            replica.comm_r,
            cache_dir_path,
            replica_path,
        );

        let result = filecoin_proofs_api::post::generate_single_vanilla_proof(
            replica.registered_proof.into(),
            sector_id,
            &replica_v1,
            &*challenges,
        )?;
        Ok(result.into())
    })
}

/// TODO: document
#[no_mangle]
pub unsafe extern "C" fn fil_generate_winning_post_with_vanilla(
    registered_proof: fil_RegisteredPoStProof,
    randomness: fil_32ByteArray,
    prover_id: fil_32ByteArray,
    vanilla_proofs: &fil_Array<fil_VanillaProof>,
) -> *mut fil_GenerateWinningPoStResponse {
    catch_panic_response("generate_winning_post_with_vanilla", || {
        let vanilla_proofs: Vec<VanillaProof> = vanilla_proofs
            .iter()
            .map(|vanilla_proof| vanilla_proof.to_vec())
            .collect();

        let result = filecoin_proofs_api::post::generate_winning_post_with_vanilla(
            registered_proof.into(),
            &randomness.inner,
            prover_id.inner,
            &vanilla_proofs,
        )?;

        let result = result
            .into_iter()
            .map(|(t, proof)| fil_PoStProof {
                registered_proof: (t).into(),
                proof: proof.into(),
            })
            .collect::<Vec<_>>();

        Ok(result.into())
    })
}

/// TODO: document
#[no_mangle]
pub unsafe extern "C" fn fil_generate_winning_post(
    randomness: fil_32ByteArray,
    replicas: &fil_Array<fil_PrivateReplicaInfo>,
    prover_id: fil_32ByteArray,
) -> *mut fil_GenerateWinningPoStResponse {
    catch_panic_response("generate_winning_post", || {
        let replicas = to_private_replica_info_map(replicas)?;
        let result = filecoin_proofs_api::post::generate_winning_post(
            &randomness.inner,
            &replicas,
            prover_id.inner,
        )?;

        let result = result
            .into_iter()
            .map(|(t, proof)| fil_PoStProof {
                registered_proof: (t).into(),
                proof: proof.into(),
            })
            .collect::<Vec<_>>();

        Ok(result.into())
    })
}

/// Verifies that a proof-of-spacetime is valid.
#[no_mangle]
pub unsafe extern "C" fn fil_verify_winning_post(
    randomness: fil_32ByteArray,
    replicas: &fil_Array<fil_PublicReplicaInfo>,
    proofs: &fil_Array<fil_PoStProof>,
    prover_id: fil_32ByteArray,
) -> *mut fil_VerifyWinningPoStResponse {
    catch_panic_response("verify_winning_post", || {
        let replicas = to_public_replica_info_map(replicas);
        let proofs: Vec<u8> = proofs.iter().flat_map(|pp| pp.clone().proof).collect();

        let result = filecoin_proofs_api::post::verify_winning_post(
            &randomness.inner,
            &proofs,
            &replicas,
            prover_id.inner,
        )?;

        Ok(result)
    })
}

/// TODO: document
#[no_mangle]
pub unsafe extern "C" fn fil_generate_window_post_with_vanilla(
    registered_proof: fil_RegisteredPoStProof,
    randomness: fil_32ByteArray,
    prover_id: fil_32ByteArray,
    vanilla_proofs: &fil_Array<fil_VanillaProof>,
) -> *mut fil_GenerateWindowPoStResponse {
    catch_panic_response_raw("generate_window_post_with_vanilla", || {
        let vanilla_proofs: Vec<VanillaProof> = vanilla_proofs
            .iter()
            .map(|vanilla_proof| vanilla_proof.to_vec())
            .collect();

        let result = filecoin_proofs_api::post::generate_window_post_with_vanilla(
            registered_proof.into(),
            &randomness.inner,
            prover_id.inner,
            &vanilla_proofs,
        );

        let mut response = fil_GenerateWindowPoStResponse::default();

        match result {
            Ok(output) => {
                let mapped: Vec<fil_PoStProof> = output
                    .into_iter()
                    .map(|(t, proof)| fil_PoStProof {
                        registered_proof: t.into(),
                        proof: proof.into(),
                    })
                    .collect();

                response.status_code = FCPResponseStatus::FCPNoError;
                response.value.proofs = mapped.into();
            }
            Err(err) => {
                // If there were faulty sectors, add them to the response
                if let Some(StorageProofsError::FaultySectors(sectors)) =
                    err.downcast_ref::<StorageProofsError>()
                {
                    let sectors_u64 = sectors
                        .iter()
                        .map(|sector| u64::from(*sector))
                        .collect::<Vec<u64>>();

                    response.value.faulty_sectors = sectors_u64.into()
                }

                response.status_code = FCPResponseStatus::FCPUnclassifiedError;
                response.error_msg = err.to_string().into();
            }
        }

        response
    })
}

/// TODO: document
#[no_mangle]
pub unsafe extern "C" fn fil_generate_window_post(
    randomness: fil_32ByteArray,
    replicas: &fil_Array<fil_PrivateReplicaInfo>,
    prover_id: fil_32ByteArray,
) -> *mut fil_GenerateWindowPoStResponse {
    catch_panic_response_raw("generate_window_post", || {
        let result = to_private_replica_info_map(replicas).and_then(|replicas| {
            filecoin_proofs_api::post::generate_window_post(
                &randomness.inner,
                &replicas,
                prover_id.inner,
            )
        });

        let mut response = fil_GenerateWindowPoStResponse::default();
        match result {
            Ok(output) => {
                let mapped: Vec<fil_PoStProof> = output
                    .into_iter()
                    .map(|(t, proof)| fil_PoStProof {
                        registered_proof: t.into(),
                        proof: proof.into(),
                    })
                    .collect();

                response.status_code = FCPResponseStatus::FCPNoError;
                response.value.proofs = mapped.into();
            }
            Err(err) => {
                // If there were faulty sectors, add them to the response
                if let Some(StorageProofsError::FaultySectors(sectors)) =
                    err.downcast_ref::<StorageProofsError>()
                {
                    let sectors_u64 = sectors
                        .iter()
                        .map(|sector| u64::from(*sector))
                        .collect::<Vec<u64>>();

                    response.value.faulty_sectors = sectors_u64.into();
                }

                response.status_code = FCPResponseStatus::FCPUnclassifiedError;
                response.error_msg = err.to_string().into();
            }
        }

        response
    })
}

/// Verifies that a proof-of-spacetime is valid.
#[no_mangle]
pub unsafe extern "C" fn fil_verify_window_post(
    randomness: fil_32ByteArray,
    replicas: &fil_Array<fil_PublicReplicaInfo>,
    proofs: &fil_Array<fil_PoStProof>,
    prover_id: fil_32ByteArray,
) -> *mut fil_VerifyWindowPoStResponse {
    catch_panic_response("verify_window_post", || {
        let replicas = to_public_replica_info_map(replicas);
        let proofs: Vec<(RegisteredPoStProof, &[u8])> = proofs
            .iter()
            .map(|x| (RegisteredPoStProof::from(x.registered_proof), &x.proof[..]))
            .collect();

        let result = filecoin_proofs_api::post::verify_window_post(
            &randomness.inner,
            &proofs,
            &replicas,
            prover_id.inner,
        )?;

        Ok(result)
    })
}

/// TODO: document
#[no_mangle]
pub unsafe extern "C" fn fil_merge_window_post_partition_proofs(
    registered_proof: fil_RegisteredPoStProof,
    partition_proofs: &fil_Array<fil_PartitionSnarkProof>,
) -> *mut fil_MergeWindowPoStPartitionProofsResponse {
    catch_panic_response("merge_window_post_partition_proofs", || {
        let partition_proofs = partition_proofs
            .iter()
            .map(|pp| PartitionSnarkProof(pp.proof.to_vec()))
            .collect::<Vec<_>>();

        let proof = filecoin_proofs_api::post::merge_window_post_partition_proofs(
            registered_proof.into(),
            partition_proofs,
        )?;

        Ok(fil_PoStProof {
            registered_proof,
            proof: proof.into(),
        })
    })
}

/// TODO: document
#[no_mangle]
pub unsafe extern "C" fn fil_get_num_partition_for_fallback_post(
    registered_proof: fil_RegisteredPoStProof,
    num_sectors: libc::size_t,
) -> *mut fil_GetNumPartitionForFallbackPoStResponse {
    catch_panic_response("get_num_partition_for_fallback_post", || {
        let result = filecoin_proofs_api::post::get_num_partition_for_fallback_post(
            registered_proof.into(),
            num_sectors,
        )?;
        Ok(result)
    })
}

/// TODO: document
#[no_mangle]
pub unsafe extern "C" fn fil_generate_single_window_post_with_vanilla(
    registered_proof: fil_RegisteredPoStProof,
    randomness: fil_32ByteArray,
    prover_id: fil_32ByteArray,
    vanilla_proofs: &fil_Array<fil_VanillaProof>,
    partition_index: libc::size_t,
) -> *mut fil_GenerateSingleWindowPoStWithVanillaResponse {
    catch_panic_response_raw("generate_single_window_post_with_vanilla", || {
        let vanilla_proofs: Vec<VanillaProof> = vanilla_proofs
            .iter()
            .map(|vanilla_proof| vanilla_proof.to_vec())
            .collect();

        let result = filecoin_proofs_api::post::generate_single_window_post_with_vanilla(
            registered_proof.into(),
            &randomness.inner,
            prover_id.inner,
            &vanilla_proofs,
            partition_index,
        );

        let mut response = fil_GenerateSingleWindowPoStWithVanillaResponse::default();

        match result {
            Ok(output) => {
                let partition_proof = fil_PartitionSnarkProof {
                    registered_proof,
                    proof: output.0.into(),
                };

                response.status_code = FCPResponseStatus::FCPNoError;
                response.value.partition_proof = partition_proof;
            }
            Err(err) => {
                // If there were faulty sectors, add them to the response
                if let Some(StorageProofsError::FaultySectors(sectors)) =
                    err.downcast_ref::<StorageProofsError>()
                {
                    let sectors_u64 = sectors
                        .iter()
                        .map(|sector| u64::from(*sector))
                        .collect::<Vec<u64>>();

                    response.value.faulty_sectors = sectors_u64.into();
                }

                response.status_code = FCPResponseStatus::FCPUnclassifiedError;
                response.error_msg = err.to_string().into();
            }
        }

        response
    })
}

/// TODO: document
#[no_mangle]
pub unsafe extern "C" fn fil_empty_sector_update_encode_into(
    registered_proof: fil_RegisteredUpdateProof,
    new_replica_path: &fil_Bytes,
    new_cache_dir_path: &fil_Bytes,
    sector_key_path: &fil_Bytes,
    sector_key_cache_dir_path: &fil_Bytes,
    staged_data_path: &fil_Bytes,
    pieces: &fil_Array<fil_PublicPieceInfo>,
) -> *mut fil_EmptySectorUpdateEncodeIntoResponse {
    catch_panic_response("fil_empty_sector_update_encode_into", || {
        let public_pieces = pieces.iter().map(Into::into).collect::<Vec<_>>();

        let output = empty_sector_update_encode_into(
            registered_proof.into(),
            new_replica_path.as_path()?,
            new_cache_dir_path.as_path()?,
            sector_key_path.as_path()?,
            sector_key_cache_dir_path.as_path()?,
            staged_data_path.as_path()?,
            &public_pieces,
        )?;

        Ok(fil_EmptySectorUpdateEncodeInto {
            comm_r_new: output.comm_r_new,
            comm_r_last_new: output.comm_r_last_new,
            comm_d_new: output.comm_d_new,
        })
    })
}

/// TODO: document
#[no_mangle]
pub unsafe extern "C" fn fil_empty_sector_update_decode_from(
    registered_proof: fil_RegisteredUpdateProof,
    out_data_path: &fil_Bytes,
    replica_path: &fil_Bytes,
    sector_key_path: &fil_Bytes,
    sector_key_cache_dir_path: &fil_Bytes,
    comm_d_new: fil_32ByteArray,
) -> *mut fil_EmptySectorUpdateDecodeFromResponse {
    catch_panic_response("fil_empty_sector_update_decode_from", || {
        empty_sector_update_decode_from(
            registered_proof.into(),
            out_data_path.as_path()?,
            replica_path.as_path()?,
            sector_key_path.as_path()?,
            sector_key_cache_dir_path.as_path()?,
            comm_d_new.inner,
        )?;

        Ok(())
    })
}

/// TODO: document
#[no_mangle]
pub unsafe extern "C" fn fil_empty_sector_update_remove_encoded_data(
    registered_proof: fil_RegisteredUpdateProof,
    sector_key_path: &fil_Bytes,
    sector_key_cache_dir_path: &fil_Bytes,
    replica_path: &fil_Bytes,
    replica_cache_path: &fil_Bytes,
    data_path: &fil_Bytes,
    comm_d_new: fil_32ByteArray,
) -> *mut fil_EmptySectorUpdateRemoveEncodedDataResponse {
    catch_panic_response("fil_empty_sector_update_remove_encoded_data", || {
        empty_sector_update_remove_encoded_data(
            registered_proof.into(),
            sector_key_path.as_path()?,
            sector_key_cache_dir_path.as_path()?,
            replica_path.as_path()?,
            replica_cache_path.as_path()?,
            data_path.as_path()?,
            comm_d_new.inner,
        )?;

        Ok(())
    })
}

/// TODO: document
#[no_mangle]
pub unsafe extern "C" fn fil_generate_empty_sector_update_partition_proofs(
    registered_proof: fil_RegisteredUpdateProof,
    comm_r_old: fil_32ByteArray,
    comm_r_new: fil_32ByteArray,
    comm_d_new: fil_32ByteArray,
    sector_key_path: &fil_Bytes,
    sector_key_cache_dir_path: &fil_Bytes,
    replica_path: &fil_Bytes,
    replica_cache_path: &fil_Bytes,
) -> *mut fil_PartitionProofResponse {
    catch_panic_response("fil_generate_empty_sector_update_partition_proofs", || {
        let output = generate_partition_proofs(
            registered_proof.into(),
            comm_r_old.inner,
            comm_r_new.inner,
            comm_d_new.inner,
            sector_key_path.as_path()?,
            sector_key_cache_dir_path.as_path()?,
            replica_path.as_path()?,
            replica_cache_path.as_path()?,
        )?;

        let result = output
            .into_iter()
            .map(|proof| proof.0.into())
            .collect::<Vec<_>>()
            .into();
        Ok(result)
    })
}

/// TODO: document
#[no_mangle]
pub unsafe extern "C" fn fil_verify_empty_sector_update_partition_proofs(
    registered_proof: fil_RegisteredUpdateProof,
    proofs: &fil_Array<fil_PartitionProof>,
    comm_r_old: fil_32ByteArray,
    comm_r_new: fil_32ByteArray,
    comm_d_new: fil_32ByteArray,
) -> *mut fil_VerifyPartitionProofResponse {
    catch_panic_response("fil_verify_empty_sector_update_partition_proofs", || {
        let proofs: Vec<PartitionProofBytes> = proofs
            .iter()
            .map(|pp| PartitionProofBytes(pp.to_vec()))
            .collect();

        let result = verify_partition_proofs(
            registered_proof.into(),
            &proofs,
            comm_r_old.inner,
            comm_r_new.inner,
            comm_d_new.inner,
        )?;

        Ok(result)
    })
}

/// TODO: document
#[no_mangle]
pub unsafe extern "C" fn fil_generate_empty_sector_update_proof_with_vanilla(
    registered_proof: fil_RegisteredUpdateProof,
    vanilla_proofs: &fil_Array<fil_PartitionProof>,
    comm_r_old: fil_32ByteArray,
    comm_r_new: fil_32ByteArray,
    comm_d_new: fil_32ByteArray,
) -> *mut fil_EmptySectorUpdateProofResponse {
    catch_panic_response(
        "fil_generate_empty_sector_update_proof_with_vanilla",
        || {
            let partition_proofs: Vec<PartitionProofBytes> = vanilla_proofs
                .iter()
                .map(|partition_proof| PartitionProofBytes(partition_proof.to_vec()))
                .collect();

            let result = generate_empty_sector_update_proof_with_vanilla(
                registered_proof.into(),
                partition_proofs,
                comm_r_old.inner,
                comm_r_new.inner,
                comm_d_new.inner,
            )?;

            Ok(result.0.into())
        },
    )
}

/// TODO: document
#[no_mangle]
pub unsafe extern "C" fn fil_generate_empty_sector_update_proof(
    registered_proof: fil_RegisteredUpdateProof,
    comm_r_old: fil_32ByteArray,
    comm_r_new: fil_32ByteArray,
    comm_d_new: fil_32ByteArray,
    sector_key_path: &fil_Bytes,
    sector_key_cache_dir_path: &fil_Bytes,
    replica_path: &fil_Bytes,
    replica_cache_path: &fil_Bytes,
) -> *mut fil_EmptySectorUpdateProofResponse {
    catch_panic_response("fil_generate_empty_sector_update_proof", || {
        let result = generate_empty_sector_update_proof(
            registered_proof.into(),
            comm_r_old.inner,
            comm_r_new.inner,
            comm_d_new.inner,
            sector_key_path.as_path()?,
            sector_key_cache_dir_path.as_path()?,
            replica_path.as_path()?,
            replica_cache_path.as_path()?,
        )?;

        Ok(result.0.into())
    })
}

/// TODO: document
#[no_mangle]
pub unsafe extern "C" fn fil_verify_empty_sector_update_proof(
    registered_proof: fil_RegisteredUpdateProof,
    proof: &fil_Bytes,
    comm_r_old: fil_32ByteArray,
    comm_r_new: fil_32ByteArray,
    comm_d_new: fil_32ByteArray,
) -> *mut fil_VerifyEmptySectorUpdateProofResponse {
    catch_panic_response("fil_verify_empty_sector_update_proof", || {
        let proof_bytes: Vec<u8> = proof.to_vec();

        let result = verify_empty_sector_update_proof(
            registered_proof.into(),
            &proof_bytes,
            comm_r_old.inner,
            comm_r_new.inner,
            comm_d_new.inner,
        )?;

        Ok(result)
    })
}

/// Returns the merkle root for a piece after piece padding and alignment.
/// The caller is responsible for closing the passed in file descriptor.
#[no_mangle]
#[cfg(not(target_os = "windows"))]
pub unsafe extern "C" fn fil_generate_piece_commitment(
    registered_proof: fil_RegisteredSealProof,
    piece_fd_raw: libc::c_int,
    unpadded_piece_size: u64,
) -> *mut fil_GeneratePieceCommitmentResponse {
    catch_panic_response("fil_generate_piece_commitment", || {
        use std::os::unix::io::{FromRawFd, IntoRawFd};

        let mut piece_file = std::fs::File::from_raw_fd(piece_fd_raw);

        let unpadded_piece_size = UnpaddedBytesAmount(unpadded_piece_size);
        let result = generate_piece_commitment(
            registered_proof.into(),
            &mut piece_file,
            unpadded_piece_size,
        );

        // avoid dropping the File which closes it
        let _ = piece_file.into_raw_fd();

        let result = result.map(|meta| fil_GeneratePieceCommitment {
            comm_p: meta.commitment,
            num_bytes_aligned: meta.size.into(),
        })?;

        Ok(result)
    })
}

/// Returns the merkle root for a sector containing the provided pieces.
#[no_mangle]
pub unsafe extern "C" fn fil_generate_data_commitment(
    registered_proof: fil_RegisteredSealProof,
    pieces: &fil_Array<fil_PublicPieceInfo>,
) -> *mut fil_GenerateDataCommitmentResponse {
    catch_panic_response("generate_data_commitment", || {
        let public_pieces: Vec<PieceInfo> = pieces.iter().map(Into::into).collect();
        let result = compute_comm_d(registered_proof.into(), &public_pieces)?;

        Ok(result.into())
    })
}

#[no_mangle]
pub unsafe extern "C" fn fil_clear_cache(
    sector_size: u64,
    cache_dir_path: &fil_Bytes,
) -> *mut fil_ClearCacheResponse {
    catch_panic_response("fil_clear_cache", || {
        let result = clear_cache(sector_size, &cache_dir_path.as_path()?)?;

        Ok(result)
    })
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_write_with_alignment_response(
    ptr: *mut fil_WriteWithAlignmentResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_write_without_alignment_response(
    ptr: *mut fil_WriteWithoutAlignmentResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_fauxrep_response(ptr: *mut fil_FauxRepResponse) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_seal_pre_commit_phase1_response(
    ptr: *mut fil_SealPreCommitPhase1Response,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_seal_pre_commit_phase2_response(
    ptr: *mut fil_SealPreCommitPhase2Response,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_seal_commit_phase1_response(
    ptr: *mut fil_SealCommitPhase1Response,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_seal_commit_phase2_response(
    ptr: *mut fil_SealCommitPhase2Response,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_unseal_range_response(ptr: *mut fil_UnsealRangeResponse) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_generate_piece_commitment_response(
    ptr: *mut fil_GeneratePieceCommitmentResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_generate_data_commitment_response(
    ptr: *mut fil_GenerateDataCommitmentResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_string_response(ptr: *mut fil_StringResponse) {
    let _ = Box::from_raw(ptr);
}

/// Returns the number of user bytes that will fit into a staged sector.
#[no_mangle]
pub unsafe extern "C" fn fil_get_max_user_bytes_per_staged_sector(
    registered_proof: fil_RegisteredSealProof,
) -> u64 {
    u64::from(UnpaddedBytesAmount::from(
        RegisteredSealProof::from(registered_proof).sector_size(),
    ))
}

/// Returns the CID of the Groth parameter file for sealing.
#[no_mangle]
pub unsafe extern "C" fn fil_get_seal_params_cid(
    registered_proof: fil_RegisteredSealProof,
) -> *mut fil_StringResponse {
    registered_seal_proof_accessor(registered_proof, RegisteredSealProof::params_cid)
}

/// Returns the CID of the verifying key-file for verifying a seal proof.
#[no_mangle]
pub unsafe extern "C" fn fil_get_seal_verifying_key_cid(
    registered_proof: fil_RegisteredSealProof,
) -> *mut fil_StringResponse {
    registered_seal_proof_accessor(registered_proof, RegisteredSealProof::verifying_key_cid)
}

/// Returns the path from which the proofs library expects to find the Groth
/// parameter file used when sealing.
#[no_mangle]
pub unsafe extern "C" fn fil_get_seal_params_path(
    registered_proof: fil_RegisteredSealProof,
) -> *mut fil_StringResponse {
    registered_seal_proof_accessor(registered_proof, |p| {
        p.cache_params_path()
            .map(|pb| String::from(pb.to_string_lossy()))
    })
}

/// Returns the path from which the proofs library expects to find the verifying
/// key-file used when verifying a seal proof.
#[no_mangle]
pub unsafe extern "C" fn fil_get_seal_verifying_key_path(
    registered_proof: fil_RegisteredSealProof,
) -> *mut fil_StringResponse {
    registered_seal_proof_accessor(registered_proof, |p| {
        p.cache_verifying_key_path()
            .map(|pb| String::from(pb.to_string_lossy()))
    })
}

/// Returns the identity of the circuit for the provided seal proof.
#[no_mangle]
pub unsafe extern "C" fn fil_get_seal_circuit_identifier(
    registered_proof: fil_RegisteredSealProof,
) -> *mut fil_StringResponse {
    registered_seal_proof_accessor(registered_proof, RegisteredSealProof::circuit_identifier)
}

/// Returns the version of the provided seal proof type.
#[no_mangle]
pub unsafe extern "C" fn fil_get_seal_version(
    registered_proof: fil_RegisteredSealProof,
) -> *mut fil_StringResponse {
    registered_seal_proof_accessor(registered_proof, |p| Ok(format!("{:?}", p)))
}

/// Returns the CID of the Groth parameter file for generating a PoSt.
#[no_mangle]
pub unsafe extern "C" fn fil_get_post_params_cid(
    registered_proof: fil_RegisteredPoStProof,
) -> *mut fil_StringResponse {
    registered_post_proof_accessor(registered_proof, RegisteredPoStProof::params_cid)
}

/// Returns the CID of the verifying key-file for verifying a PoSt proof.
#[no_mangle]
pub unsafe extern "C" fn fil_get_post_verifying_key_cid(
    registered_proof: fil_RegisteredPoStProof,
) -> *mut fil_StringResponse {
    registered_post_proof_accessor(registered_proof, RegisteredPoStProof::verifying_key_cid)
}

/// Returns the path from which the proofs library expects to find the Groth
/// parameter file used when generating a PoSt.
#[no_mangle]
pub unsafe extern "C" fn fil_get_post_params_path(
    registered_proof: fil_RegisteredPoStProof,
) -> *mut fil_StringResponse {
    registered_post_proof_accessor(registered_proof, |p| {
        p.cache_params_path()
            .map(|pb| String::from(pb.to_string_lossy()))
    })
}

/// Returns the path from which the proofs library expects to find the verifying
/// key-file used when verifying a PoSt proof.
#[no_mangle]
pub unsafe extern "C" fn fil_get_post_verifying_key_path(
    registered_proof: fil_RegisteredPoStProof,
) -> *mut fil_StringResponse {
    registered_post_proof_accessor(registered_proof, |p| {
        p.cache_verifying_key_path()
            .map(|pb| String::from(pb.to_string_lossy()))
    })
}

/// Returns the identity of the circuit for the provided PoSt proof type.
#[no_mangle]
pub unsafe extern "C" fn fil_get_post_circuit_identifier(
    registered_proof: fil_RegisteredPoStProof,
) -> *mut fil_StringResponse {
    registered_post_proof_accessor(registered_proof, RegisteredPoStProof::circuit_identifier)
}

/// Returns the version of the provided seal proof.
#[no_mangle]
pub unsafe extern "C" fn fil_get_post_version(
    registered_proof: fil_RegisteredPoStProof,
) -> *mut fil_StringResponse {
    registered_post_proof_accessor(registered_proof, |p| Ok(format!("{:?}", p)))
}

unsafe fn registered_seal_proof_accessor(
    registered_proof: fil_RegisteredSealProof,
    op: fn(RegisteredSealProof) -> anyhow::Result<String>,
) -> *mut fil_StringResponse {
    let rsp: RegisteredSealProof = registered_proof.into();

    fil_StringResponse::from(op(rsp).map(Into::into)).into_boxed_raw()
}

unsafe fn registered_post_proof_accessor(
    registered_proof: fil_RegisteredPoStProof,
    op: fn(RegisteredPoStProof) -> anyhow::Result<String>,
) -> *mut fil_StringResponse {
    let rsp: RegisteredPoStProof = registered_proof.into();

    fil_StringResponse::from(op(rsp).map(Into::into)).into_boxed_raw()
}

/// Deallocates a VerifySealResponse.
#[no_mangle]
pub unsafe extern "C" fn fil_destroy_verify_seal_response(ptr: *mut fil_VerifySealResponse) {
    let _ = Box::from_raw(ptr);
}

/// Deallocates a VerifyAggregateSealProofResponse.
#[no_mangle]
pub unsafe extern "C" fn fil_destroy_verify_aggregate_seal_response(
    ptr: *mut fil_VerifyAggregateSealProofResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_finalize_ticket_response(
    ptr: *mut fil_FinalizeTicketResponse,
) {
    let _ = Box::from_raw(ptr);
}

/// Deallocates a VerifyPoStResponse.
#[no_mangle]
pub unsafe extern "C" fn fil_destroy_verify_winning_post_response(
    ptr: *mut fil_VerifyWinningPoStResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_verify_window_post_response(
    ptr: *mut fil_VerifyWindowPoStResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_generate_fallback_sector_challenges_response(
    ptr: *mut fil_GenerateFallbackSectorChallengesResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_generate_single_vanilla_proof_response(
    ptr: *mut fil_GenerateSingleVanillaProofResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_generate_single_window_post_with_vanilla_response(
    ptr: *mut fil_GenerateSingleWindowPoStWithVanillaResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_get_num_partition_for_fallback_post_response(
    ptr: *mut fil_GetNumPartitionForFallbackPoStResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_merge_window_post_partition_proofs_response(
    ptr: *mut fil_MergeWindowPoStPartitionProofsResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_generate_winning_post_response(
    ptr: *mut fil_GenerateWinningPoStResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_generate_window_post_response(
    ptr: *mut fil_GenerateWindowPoStResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_generate_winning_post_sector_challenge(
    ptr: *mut fil_GenerateWinningPoStSectorChallenge,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_clear_cache_response(ptr: *mut fil_ClearCacheResponse) {
    let _ = Box::from_raw(ptr);
}

/// Deallocates a AggregateProof
#[no_mangle]
pub unsafe extern "C" fn fil_destroy_aggregate_proof(ptr: *mut fil_AggregateProof) {
    let _ = Box::from_raw(ptr);
}

/// Deallocates a EmptySectorUpdateProof
#[no_mangle]
pub unsafe extern "C" fn fil_destroy_empty_sector_update_generate_proof_response(
    ptr: *mut fil_EmptySectorUpdateProofResponse,
) {
    let _ = Box::from_raw(ptr);
}

/// Deallocates a VerifyEmptySectorUpdateProofResponse
#[no_mangle]
pub unsafe extern "C" fn fil_destroy_empty_sector_update_verify_proof_response(
    ptr: *mut fil_VerifyEmptySectorUpdateProofResponse,
) {
    let _ = Box::from_raw(ptr);
}

/// Deallocates a PartitionProofResponse
#[no_mangle]
pub unsafe extern "C" fn fil_destroy_generate_empty_sector_update_partition_proof_response(
    ptr: *mut fil_PartitionProofResponse,
) {
    let _ = Box::from_raw(ptr);
}

/// Deallocates a VerifyEmptySectorUpdateProofResponse
#[no_mangle]
pub unsafe extern "C" fn fil_destroy_verify_empty_sector_update_partition_proof_response(
    ptr: *mut fil_VerifyPartitionProofResponse,
) {
    let _ = Box::from_raw(ptr);
}

/// Deallocates a EmptySectorUpdateEncodeIntoResponse
#[no_mangle]
pub unsafe extern "C" fn fil_destroy_empty_sector_update_encode_into_response(
    ptr: *mut fil_EmptySectorUpdateEncodeIntoResponse,
) {
    let _ = Box::from_raw(ptr);
}

/// Deallocates a EmptySectorUpdateDecodeFromResponse
#[no_mangle]
pub unsafe extern "C" fn fil_destroy_empty_sector_update_decode_from_response(
    ptr: *mut fil_EmptySectorUpdateDecodeFromResponse,
) {
    let _ = Box::from_raw(ptr);
}

/// Deallocates a EmptySectorUpdateRemoveEncodedDataResponse
#[no_mangle]
pub unsafe extern "C" fn fil_destroy_empty_sector_update_remove_encoded_data_response(
    ptr: *mut fil_EmptySectorUpdateRemoveEncodedDataResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[cfg(test)]
pub mod tests {
    use std::fs::{metadata, remove_file, OpenOptions};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::io::IntoRawFd;
    use std::path::Path;

    use anyhow::{ensure, Error, Result};
    use log::info;
    use memmap::MmapOptions;
    use rand::{thread_rng, Rng};

    use super::*;
    use fr32::bytes_into_fr;

    // This is a test method for ensuring that the elements of 1 file
    // matches the other.
    pub fn compare_elements(path1: &Path, path2: &Path) -> Result<(), Error> {
        info!("Comparing elements between {:?} and {:?}", path1, path2);
        let f_data1 = OpenOptions::new().read(true).open(path1)?;
        let data1 = unsafe { MmapOptions::new().map(&f_data1) }?;
        let f_data2 = OpenOptions::new().read(true).open(path2)?;
        let data2 = unsafe { MmapOptions::new().map(&f_data2) }?;
        let fr_size = std::mem::size_of::<Fr>() as usize;
        let end = metadata(path1)?.len() as u64;
        ensure!(
            metadata(path2)?.len() as u64 == end,
            "File sizes must match"
        );

        for i in (0..end).step_by(fr_size) {
            let index = i as usize;
            let fr1 = bytes_into_fr(&data1[index..index + fr_size])?;
            let fr2 = bytes_into_fr(&data2[index..index + fr_size])?;
            ensure!(fr1 == fr2, "Data mismatch when comparing elements");
        }
        info!("Match found for {:?} and {:?}", path1, path2);

        Ok(())
    }

    #[test]
    fn test_write_with_and_without_alignment() -> Result<()> {
        let registered_proof = fil_RegisteredSealProof::StackedDrg2KiBV1;

        // write some bytes to a temp file to be used as the byte source
        let mut rng = thread_rng();
        let buf: Vec<u8> = (0..508).map(|_| rng.gen()).collect();

        // first temp file occupies 4 nodes in a merkle tree built over the
        // destination (after preprocessing)
        let mut src_file_a = tempfile::tempfile()?;
        src_file_a.write_all(&buf[0..127])?;
        src_file_a.seek(SeekFrom::Start(0))?;

        // second occupies 16 nodes
        let mut src_file_b = tempfile::tempfile()?;
        src_file_b.write_all(&buf[0..508])?;
        src_file_b.seek(SeekFrom::Start(0))?;

        // create a temp file to be used as the byte destination
        let dest = tempfile::tempfile()?;

        // transmute temp files to file descriptors
        let src_fd_a = src_file_a.into_raw_fd();
        let src_fd_b = src_file_b.into_raw_fd();
        let dst_fd = dest.into_raw_fd();

        // write the first file
        unsafe {
            let resp = fil_write_without_alignment(registered_proof, src_fd_a, 127, dst_fd);

            if (*resp).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp).error_msg.as_str().unwrap();
                panic!("write_without_alignment failed: {:?}", msg);
            }

            assert_eq!(
                (*resp).total_write_unpadded,
                127,
                "should have added 127 bytes of (unpadded) left alignment"
            );
        }

        // write the second
        unsafe {
            let existing = vec![127u64];

            let resp =
                fil_write_with_alignment(registered_proof, src_fd_b, 508, dst_fd, existing.into());

            if (*resp).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp).error_msg.as_str().unwrap();
                panic!("write_with_alignment failed: {:?}", msg);
            }

            assert_eq!(
                (*resp).left_alignment_unpadded,
                381,
                "should have added 381 bytes of (unpadded) left alignment"
            );
        }

        Ok(())
    }

    #[test]
    fn test_proof_types() {
        let seal_types = vec![
            fil_RegisteredSealProof::StackedDrg2KiBV1,
            fil_RegisteredSealProof::StackedDrg8MiBV1,
            fil_RegisteredSealProof::StackedDrg512MiBV1,
            fil_RegisteredSealProof::StackedDrg32GiBV1,
            fil_RegisteredSealProof::StackedDrg64GiBV1,
            fil_RegisteredSealProof::StackedDrg2KiBV1_1,
            fil_RegisteredSealProof::StackedDrg8MiBV1_1,
            fil_RegisteredSealProof::StackedDrg512MiBV1_1,
            fil_RegisteredSealProof::StackedDrg32GiBV1_1,
            fil_RegisteredSealProof::StackedDrg64GiBV1_1,
        ];

        let post_types = vec![
            fil_RegisteredPoStProof::StackedDrgWinning2KiBV1,
            fil_RegisteredPoStProof::StackedDrgWinning8MiBV1,
            fil_RegisteredPoStProof::StackedDrgWinning512MiBV1,
            fil_RegisteredPoStProof::StackedDrgWinning32GiBV1,
            fil_RegisteredPoStProof::StackedDrgWinning64GiBV1,
            fil_RegisteredPoStProof::StackedDrgWindow2KiBV1,
            fil_RegisteredPoStProof::StackedDrgWindow8MiBV1,
            fil_RegisteredPoStProof::StackedDrgWindow512MiBV1,
            fil_RegisteredPoStProof::StackedDrgWindow32GiBV1,
            fil_RegisteredPoStProof::StackedDrgWindow64GiBV1,
        ];

        let num_ops = (seal_types.len() + post_types.len()) * 6;

        let mut pairs: Vec<(&str, *mut fil_StringResponse)> = Vec::with_capacity(num_ops);

        unsafe {
            for st in seal_types {
                pairs.push(("get_seal_params_cid", fil_get_seal_params_cid(st)));
                pairs.push((
                    "get_seal_verify_key_cid",
                    fil_get_seal_verifying_key_cid(st),
                ));
                pairs.push(("get_seal_verify_key_cid", fil_get_seal_params_path(st)));
                pairs.push((
                    "get_seal_verify_key_cid",
                    fil_get_seal_verifying_key_path(st),
                ));
                pairs.push((
                    "get_seal_circuit_identifier",
                    fil_get_seal_circuit_identifier(st),
                ));
                pairs.push(("get_seal_version", fil_get_seal_version(st)));
            }

            for pt in post_types {
                pairs.push(("get_post_params_cid", fil_get_post_params_cid(pt)));
                pairs.push((
                    "get_post_verify_key_cid",
                    fil_get_post_verifying_key_cid(pt),
                ));
                pairs.push(("get_post_params_path", fil_get_post_params_path(pt)));
                pairs.push((
                    "get_post_verifying_key_path",
                    fil_get_post_verifying_key_path(pt),
                ));
                pairs.push((
                    "get_post_circuit_identifier",
                    fil_get_post_circuit_identifier(pt),
                ));
                pairs.push(("get_post_version", fil_get_post_version(pt)));
            }
        }

        for (label, r) in pairs {
            unsafe {
                assert_eq!(
                    (*r).status_code,
                    FCPResponseStatus::FCPNoError,
                    "non-success exit code from {:?}: {:?}",
                    label,
                    (*r).error_msg.as_str().unwrap()
                );

                let y = (*r).as_str().unwrap();

                assert!(!y.is_empty());

                fil_destroy_string_response(r);
            }
        }
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn test_sealing_v1() -> Result<()> {
        test_sealing_inner(fil_RegisteredSealProof::StackedDrg2KiBV1)
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn test_sealing_v1_1() -> Result<()> {
        test_sealing_inner(fil_RegisteredSealProof::StackedDrg2KiBV1_1)
    }

    fn test_sealing_inner(registered_proof_seal: fil_RegisteredSealProof) -> Result<()> {
        let wrap = |x| fil_32ByteArray { inner: x };

        // miscellaneous setup and shared values
        let registered_proof_winning_post = fil_RegisteredPoStProof::StackedDrgWinning2KiBV1;
        let registered_proof_window_post = fil_RegisteredPoStProof::StackedDrgWindow2KiBV1;

        let cache_dir = tempfile::tempdir()?;
        let cache_dir_path: fil_Bytes = cache_dir.into_path().into();

        let prover_id = fil_32ByteArray { inner: [1u8; 32] };
        let randomness = fil_32ByteArray { inner: [7u8; 32] };
        let sector_id = 42;
        let sector_id2 = 43;
        let seed = fil_32ByteArray { inner: [5u8; 32] };
        let ticket = fil_32ByteArray { inner: [6u8; 32] };

        // create a byte source (a user's piece)
        let mut rng = thread_rng();
        let buf_a: Vec<u8> = (0..2032).map(|_| rng.gen()).collect();

        let mut piece_file_a = tempfile::tempfile()?;
        piece_file_a.write_all(&buf_a[0..127])?;
        piece_file_a.seek(SeekFrom::Start(0))?;

        let mut piece_file_b = tempfile::tempfile()?;
        piece_file_b.write_all(&buf_a[0..1016])?;
        piece_file_b.seek(SeekFrom::Start(0))?;

        // create the staged sector (the byte destination)
        let (staged_file, staged_path) = tempfile::NamedTempFile::new()?.keep()?;
        let staged_path: fil_Bytes = staged_path.into();

        // create a temp file to be used as the byte destination
        let (sealed_file, sealed_path) = tempfile::NamedTempFile::new()?.keep()?;
        let sealed_path: fil_Bytes = sealed_path.into();

        // last temp file is used to output unsealed bytes
        let (unseal_file, unseal_path) = tempfile::NamedTempFile::new()?.keep()?;

        // transmute temp files to file descriptors
        let piece_file_a_fd = piece_file_a.into_raw_fd();
        let piece_file_b_fd = piece_file_b.into_raw_fd();
        let staged_sector_fd = staged_file.into_raw_fd();

        unsafe {
            let resp_a1 = fil_write_without_alignment(
                registered_proof_seal,
                piece_file_a_fd,
                127,
                staged_sector_fd,
            );

            if (*resp_a1).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_a1).error_msg.as_str().unwrap();
                panic!("write_without_alignment failed: {:?}", msg);
            }

            let existing_piece_sizes = vec![127];

            let resp_a2 = fil_write_with_alignment(
                registered_proof_seal,
                piece_file_b_fd,
                1016,
                staged_sector_fd,
                existing_piece_sizes.into(),
            );

            if (*resp_a2).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_a2).error_msg.as_str().unwrap();
                panic!("write_with_alignment failed: {:?}", msg);
            }

            let pieces = vec![
                fil_PublicPieceInfo {
                    num_bytes: 127,
                    comm_p: (*resp_a1).comm_p,
                },
                fil_PublicPieceInfo {
                    num_bytes: 1016,
                    comm_p: (*resp_a2).comm_p,
                },
            ]
            .into();

            let resp_x = fil_generate_data_commitment(registered_proof_seal, &pieces);

            if (*resp_x).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_x).error_msg.as_str().unwrap();
                panic!("generate_data_commitment failed: {:?}", msg);
            }

            let resp_b1 = fil_seal_pre_commit_phase1(
                registered_proof_seal,
                &cache_dir_path,
                &staged_path,
                &sealed_path,
                sector_id,
                prover_id,
                ticket,
                &pieces,
            );

            if (*resp_b1).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_b1).error_msg.as_str().unwrap();
                panic!("seal_pre_commit_phase1 failed: {:?}", msg);
            }

            let resp_b2 =
                fil_seal_pre_commit_phase2((*resp_b1).value.clone(), &cache_dir_path, &sealed_path);

            if (*resp_b2).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_b2).error_msg.as_str().unwrap();
                panic!("seal_pre_commit_phase2 failed: {:?}", msg);
            }

            let pre_computed_comm_d: &[u8; 32] = &(*resp_x);
            let pre_commit_comm_d: &[u8; 32] = &(*resp_b2).comm_d;

            assert_eq!(
                format!("{:x?}", &pre_computed_comm_d),
                format!("{:x?}", &pre_commit_comm_d),
                "pre-computed CommD and pre-commit CommD don't match"
            );

            let resp_c1 = fil_seal_commit_phase1(
                registered_proof_seal,
                wrap((*resp_b2).comm_r),
                wrap((*resp_b2).comm_d),
                &cache_dir_path,
                &sealed_path,
                sector_id,
                prover_id,
                ticket,
                seed,
                &pieces,
            );

            if (*resp_c1).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_c1).error_msg.as_str().unwrap();
                panic!("seal_commit_phase1 failed: {:?}", msg);
            }

            let resp_c2 = fil_seal_commit_phase2(&(*resp_c1), sector_id, prover_id);

            if (*resp_c2).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_c2).error_msg.as_str().unwrap();
                panic!("seal_commit_phase2 failed: {:?}", msg);
            }

            let resp_d = fil_verify_seal(
                registered_proof_seal,
                wrap((*resp_b2).comm_r),
                wrap((*resp_b2).comm_d),
                prover_id,
                ticket,
                seed,
                sector_id,
                &(*resp_c2).proof,
            );

            if (*resp_d).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_d).error_msg.as_str().unwrap();
                panic!("seal_commit failed: {:?}", msg);
            }

            assert!(*(*resp_d), "proof was not valid");

            let resp_c22 = fil_seal_commit_phase2(&(*resp_c1), sector_id, prover_id);

            if (*resp_c22).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_c22).error_msg.as_str().unwrap();
                panic!("seal_commit_phase2 failed: {:?}", msg);
            }

            let resp_d2 = fil_verify_seal(
                registered_proof_seal,
                wrap((*resp_b2).comm_r),
                wrap((*resp_b2).comm_d),
                prover_id,
                ticket,
                seed,
                sector_id,
                &(*resp_c22).proof,
            );

            if (*resp_d2).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_d2).error_msg.as_str().unwrap();
                panic!("seal_commit failed: {:?}", msg);
            }

            assert!(*(*resp_d2), "proof was not valid");

            //////////////////////////////////////////////////////////////////
            // Begin Sector Upgrade testing
            /*
                At this point, upgrade the sector with additional data
                and generate sector update proofs, then test decoding,
                then finally remove the data and continue onward as
                normal.
            */
            let registered_proof_empty_sector_update = fil_RegisteredUpdateProof::StackedDrg2KiBV1;

            let new_cache_dir = tempfile::tempdir()?;
            let new_cache_dir_path = new_cache_dir.into_path();
            let removed_data_dir = tempfile::tempdir()?;
            let removed_data_dir_path = removed_data_dir.into_path();

            let buf_b: Vec<u8> = (0..2032).map(|_| rng.gen()).collect();
            let mut piece_file_c = tempfile::tempfile()?;
            piece_file_c.write_all(&buf_b[0..127])?;
            piece_file_c.seek(SeekFrom::Start(0))?;

            let mut piece_file_d = tempfile::tempfile()?;
            piece_file_d.write_all(&buf_a[0..1016])?;
            piece_file_d.seek(SeekFrom::Start(0))?;

            // create the new staged sector (the byte destination)
            let (new_staged_file, new_staged_path) = tempfile::NamedTempFile::new()?.keep()?;
            // create a temp file to be used as the byte destination
            let (_new_sealed_file, new_sealed_path) = tempfile::NamedTempFile::new()?.keep()?;
            // create a temp file to be used as the decoded destination
            let (_decoded_file, decoded_path) = tempfile::NamedTempFile::new()?.keep()?;
            // create a temp file to be used as the removed data destination
            let (_removed_data_file, removed_data_path) = tempfile::NamedTempFile::new()?.keep()?;

            // transmute temp files to file descriptors
            let piece_file_c_fd = piece_file_c.into_raw_fd();
            let piece_file_d_fd = piece_file_d.into_raw_fd();
            let new_staged_sector_fd = new_staged_file.into_raw_fd();

            let resp_new_a1 = fil_write_without_alignment(
                registered_proof_seal,
                piece_file_c_fd,
                127,
                new_staged_sector_fd,
            );

            if (*resp_new_a1).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_new_a1).error_msg.as_str().unwrap();
                panic!("write_without_alignment failed: {:?}", msg);
            }

            let existing_piece_sizes = vec![127];

            let resp_new_a2 = fil_write_with_alignment(
                registered_proof_seal,
                piece_file_d_fd,
                1016,
                new_staged_sector_fd,
                existing_piece_sizes.into(),
            );

            if (*resp_new_a2).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_new_a2).error_msg.as_str().unwrap();
                panic!("write_with_alignment failed: {:?}", msg);
            }

            let new_pieces = vec![
                fil_PublicPieceInfo {
                    num_bytes: 127,
                    comm_p: (*resp_new_a1).comm_p,
                },
                fil_PublicPieceInfo {
                    num_bytes: 1016,
                    comm_p: (*resp_new_a2).comm_p,
                },
            ]
            .into();

            let resp_new_x = fil_generate_data_commitment(registered_proof_seal, &new_pieces);

            if (*resp_new_x).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_new_x).error_msg.as_str().unwrap();
                panic!("generate_data_commitment failed: {:?}", msg);
            }

            let new_cache_dir_path = new_cache_dir_path.into();
            let new_staged_path: fil_Bytes = new_staged_path.into();
            let new_sealed_path: fil_Bytes = new_sealed_path.into();
            let decoded_path: fil_Bytes = decoded_path.into();
            let removed_data_path: fil_Bytes = removed_data_path.into();
            let removed_data_dir_path = removed_data_dir_path.into();

            // Set the new_sealed_file length to the same as the
            // original sealed file length (required for the API, but
            // this is a test-specific workaround)
            let new_sealed_target_len = metadata(&sealed_path.as_path().unwrap())?.len();
            let f_new_sealed_sector = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(new_sealed_path.as_path().unwrap())?;
            f_new_sealed_sector.set_len(new_sealed_target_len)?;

            let resp_encode = fil_empty_sector_update_encode_into(
                registered_proof_empty_sector_update,
                &new_sealed_path,
                &new_cache_dir_path,
                &sealed_path,
                &cache_dir_path,
                &new_staged_path,
                &new_pieces,
            );

            if (*resp_encode).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_encode).error_msg.as_str().unwrap();
                panic!("empty_sector_update_encode_into failed: {:?}", msg);
            }

            // First generate all vanilla partition proofs
            let resp_partition_proofs = fil_generate_empty_sector_update_partition_proofs(
                registered_proof_empty_sector_update,
                wrap((*resp_b2).comm_r),
                wrap((*resp_encode).comm_r_new),
                wrap((*resp_encode).comm_d_new),
                &sealed_path,
                &cache_dir_path,
                &new_sealed_path,
                &new_cache_dir_path,
            );

            if (*resp_partition_proofs).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_partition_proofs).error_msg.as_str().unwrap();
                panic!("generate_partition_proofs failed: {:?}", msg);
            }

            // Verify vanilla partition proofs
            let resp_verify_partition_proofs = fil_verify_empty_sector_update_partition_proofs(
                registered_proof_empty_sector_update,
                &(*resp_partition_proofs),
                wrap((*resp_b2).comm_r),
                wrap((*resp_encode).comm_r_new),
                wrap((*resp_encode).comm_d_new),
            );

            if (*resp_verify_partition_proofs).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_verify_partition_proofs).error_msg.as_str().unwrap();
                panic!("verify_partition_proofs failed: {:?}", msg);
            }

            // Then generate the sector update proof with the vanilla proofs
            let resp_empty_sector_update = fil_generate_empty_sector_update_proof_with_vanilla(
                registered_proof_empty_sector_update,
                &(*resp_partition_proofs),
                wrap((*resp_b2).comm_r),
                wrap((*resp_encode).comm_r_new),
                wrap((*resp_encode).comm_d_new),
            );

            if (*resp_empty_sector_update).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_empty_sector_update).error_msg.as_str().unwrap();
                panic!(
                    "generate_empty_sector_update_proof_with_vanilla failed: {:?}",
                    msg
                );
            }

            // And verify that sector update proof
            let resp_verify_empty_sector_update = fil_verify_empty_sector_update_proof(
                registered_proof_empty_sector_update,
                &(*resp_empty_sector_update),
                wrap((*resp_b2).comm_r),
                wrap((*resp_encode).comm_r_new),
                wrap((*resp_encode).comm_d_new),
            );

            if (*resp_verify_empty_sector_update).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_verify_empty_sector_update)
                    .error_msg
                    .as_str()
                    .unwrap();
                panic!("verify_empty_sector_update_proof failed: {:?}", msg);
            }

            // Now re-generate the empty sector update monolithically (the vanilla proofs are generated internally)
            let resp_empty_sector_update2 = fil_generate_empty_sector_update_proof(
                registered_proof_empty_sector_update,
                wrap((*resp_b2).comm_r),
                wrap((*resp_encode).comm_r_new),
                wrap((*resp_encode).comm_d_new),
                &sealed_path,
                &cache_dir_path,
                &new_sealed_path,
                &new_cache_dir_path,
            );

            if (*resp_empty_sector_update2).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_empty_sector_update2).error_msg.as_str().unwrap();
                panic!("generate_empty_sector_update_proof failed: {:?}", msg);
            }

            let resp_verify_empty_sector_update2 = fil_verify_empty_sector_update_proof(
                registered_proof_empty_sector_update,
                &(*resp_empty_sector_update2),
                wrap((*resp_b2).comm_r),
                wrap((*resp_encode).comm_r_new),
                wrap((*resp_encode).comm_d_new),
            );

            if (*resp_verify_empty_sector_update2).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_verify_empty_sector_update2)
                    .error_msg
                    .as_str()
                    .unwrap();
                panic!("verify_empty_sector_update_proof failed: {:?}", msg);
            }

            // Set the new_decoded_file length to the same as the
            // original sealed file length (required for the API, but
            // this is a test-specific workaround)
            let f_decoded_sector = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(&decoded_path.as_path().unwrap())?;
            f_decoded_sector.set_len(new_sealed_target_len)?;

            let resp_decode = fil_empty_sector_update_decode_from(
                registered_proof_empty_sector_update,
                &decoded_path,
                &new_sealed_path,
                &sealed_path,
                &cache_dir_path,
                wrap((*resp_encode).comm_d_new),
            );

            if (*resp_decode).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_decode).error_msg.as_str().unwrap();
                panic!("empty_sector_update_decode_from failed: {:?}", msg);
            }

            // When the data is decoded, it MUST match the original new staged data.
            compare_elements(
                &decoded_path.as_path().unwrap(),
                &new_staged_path.as_path().unwrap(),
            )?;

            // Set the new_removed_data_file length to the same as the
            // original sealed file length (required for the API, but
            // this is a test-specific workaround)
            let f_removed_data_sector = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(&removed_data_path.as_path().unwrap())?;
            f_removed_data_sector.set_len(new_sealed_target_len)?;

            let resp_removed = fil_empty_sector_update_remove_encoded_data(
                registered_proof_empty_sector_update,
                &removed_data_path,
                &removed_data_dir_path,
                &new_sealed_path, // new sealed file path
                &cache_dir_path,  // old replica dir path (for p_aux)
                &new_staged_path, // new staged file data path
                wrap((*resp_encode).comm_d_new),
            );

            if (*resp_removed).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_removed).error_msg.as_str().unwrap();
                panic!("empty_sector_update_remove_encoded_data failed: {:?}", msg);
            }

            // When the data is removed, it MUST match the original sealed data.
            compare_elements(
                &removed_data_path.as_path().unwrap(),
                &sealed_path.as_path().unwrap(),
            )?;

            fil_destroy_write_without_alignment_response(resp_new_a1);
            fil_destroy_write_with_alignment_response(resp_new_a2);
            fil_destroy_generate_data_commitment_response(resp_new_x);

            fil_destroy_empty_sector_update_encode_into_response(resp_encode);
            fil_destroy_empty_sector_update_decode_from_response(resp_decode);
            fil_destroy_empty_sector_update_remove_encoded_data_response(resp_removed);

            fil_destroy_generate_empty_sector_update_partition_proof_response(
                resp_partition_proofs,
            );
            fil_destroy_verify_empty_sector_update_partition_proof_response(
                resp_verify_partition_proofs,
            );

            fil_destroy_empty_sector_update_generate_proof_response(resp_empty_sector_update);
            fil_destroy_empty_sector_update_generate_proof_response(resp_empty_sector_update2);
            fil_destroy_empty_sector_update_verify_proof_response(resp_verify_empty_sector_update);
            fil_destroy_empty_sector_update_verify_proof_response(resp_verify_empty_sector_update2);

            ensure!(
                remove_file(&new_staged_path.as_path().unwrap()).is_ok(),
                "failed to remove new_staged_path"
            );
            ensure!(
                remove_file(&new_sealed_path.as_path().unwrap()).is_ok(),
                "failed to remove new_sealed_path"
            );
            ensure!(
                remove_file(&decoded_path.as_path().unwrap()).is_ok(),
                "failed to remove decoded_path"
            );
            ensure!(
                remove_file(&removed_data_path.as_path().unwrap()).is_ok(),
                "failed to remove unseal_path"
            );
            // End Sector Upgrade testing
            //////////////////////////////////////////////////////////////////

            let resp_e = fil_unseal_range(
                registered_proof_seal,
                &cache_dir_path,
                sealed_file.into_raw_fd(),
                unseal_file.into_raw_fd(),
                sector_id,
                prover_id,
                ticket,
                wrap((*resp_b2).comm_d),
                0,
                2032,
            );

            if (*resp_e).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_e).error_msg.as_str().unwrap();
                panic!("unseal failed: {:?}", msg);
            }

            // ensure unsealed bytes match what we had in our piece
            let mut buf_b = Vec::with_capacity(2032);
            let mut f = std::fs::File::open(&unseal_path)?;

            let _ = f.read_to_end(&mut buf_b)?;

            let piece_a_len = (*resp_a1).total_write_unpadded as usize;
            let piece_b_len = (*resp_a2).total_write_unpadded as usize;
            let piece_b_prefix_len = (*resp_a2).left_alignment_unpadded as usize;

            let alignment = vec![0; piece_b_prefix_len];

            let expected = [
                &buf_a[0..piece_a_len],
                &alignment[..],
                &buf_a[0..(piece_b_len - piece_b_prefix_len)],
            ]
            .concat();

            assert_eq!(
                format!("{:x?}", &expected),
                format!("{:x?}", &buf_b),
                "original bytes don't match unsealed bytes"
            );

            // generate a PoSt

            let sectors = vec![sector_id];
            let resp_f = fil_generate_winning_post_sector_challenge(
                registered_proof_winning_post,
                randomness,
                sectors.len() as u64,
                prover_id,
            );

            if (*resp_f).status_code != FCPResponseStatus::FCPNoError {
                panic!(
                    "generate_candidates failed: {}",
                    (*resp_f).error_msg.as_str().unwrap()
                );
            }

            // exercise the ticket-finalizing code path (but don't do anything with the results
            let result: &[u64] = &(*resp_f);

            if result.is_empty() {
                panic!("generate_candidates produced no results");
            }

            let private_replicas = vec![fil_PrivateReplicaInfo {
                registered_proof: registered_proof_winning_post,
                cache_dir_path: cache_dir_path.clone(),
                comm_r: (*resp_b2).comm_r,
                replica_path: sealed_path.clone(),
                sector_id,
            }]
            .into();

            // winning post

            let resp_h = fil_generate_winning_post(randomness, &private_replicas, prover_id);

            if (*resp_h).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_h).error_msg.as_str().unwrap();
                panic!("generate_winning_post failed: {:?}", msg);
            }
            let public_replicas = vec![fil_PublicReplicaInfo {
                registered_proof: registered_proof_winning_post,
                sector_id,
                comm_r: (*resp_b2).comm_r,
            }]
            .into();

            let resp_i =
                fil_verify_winning_post(randomness, &public_replicas, &(*resp_h), prover_id);

            if (*resp_i).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_i).error_msg.as_str().unwrap();
                panic!("verify_winning_post failed: {:?}", msg);
            }

            if !*(*resp_i) {
                panic!("verify_winning_post rejected the provided proof as invalid");
            }

            //////////////////////////////////////////////
            // Winning PoSt using distributed API
            //
            // NOTE: This performs the winning post all over again, just using
            // a different API.  This is just for testing and would not normally
            // be repeated like this in sequence.
            //
            //////////////////////////////////////////////

            // First generate sector challenges.
            let resp_sc = fil_generate_fallback_sector_challenges(
                registered_proof_winning_post,
                randomness,
                &sectors.into(),
                prover_id,
            );

            if (*resp_sc).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_sc).error_msg.as_str().unwrap();
                panic!("fallback_sector_challenges failed: {:?}", msg);
            }

            let sector_ids: Vec<u64> = (*resp_sc).ids.to_vec();
            let sector_challenges: Vec<u64> = (*resp_sc).challenges.to_vec();
            let challenges_stride = (*resp_sc).challenges_stride;
            let challenge_iterations = sector_challenges.len() / challenges_stride;
            assert_eq!(
                sector_ids.len(),
                challenge_iterations,
                "Challenge iterations must match the number of sector ids"
            );

            let mut vanilla_proofs: Vec<fil_VanillaProof> = Vec::with_capacity(sector_ids.len());

            // Gather up all vanilla proofs.
            for i in 0..challenge_iterations {
                let sector_id = sector_ids[i];
                let challenges = sector_challenges
                    [i * challenges_stride..i * challenges_stride + challenges_stride]
                    .into();
                let private_replica = private_replicas
                    .iter()
                    .find(|&replica| replica.sector_id == sector_id)
                    .expect("failed to find private replica info")
                    .clone();

                let resp_vp = fil_generate_single_vanilla_proof(private_replica, &challenges);

                if (*resp_vp).status_code != FCPResponseStatus::FCPNoError {
                    let msg = (*resp_vp).error_msg.as_str().unwrap();
                    panic!("generate_single_vanilla_proof failed: {:?}", msg);
                }

                vanilla_proofs.push((*resp_vp).value.clone());
                fil_destroy_generate_single_vanilla_proof_response(resp_vp);
            }

            let resp_wpwv = fil_generate_winning_post_with_vanilla(
                registered_proof_winning_post,
                randomness,
                prover_id,
                &vanilla_proofs.into(),
            );

            if (*resp_wpwv).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_wpwv).error_msg.as_str().unwrap();
                panic!("generate_winning_post_with_vanilla failed: {:?}", msg);
            }

            // Verify the second winning post (generated by the distributed post API)
            let resp_di =
                fil_verify_winning_post(randomness, &public_replicas, &(*resp_wpwv), prover_id);

            if (*resp_di).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_di).error_msg.as_str().unwrap();
                panic!("verify_winning_post failed: {:?}", msg);
            }

            if !*(*resp_di) {
                panic!("verify_winning_post rejected the provided proof as invalid");
            }

            // window post

            let private_replicas = vec![fil_PrivateReplicaInfo {
                registered_proof: registered_proof_window_post,
                cache_dir_path: cache_dir_path.clone(),
                comm_r: (*resp_b2).comm_r,
                replica_path: sealed_path.clone(),
                sector_id,
            }];

            let resp_j = fil_generate_window_post(randomness, &private_replicas.into(), prover_id);

            if (*resp_j).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_j).error_msg.as_str().unwrap();
                panic!("generate_window_post failed: {:?}", msg);
            }

            let public_replicas = vec![fil_PublicReplicaInfo {
                registered_proof: registered_proof_window_post,
                sector_id,
                comm_r: (*resp_b2).comm_r,
            }];

            let resp_k = fil_verify_window_post(
                randomness,
                &public_replicas.into(),
                &(*resp_j).proofs,
                prover_id,
            );

            if (*resp_k).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_k).error_msg.as_str().unwrap();
                panic!("verify_window_post failed: {:?}", msg);
            }

            if !*(*resp_k) {
                panic!("verify_window_post rejected the provided proof as invalid");
            }

            //////////////////////////////////////////////
            // Window PoSt using distributed API
            //
            // NOTE: This performs the window post all over again, just using
            // a different API.  This is just for testing and would not normally
            // be repeated like this in sequence.
            //
            //////////////////////////////////////////////

            let sectors = vec![sector_id, sector_id2].into();
            let private_replicas = vec![
                fil_PrivateReplicaInfo {
                    registered_proof: registered_proof_window_post,
                    cache_dir_path: cache_dir_path.clone(),
                    comm_r: (*resp_b2).comm_r,
                    replica_path: sealed_path.clone(),
                    sector_id,
                },
                fil_PrivateReplicaInfo {
                    registered_proof: registered_proof_window_post,
                    cache_dir_path,
                    comm_r: (*resp_b2).comm_r,
                    replica_path: sealed_path.clone(),
                    sector_id: sector_id2,
                },
            ];
            let public_replicas = vec![
                fil_PublicReplicaInfo {
                    registered_proof: registered_proof_window_post,
                    sector_id,
                    comm_r: (*resp_b2).comm_r,
                },
                fil_PublicReplicaInfo {
                    registered_proof: registered_proof_window_post,
                    sector_id: sector_id2,
                    comm_r: (*resp_b2).comm_r,
                },
            ]
            .into();

            // Generate sector challenges.
            let resp_sc2 = fil_generate_fallback_sector_challenges(
                registered_proof_window_post,
                randomness,
                &sectors,
                prover_id,
            );

            if (*resp_sc2).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_sc2).error_msg.as_str().unwrap();
                panic!("fallback_sector_challenges failed: {:?}", msg);
            }

            let sector_ids: Vec<u64> = (*resp_sc2).ids.to_vec();
            let sector_challenges: Vec<u64> = (*resp_sc2).challenges.to_vec();
            let challenges_stride = (*resp_sc2).challenges_stride;
            let challenge_iterations = sector_challenges.len() / challenges_stride;
            assert_eq!(
                sector_ids.len(),
                challenge_iterations,
                "Challenge iterations must match the number of sector ids"
            );

            let mut vanilla_proofs: Vec<fil_VanillaProof> = Vec::with_capacity(sector_ids.len());

            // Gather up all vanilla proofs.
            for i in 0..challenge_iterations {
                let sector_id = sector_ids[i];
                let challenges = sector_challenges
                    [i * challenges_stride..i * challenges_stride + challenges_stride]
                    .into();

                let private_replica = private_replicas
                    .iter()
                    .find(|&replica| replica.sector_id == sector_id)
                    .expect("failed to find private replica info")
                    .clone();

                let resp_vp = fil_generate_single_vanilla_proof(private_replica, &challenges);

                if (*resp_vp).status_code != FCPResponseStatus::FCPNoError {
                    let msg = (*resp_vp).error_msg.as_str().unwrap();
                    panic!("generate_single_vanilla_proof failed: {:?}", msg);
                }

                vanilla_proofs.push((*resp_vp).value.clone());
                fil_destroy_generate_single_vanilla_proof_response(resp_vp);
            }

            let resp_wpwv2 = fil_generate_window_post_with_vanilla(
                registered_proof_window_post,
                randomness,
                prover_id,
                &vanilla_proofs.into(),
            );

            if (*resp_wpwv2).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_wpwv2).error_msg.as_str().unwrap();
                panic!("generate_window_post_with_vanilla failed: {:?}", msg);
            }

            let resp_k2 = fil_verify_window_post(
                randomness,
                &public_replicas,
                &(*resp_wpwv2).proofs,
                prover_id,
            );

            if (*resp_k2).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_k2).error_msg.as_str().unwrap();
                panic!("verify_window_post failed: {:?}", msg);
            }

            if !*(*resp_k2) {
                panic!("verify_window_post rejected the provided proof as invalid");
            }

            //////////////////////////////////////////////
            // Window PoSt using single partition API
            //
            // NOTE: This performs the window post all over again, just using
            // a different API.  This is just for testing and would not normally
            // be repeated like this in sequence.
            //
            //////////////////////////////////////////////

            // Note: Re-using all of the sector challenges and types
            // required from above previous distributed PoSt API run.

            let num_partitions_resp = fil_get_num_partition_for_fallback_post(
                registered_proof_window_post,
                sectors.len(),
            );
            if (*num_partitions_resp).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*num_partitions_resp).error_msg.as_str().unwrap();
                panic!("get_num_partition_for_fallback_post failed: {:?}", msg);
            }

            let mut partition_proofs: Vec<fil_PartitionSnarkProof> =
                Vec::with_capacity(**num_partitions_resp);
            for partition_index in 0..(**num_partitions_resp) {
                let mut vanilla_proofs = Vec::with_capacity(challenge_iterations);
                for i in 0..challenge_iterations {
                    let sector_id = sector_ids[i];
                    let challenges = sector_challenges
                        [i * challenges_stride..i * challenges_stride + challenges_stride]
                        .into();

                    let private_replica = private_replicas
                        .iter()
                        .find(|&replica| replica.sector_id == sector_id)
                        .expect("failed to find private replica info")
                        .clone();

                    let resp_vp = fil_generate_single_vanilla_proof(private_replica, &challenges);

                    if (*resp_vp).status_code != FCPResponseStatus::FCPNoError {
                        let msg = (*resp_vp).error_msg.as_str().unwrap();
                        panic!("generate_single_vanilla_proof failed: {:?}", msg);
                    }

                    vanilla_proofs.push((*resp_vp).value.clone());
                    fil_destroy_generate_single_vanilla_proof_response(resp_vp);
                }

                let single_partition_proof_resp = fil_generate_single_window_post_with_vanilla(
                    registered_proof_window_post,
                    randomness,
                    prover_id,
                    &vanilla_proofs.into(),
                    partition_index,
                );

                if (*single_partition_proof_resp).status_code != FCPResponseStatus::FCPNoError {
                    let msg = (*single_partition_proof_resp).error_msg.as_str().unwrap();
                    panic!("generate_single_window_post_with_vanilla failed: {:?}", msg);
                }

                partition_proofs.push((*single_partition_proof_resp).partition_proof.clone());
                fil_destroy_generate_single_window_post_with_vanilla_response(
                    single_partition_proof_resp,
                );
            }

            fil_destroy_get_num_partition_for_fallback_post_response(num_partitions_resp);

            let merged_proof_resp = fil_merge_window_post_partition_proofs(
                registered_proof_window_post,
                &partition_proofs.into(),
            );

            if (*merged_proof_resp).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*merged_proof_resp).error_msg.as_str().unwrap();
                panic!("merge_window_post_partition_proofs failed: {:?}", msg);
            }

            let resp_k3 = fil_verify_window_post(
                randomness,
                &public_replicas,
                &vec![(*merged_proof_resp).value.clone()].into(),
                prover_id,
            );

            if (*resp_k3).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_k3).error_msg.as_str().unwrap();
                panic!("verify_window_post failed: {:?}", msg);
            }

            if !*(*resp_k3) {
                panic!("verify_window_post rejected the provided proof as invalid");
            }

            fil_destroy_merge_window_post_partition_proofs_response(merged_proof_resp);

            ////////////////////
            // Cleanup responses
            ////////////////////

            fil_destroy_write_without_alignment_response(resp_a1);
            fil_destroy_write_with_alignment_response(resp_a2);
            fil_destroy_generate_data_commitment_response(resp_x);

            fil_destroy_seal_pre_commit_phase1_response(resp_b1);
            fil_destroy_seal_pre_commit_phase2_response(resp_b2);
            fil_destroy_seal_commit_phase1_response(resp_c1);
            fil_destroy_seal_commit_phase2_response(resp_c2);

            fil_destroy_verify_seal_response(resp_d);
            fil_destroy_unseal_range_response(resp_e);

            fil_destroy_generate_winning_post_sector_challenge(resp_f);
            fil_destroy_generate_fallback_sector_challenges_response(resp_sc);
            fil_destroy_generate_winning_post_response(resp_h);
            fil_destroy_generate_winning_post_response(resp_wpwv);
            fil_destroy_verify_winning_post_response(resp_i);
            fil_destroy_verify_winning_post_response(resp_di);

            fil_destroy_generate_fallback_sector_challenges_response(resp_sc2);
            fil_destroy_generate_window_post_response(resp_j);
            fil_destroy_generate_window_post_response(resp_wpwv2);
            fil_destroy_verify_window_post_response(resp_k);
            fil_destroy_verify_window_post_response(resp_k2);
            fil_destroy_verify_window_post_response(resp_k3);

            ensure!(
                remove_file(&staged_path.as_path().unwrap()).is_ok(),
                "failed to remove staged_path"
            );
            ensure!(
                remove_file(&sealed_path.as_path().unwrap()).is_ok(),
                "failed to remove sealed_path"
            );
            ensure!(
                remove_file(&unseal_path).is_ok(),
                "failed to remove unseal_path"
            );
        }

        Ok(())
    }

    #[test]
    fn test_faulty_sectors_v1() -> Result<()> {
        test_faulty_sectors_inner(fil_RegisteredSealProof::StackedDrg2KiBV1)
    }

    #[test]
    fn test_faulty_sectors_v1_1() -> Result<()> {
        test_faulty_sectors_inner(fil_RegisteredSealProof::StackedDrg2KiBV1_1)
    }

    fn test_faulty_sectors_inner(registered_proof_seal: fil_RegisteredSealProof) -> Result<()> {
        // miscellaneous setup and shared values
        let registered_proof_window_post = fil_RegisteredPoStProof::StackedDrgWindow2KiBV1;

        let cache_dir = tempfile::tempdir()?;
        let cache_dir_path: fil_Bytes = cache_dir.into_path().into();

        let prover_id = fil_32ByteArray { inner: [1u8; 32] };
        let randomness = fil_32ByteArray { inner: [7u8; 32] };
        let sector_id = 42;
        let ticket = fil_32ByteArray { inner: [6u8; 32] };

        // create a byte source (a user's piece)
        let mut rng = thread_rng();
        let buf_a: Vec<u8> = (0..2032).map(|_| rng.gen()).collect();

        let mut piece_file_a = tempfile::tempfile()?;
        piece_file_a.write_all(&buf_a[0..127])?;
        piece_file_a.seek(SeekFrom::Start(0))?;

        let mut piece_file_b = tempfile::tempfile()?;
        piece_file_b.write_all(&buf_a[0..1016])?;
        piece_file_b.seek(SeekFrom::Start(0))?;

        // create the staged sector (the byte destination)
        let (staged_file, staged_path) = tempfile::NamedTempFile::new()?.keep()?;
        let staged_path: fil_Bytes = staged_path.into();

        // create a temp file to be used as the byte destination
        let (_sealed_file, sealed_path) = tempfile::NamedTempFile::new()?.keep()?;
        let sealed_path: fil_Bytes = sealed_path.into();

        // transmute temp files to file descriptors
        let piece_file_a_fd = piece_file_a.into_raw_fd();
        let piece_file_b_fd = piece_file_b.into_raw_fd();
        let staged_sector_fd = staged_file.into_raw_fd();

        unsafe {
            let resp_a1 = fil_write_without_alignment(
                registered_proof_seal,
                piece_file_a_fd,
                127,
                staged_sector_fd,
            );

            if (*resp_a1).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_a1).error_msg.as_str().unwrap();
                panic!("write_without_alignment failed: {:?}", msg);
            }

            let existing_piece_sizes = vec![127];

            let resp_a2 = fil_write_with_alignment(
                registered_proof_seal,
                piece_file_b_fd,
                1016,
                staged_sector_fd,
                existing_piece_sizes.into(),
            );

            if (*resp_a2).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_a2).error_msg.as_str().unwrap();
                panic!("write_with_alignment failed: {:?}", msg);
            }

            let pieces = vec![
                fil_PublicPieceInfo {
                    num_bytes: 127,
                    comm_p: (*resp_a1).comm_p,
                },
                fil_PublicPieceInfo {
                    num_bytes: 1016,
                    comm_p: (*resp_a2).comm_p,
                },
            ]
            .into();

            let resp_x = fil_generate_data_commitment(registered_proof_seal, &pieces);

            if (*resp_x).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_x).error_msg.as_str().unwrap();
                panic!("generate_data_commitment failed: {:?}", msg);
            }

            let resp_b1 = fil_seal_pre_commit_phase1(
                registered_proof_seal,
                &cache_dir_path,
                &staged_path,
                &sealed_path,
                sector_id,
                prover_id,
                ticket,
                &pieces,
            );

            if (*resp_b1).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_b1).error_msg.as_str().unwrap();
                panic!("seal_pre_commit_phase1 failed: {:?}", msg);
            }

            let resp_b2 =
                fil_seal_pre_commit_phase2((*resp_b1).value.clone(), &cache_dir_path, &sealed_path);

            if (*resp_b2).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_b2).error_msg.as_str().unwrap();
                panic!("seal_pre_commit_phase2 failed: {:?}", msg);
            }

            // window post

            let faulty_sealed_file = tempfile::NamedTempFile::new()?;
            let faulty_sealed_path = faulty_sealed_file.path();

            let private_replicas = vec![fil_PrivateReplicaInfo {
                registered_proof: registered_proof_window_post,
                cache_dir_path,
                comm_r: (*resp_b2).comm_r,
                replica_path: faulty_sealed_path.into(),
                sector_id,
            }];

            let resp_j = fil_generate_window_post(randomness, &private_replicas.into(), prover_id);

            assert_eq!(
                (*resp_j).status_code,
                FCPResponseStatus::FCPUnclassifiedError,
                "generate_window_post should have failed"
            );

            let faulty_sectors: &[u64] = &(*resp_j).faulty_sectors;
            assert_eq!(faulty_sectors, &[42], "sector 42 should be faulty");

            fil_destroy_write_without_alignment_response(resp_a1);
            fil_destroy_write_with_alignment_response(resp_a2);

            fil_destroy_seal_pre_commit_phase1_response(resp_b1);
            fil_destroy_seal_pre_commit_phase2_response(resp_b2);

            fil_destroy_generate_window_post_response(resp_j);

            ensure!(
                remove_file(&staged_path.as_path().unwrap()).is_ok(),
                "failed to remove staged_path"
            );
            ensure!(
                remove_file(&sealed_path.as_path().unwrap()).is_ok(),
                "failed to remove sealed_path"
            );
        }

        Ok(())
    }

    #[test]
    #[ignore]
    fn test_sealing_aggregation_v1() -> Result<()> {
        test_sealing_aggregation(
            fil_RegisteredSealProof::StackedDrg2KiBV1,
            fil_RegisteredAggregationProof::SnarkPackV1,
        )
    }

    #[test]
    #[ignore]
    fn test_sealing_aggregation_v1_1() -> Result<()> {
        test_sealing_aggregation(
            fil_RegisteredSealProof::StackedDrg2KiBV1_1,
            fil_RegisteredAggregationProof::SnarkPackV1,
        )
    }

    fn test_sealing_aggregation(
        registered_proof_seal: fil_RegisteredSealProof,
        registered_aggregation: fil_RegisteredAggregationProof,
    ) -> Result<()> {
        let wrap = |x| fil_32ByteArray { inner: x };

        // miscellaneous setup and shared values
        let cache_dir = tempfile::tempdir()?;
        let cache_dir_path: fil_Bytes = cache_dir.into_path().into();

        let prover_id = fil_32ByteArray { inner: [1u8; 32] };
        let sector_id = 42;
        let seed = fil_32ByteArray { inner: [5u8; 32] };
        let ticket = fil_32ByteArray { inner: [6u8; 32] };

        // create a byte source (a user's piece)
        let mut rng = thread_rng();
        let buf_a: Vec<u8> = (0..2032).map(|_| rng.gen()).collect();

        let mut piece_file_a = tempfile::tempfile()?;
        piece_file_a.write_all(&buf_a[0..127])?;
        piece_file_a.seek(SeekFrom::Start(0))?;

        let mut piece_file_b = tempfile::tempfile()?;
        piece_file_b.write_all(&buf_a[0..1016])?;
        piece_file_b.seek(SeekFrom::Start(0))?;

        // create the staged sector (the byte destination)
        let (staged_file, staged_path) = tempfile::NamedTempFile::new()?.keep()?;
        let staged_path: fil_Bytes = staged_path.into();

        // create a temp file to be used as the byte destination
        let (_sealed_file, sealed_path) = tempfile::NamedTempFile::new()?.keep()?;
        let sealed_path: fil_Bytes = sealed_path.into();

        // transmute temp files to file descriptors
        let piece_file_a_fd = piece_file_a.into_raw_fd();
        let piece_file_b_fd = piece_file_b.into_raw_fd();
        let staged_sector_fd = staged_file.into_raw_fd();

        unsafe {
            let resp_a1 = fil_write_without_alignment(
                registered_proof_seal,
                piece_file_a_fd,
                127,
                staged_sector_fd,
            );

            if (*resp_a1).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_a1).error_msg.as_str().unwrap();
                panic!("write_without_alignment failed: {:?}", msg);
            }

            let existing_piece_sizes = vec![127];

            let resp_a2 = fil_write_with_alignment(
                registered_proof_seal,
                piece_file_b_fd,
                1016,
                staged_sector_fd,
                existing_piece_sizes.into(),
            );

            if (*resp_a2).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_a2).error_msg.as_str().unwrap();
                panic!("write_with_alignment failed: {:?}", msg);
            }

            let pieces = vec![
                fil_PublicPieceInfo {
                    num_bytes: 127,
                    comm_p: (*resp_a1).comm_p,
                },
                fil_PublicPieceInfo {
                    num_bytes: 1016,
                    comm_p: (*resp_a2).comm_p,
                },
            ]
            .into();

            let resp_x = fil_generate_data_commitment(registered_proof_seal, &pieces);

            if (*resp_x).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_x).error_msg.as_str().unwrap();
                panic!("generate_data_commitment failed: {:?}", msg);
            }

            let resp_b1 = fil_seal_pre_commit_phase1(
                registered_proof_seal,
                &cache_dir_path,
                &staged_path,
                &sealed_path,
                sector_id,
                prover_id,
                ticket,
                &pieces,
            );

            if (*resp_b1).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_b1).error_msg.as_str().unwrap();
                panic!("seal_pre_commit_phase1 failed: {:?}", msg);
            }

            let resp_b2 =
                fil_seal_pre_commit_phase2((*resp_b1).value.clone(), &cache_dir_path, &sealed_path);

            if (*resp_b2).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_b2).error_msg.as_str().unwrap();
                panic!("seal_pre_commit_phase2 failed: {:?}", msg);
            }

            let pre_computed_comm_d: &[u8; 32] = &(*resp_x);
            let pre_commit_comm_d: &[u8; 32] = &(*resp_b2).comm_d;

            assert_eq!(
                format!("{:x?}", &pre_computed_comm_d),
                format!("{:x?}", &pre_commit_comm_d),
                "pre-computed CommD and pre-commit CommD don't match"
            );

            let resp_c1 = fil_seal_commit_phase1(
                registered_proof_seal,
                wrap((*resp_b2).comm_r),
                wrap((*resp_b2).comm_d),
                &cache_dir_path,
                &sealed_path,
                sector_id,
                prover_id,
                ticket,
                seed,
                &pieces,
            );

            if (*resp_c1).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_c1).error_msg.as_str().unwrap();
                panic!("seal_commit_phase1 failed: {:?}", msg);
            }

            let resp_c2 = fil_seal_commit_phase2(&(*resp_c1), sector_id, prover_id);

            if (*resp_c2).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_c2).error_msg.as_str().unwrap();
                panic!("seal_commit_phase2 failed: {:?}", msg);
            }

            let resp_d = fil_verify_seal(
                registered_proof_seal,
                wrap((*resp_b2).comm_r),
                wrap((*resp_b2).comm_d),
                prover_id,
                ticket,
                seed,
                sector_id,
                &(*resp_c2).proof,
            );

            if (*resp_d).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_d).error_msg.as_str().unwrap();
                panic!("seal_commit failed: {:?}", msg);
            }

            assert!(*(*resp_d), "proof was not valid");

            let resp_c22 = fil_seal_commit_phase2(&(*resp_c1), sector_id, prover_id);

            if (*resp_c22).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_c22).error_msg.as_str().unwrap();
                panic!("seal_commit_phase2 failed: {:?}", msg);
            }

            let resp_d2 = fil_verify_seal(
                registered_proof_seal,
                wrap((*resp_b2).comm_r),
                wrap((*resp_b2).comm_d),
                prover_id,
                ticket,
                seed,
                sector_id,
                &(*resp_c22).proof,
            );

            if (*resp_d2).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_d2).error_msg.as_str().unwrap();
                panic!("seal_commit failed: {:?}", msg);
            }

            assert!(*(*resp_d2), "proof was not valid");

            let seal_commit_responses: Vec<fil_SealCommitPhase2> =
                vec![(*resp_c2).value.clone(), (*resp_c22).value.clone()];

            let comm_rs = vec![
                fil_32ByteArray {
                    inner: (*resp_b2).comm_r,
                },
                fil_32ByteArray {
                    inner: (*resp_b2).comm_r,
                },
            ];
            let seeds = vec![seed, seed];
            let resp_aggregate_proof = fil_aggregate_seal_proofs(
                registered_proof_seal,
                registered_aggregation,
                comm_rs.into(),
                seeds.into(),
                seal_commit_responses.into(),
            );

            if (*resp_aggregate_proof).status_code != FCPResponseStatus::FCPNoError {
                panic!(
                    "aggregate_seal_proofs failed: {}",
                    (*resp_aggregate_proof).error_msg.as_str().unwrap()
                );
            }

            let inputs: Vec<fil_AggregationInputs> = vec![
                fil_AggregationInputs {
                    comm_r: wrap((*resp_b2).comm_r),
                    comm_d: wrap((*resp_b2).comm_d),
                    sector_id,
                    ticket,
                    seed,
                },
                fil_AggregationInputs {
                    comm_r: wrap((*resp_b2).comm_r),
                    comm_d: wrap((*resp_b2).comm_d),
                    sector_id,
                    ticket,
                    seed,
                },
            ];

            let resp_ad = fil_verify_aggregate_seal_proof(
                registered_proof_seal,
                registered_aggregation,
                prover_id,
                &(*resp_aggregate_proof),
                &inputs.into(),
            );

            if (*resp_ad).status_code != FCPResponseStatus::FCPNoError {
                let msg = (*resp_ad).error_msg.as_str().unwrap();
                panic!("verify_aggregate_seal_proof failed: {:?}", msg);
            }

            assert!(*(*resp_ad), "aggregated proof was not valid");

            fil_destroy_write_without_alignment_response(resp_a1);
            fil_destroy_write_with_alignment_response(resp_a2);
            fil_destroy_generate_data_commitment_response(resp_x);

            fil_destroy_seal_pre_commit_phase1_response(resp_b1);
            fil_destroy_seal_pre_commit_phase2_response(resp_b2);
            fil_destroy_seal_commit_phase1_response(resp_c1);

            fil_destroy_seal_commit_phase2_response(resp_c2);
            fil_destroy_seal_commit_phase2_response(resp_c22);

            fil_destroy_verify_seal_response(resp_d);
            fil_destroy_verify_seal_response(resp_d2);

            fil_destroy_verify_aggregate_seal_response(resp_ad);

            //fil_destroy_aggregation_inputs_response(resp_c2_inputs);
            //fil_destroy_aggregation_inputs_response(resp_c22_inputs);

            fil_destroy_aggregate_proof(resp_aggregate_proof);

            ensure!(
                remove_file(&staged_path.as_path().unwrap()).is_ok(),
                "failed to remove staged_path"
            );
            ensure!(
                remove_file(&sealed_path.as_path().unwrap()).is_ok(),
                "failed to remove sealed_path"
            );
        }

        Ok(())
    }
}
