use std::fs;

use anyhow::anyhow;
use blstrs::Scalar as Fr;
use filecoin_proofs_api::seal;
use filecoin_proofs_api::{
    self as api, update, PieceInfo, SectorId, StorageProofsError, UnpaddedByteIndex,
    UnpaddedBytesAmount,
};
use log::error;
use rayon::prelude::*;
use safer_ffi::prelude::*;

use super::helpers::{to_private_replica_info_map, to_public_replica_info_map};
use super::types::*;
use crate::util::types::{
    catch_panic_response, catch_panic_response_raw, Array, Bytes, FCPResponseStatus,
};

// A byte serialized representation of a vanilla proof.
pub type ApiVanillaProof = Vec<u8>;

/// TODO: document
#[ffi_export]
unsafe fn write_with_alignment(
    registered_proof: RegisteredSealProof,
    src_fd: libc::c_int,
    src_size: u64,
    dst_fd: libc::c_int,
    existing_piece_sizes: &Array<u64>,
) -> repr_c::Box<WriteWithAlignmentResponse> {
    catch_panic_response("write_with_alignment", || {
        let piece_sizes: Vec<UnpaddedBytesAmount> = existing_piece_sizes
            .iter()
            .copied()
            .map(UnpaddedBytesAmount)
            .collect();

        let n = UnpaddedBytesAmount(src_size);

        let (info, written) = seal::add_piece(
            registered_proof.into(),
            FileDescriptorRef::new(src_fd),
            FileDescriptorRef::new(dst_fd),
            n,
            &piece_sizes,
        )?;

        Ok(WriteWithAlignment {
            comm_p: info.commitment,
            left_alignment_unpadded: (written - n).into(),
            total_write_unpadded: written.into(),
        })
    })
}

/// TODO: document
#[ffi_export]
unsafe fn write_without_alignment(
    registered_proof: RegisteredSealProof,
    src_fd: libc::c_int,
    src_size: u64,
    dst_fd: libc::c_int,
) -> repr_c::Box<WriteWithoutAlignmentResponse> {
    catch_panic_response("write_without_alignment", || {
        let (info, written) = seal::write_and_preprocess(
            registered_proof.into(),
            FileDescriptorRef::new(src_fd),
            FileDescriptorRef::new(dst_fd),
            UnpaddedBytesAmount(src_size),
        )?;

        Ok(WriteWithoutAlignment {
            comm_p: info.commitment,
            total_write_unpadded: written.into(),
        })
    })
}

#[ffi_export]
fn fauxrep(
    registered_proof: RegisteredSealProof,
    cache_dir_path: &Bytes,
    sealed_sector_path: &Bytes,
) -> repr_c::Box<FauxRepResponse> {
    catch_panic_response("fauxrep", || {
        let res = seal::fauxrep(
            registered_proof.into(),
            cache_dir_path.as_path()?,
            sealed_sector_path.as_path()?,
        )?;
        Ok(res.into())
    })
}

#[ffi_export]
fn fauxrep2(
    registered_proof: RegisteredSealProof,
    cache_dir_path: &Bytes,
    existing_p_aux_path: &Bytes,
) -> repr_c::Box<FauxRepResponse> {
    catch_panic_response("fauxrep2", || {
        let result = seal::fauxrep2(
            registered_proof.into(),
            cache_dir_path.as_path()?,
            existing_p_aux_path.as_path()?,
        )?;

        Ok(result.into())
    })
}

/// TODO: document
#[ffi_export]
fn seal_pre_commit_phase1(
    registered_proof: RegisteredSealProof,
    cache_dir_path: &Bytes,
    staged_sector_path: &Bytes,
    sealed_sector_path: &Bytes,
    sector_id: u64,
    prover_id: ByteArray32,
    ticket: ByteArray32,
    pieces: &Array<PublicPieceInfo>,
) -> repr_c::Box<SealPreCommitPhase1Response> {
    catch_panic_response("seal_pre_commit_phase1", || {
        let public_pieces: Vec<PieceInfo> = pieces.iter().map(Into::into).collect();

        let result = seal::seal_pre_commit_phase1(
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
#[ffi_export]
fn seal_pre_commit_phase2(
    seal_pre_commit_phase1_output: &Bytes,
    cache_dir_path: &Bytes,
    sealed_sector_path: &Bytes,
) -> repr_c::Box<SealPreCommitPhase2Response> {
    catch_panic_response("seal_pre_commit_phase2", || {
        let phase_1_output = serde_json::from_slice(seal_pre_commit_phase1_output)?;

        let output = seal::seal_pre_commit_phase2(
            phase_1_output,
            cache_dir_path.as_path()?,
            sealed_sector_path.as_path()?,
        )?;

        Ok(SealPreCommitPhase2 {
            comm_r: output.comm_r,
            comm_d: output.comm_d,
            registered_proof: output.registered_proof.into(),
        })
    })
}

/// TODO: document
#[ffi_export]
fn seal_commit_phase1(
    registered_proof: RegisteredSealProof,
    comm_r: ByteArray32,
    comm_d: ByteArray32,
    cache_dir_path: &Bytes,
    replica_path: &Bytes,
    sector_id: u64,
    prover_id: ByteArray32,
    ticket: ByteArray32,
    seed: ByteArray32,
    pieces: &Array<PublicPieceInfo>,
) -> repr_c::Box<SealCommitPhase1Response> {
    catch_panic_response("seal_commit_phase1", || {
        let spcp2o = seal::SealPreCommitPhase2Output {
            registered_proof: registered_proof.into(),
            comm_r: comm_r.inner,
            comm_d: comm_d.inner,
        };

        let public_pieces: Vec<PieceInfo> = pieces.iter().map(Into::into).collect();

        let output = seal::seal_commit_phase1(
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

#[ffi_export]
fn seal_commit_phase2(
    seal_commit_phase1_output: &Bytes,
    sector_id: u64,
    prover_id: ByteArray32,
) -> repr_c::Box<SealCommitPhase2Response> {
    catch_panic_response("seal_commit_phase2", || {
        let scp1o = serde_json::from_slice(seal_commit_phase1_output)?;
        let result = seal::seal_commit_phase2(scp1o, prover_id.inner, SectorId::from(sector_id))?;

        Ok(SealCommitPhase2 {
            proof: result.proof.into(),
        })
    })
}

#[ffi_export]
fn aggregate_seal_proofs(
    registered_proof: RegisteredSealProof,
    registered_aggregation: RegisteredAggregationProof,
    comm_rs: Array<ByteArray32>,
    seeds: Array<ByteArray32>,
    seal_commit_responses: &Array<SealCommitPhase2>,
) -> repr_c::Box<AggregateProof> {
    catch_panic_response("aggregate_seal_proofs", || {
        let outputs: Vec<seal::SealCommitPhase2Output> =
            seal_commit_responses.iter().map(Into::into).collect();

        let comm_rs: Vec<[u8; 32]> = comm_rs.into_iter().map(|x| x.inner).collect();
        let seeds: Vec<[u8; 32]> = seeds.into_iter().map(|x| x.inner).collect();

        let result = seal::aggregate_seal_commit_proofs(
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
    registered_proof: RegisteredSealProof,
    prover_id: ByteArray32,
    input: &AggregationInputs,
) -> anyhow::Result<Vec<Vec<Fr>>> {
    seal::get_seal_inputs(
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
#[ffi_export]
fn verify_aggregate_seal_proof(
    registered_proof: RegisteredSealProof,
    registered_aggregation: RegisteredAggregationProof,
    prover_id: ByteArray32,
    proof: &Bytes,
    commit_inputs: &Array<AggregationInputs>,
) -> repr_c::Box<VerifyAggregateSealProofResponse> {
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

        let result = seal::verify_aggregate_seal_commit_proofs(
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
#[ffi_export]
unsafe fn unseal_range(
    registered_proof: RegisteredSealProof,
    cache_dir_path: &Bytes,
    sealed_sector_fd_raw: libc::c_int,
    unseal_output_fd_raw: libc::c_int,
    sector_id: u64,
    prover_id: ByteArray32,
    ticket: ByteArray32,
    comm_d: ByteArray32,
    unpadded_byte_index: u64,
    unpadded_bytes_amount: u64,
) -> repr_c::Box<UnsealRangeResponse> {
    catch_panic_response("unseal_range", || {
        use filepath::FilePath;
        use std::os::unix::io::{FromRawFd, IntoRawFd};

        let sealed_sector = fs::File::from_raw_fd(sealed_sector_fd_raw);
        let mut unseal_output = fs::File::from_raw_fd(unseal_output_fd_raw);

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
#[ffi_export]
fn verify_seal(
    registered_proof: RegisteredSealProof,
    comm_r: ByteArray32,
    comm_d: ByteArray32,
    prover_id: ByteArray32,
    ticket: ByteArray32,
    seed: ByteArray32,
    sector_id: u64,
    proof: &Bytes,
) -> repr_c::Box<super::types::VerifySealResponse> {
    catch_panic_response("verify_seal", || {
        let proof_bytes: Vec<u8> = proof.to_vec();

        let result = seal::verify_seal(
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
#[ffi_export]
fn generate_winning_post_sector_challenge(
    registered_proof: RegisteredPoStProof,
    randomness: ByteArray32,
    sector_set_len: u64,
    prover_id: ByteArray32,
) -> repr_c::Box<GenerateWinningPoStSectorChallenge> {
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
#[ffi_export]
fn generate_fallback_sector_challenges(
    registered_proof: RegisteredPoStProof,
    randomness: ByteArray32,
    sector_ids: &Array<u64>,
    prover_id: ByteArray32,
) -> repr_c::Box<GenerateFallbackSectorChallengesResponse> {
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
            .map(|(id, _)| u64::from(id))
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
        Ok(GenerateFallbackSectorChallenges {
            ids: sector_ids.into(),
            challenges: challenges.into(),
            challenges_stride,
        })
    })
}

/// TODO: document
#[ffi_export]
fn generate_single_vanilla_proof(
    replica: PrivateReplicaInfo,
    challenges: &Array<u64>,
) -> repr_c::Box<GenerateSingleVanillaProofResponse> {
    catch_panic_response("generate_single_vanilla_proof", || {
        let sector_id = SectorId::from(replica.sector_id);
        let cache_dir_path = replica.cache_dir_path.as_path().expect("invalid cache dir");
        let replica_path = replica
            .replica_path
            .as_path()
            .expect("invalid replica path");

        let replica_v1 = api::PrivateReplicaInfo::new(
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
#[ffi_export]
fn generate_winning_post_with_vanilla(
    registered_proof: RegisteredPoStProof,
    randomness: ByteArray32,
    prover_id: ByteArray32,
    vanilla_proofs: &Array<VanillaProof>,
) -> repr_c::Box<GenerateWinningPoStResponse> {
    catch_panic_response("generate_winning_post_with_vanilla", || {
        let vanilla_proofs: Vec<_> = vanilla_proofs
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
            .map(|(t, proof)| PoStProof {
                registered_proof: (t).into(),
                proof: proof.into(),
            })
            .collect::<Vec<_>>();

        Ok(result.into())
    })
}

/// TODO: document
#[ffi_export]
fn generate_winning_post(
    randomness: ByteArray32,
    replicas: &Array<PrivateReplicaInfo>,
    prover_id: ByteArray32,
) -> repr_c::Box<GenerateWinningPoStResponse> {
    catch_panic_response("generate_winning_post", || {
        let replicas = to_private_replica_info_map(replicas)?;
        let result = filecoin_proofs_api::post::generate_winning_post(
            &randomness.inner,
            &replicas,
            prover_id.inner,
        )?;

        let result = result
            .into_iter()
            .map(|(t, proof)| PoStProof {
                registered_proof: (t).into(),
                proof: proof.into(),
            })
            .collect::<Vec<_>>();

        Ok(result.into())
    })
}

/// Verifies that a proof-of-spacetime is valid.
#[ffi_export]
fn verify_winning_post(
    randomness: ByteArray32,
    replicas: &Array<PublicReplicaInfo>,
    proofs: &Array<PoStProof>,
    prover_id: ByteArray32,
) -> repr_c::Box<VerifyWinningPoStResponse> {
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
#[ffi_export]
fn generate_window_post_with_vanilla(
    registered_proof: RegisteredPoStProof,
    randomness: ByteArray32,
    prover_id: ByteArray32,
    vanilla_proofs: &Array<VanillaProof>,
) -> repr_c::Box<GenerateWindowPoStResponse> {
    catch_panic_response_raw("generate_window_post_with_vanilla", || {
        let vanilla_proofs: Vec<_> = vanilla_proofs
            .iter()
            .map(|vanilla_proof| vanilla_proof.to_vec())
            .collect();

        let result = filecoin_proofs_api::post::generate_window_post_with_vanilla(
            registered_proof.into(),
            &randomness.inner,
            prover_id.inner,
            &vanilla_proofs,
        );

        let mut response = GenerateWindowPoStResponse::default();

        match result {
            Ok(output) => {
                let mapped: Vec<PoStProof> = output
                    .into_iter()
                    .map(|(t, proof)| PoStProof {
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
#[ffi_export]
fn generate_window_post(
    randomness: ByteArray32,
    replicas: &Array<PrivateReplicaInfo>,
    prover_id: ByteArray32,
) -> repr_c::Box<GenerateWindowPoStResponse> {
    catch_panic_response_raw("generate_window_post", || {
        let result = to_private_replica_info_map(replicas).and_then(|replicas| {
            filecoin_proofs_api::post::generate_window_post(
                &randomness.inner,
                &replicas,
                prover_id.inner,
            )
        });

        let mut response = GenerateWindowPoStResponse::default();
        match result {
            Ok(output) => {
                let mapped: Vec<PoStProof> = output
                    .into_iter()
                    .map(|(t, proof)| PoStProof {
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
#[ffi_export]
fn verify_window_post(
    randomness: ByteArray32,
    replicas: &Array<PublicReplicaInfo>,
    proofs: &Array<PoStProof>,
    prover_id: ByteArray32,
) -> repr_c::Box<VerifyWindowPoStResponse> {
    catch_panic_response("verify_window_post", || {
        let replicas = to_public_replica_info_map(replicas);
        let proofs: Vec<(api::RegisteredPoStProof, &[u8])> = proofs
            .iter()
            .map(|x| {
                (
                    api::RegisteredPoStProof::from(x.registered_proof),
                    &x.proof[..],
                )
            })
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
#[ffi_export]
fn merge_window_post_partition_proofs(
    registered_proof: RegisteredPoStProof,
    partition_proofs: &Array<PartitionSnarkProof>,
) -> repr_c::Box<MergeWindowPoStPartitionProofsResponse> {
    catch_panic_response("merge_window_post_partition_proofs", || {
        let partition_proofs = partition_proofs
            .iter()
            .map(|pp| api::PartitionSnarkProof(pp.proof.to_vec()))
            .collect::<Vec<_>>();

        let proof = filecoin_proofs_api::post::merge_window_post_partition_proofs(
            registered_proof.into(),
            partition_proofs,
        )?;

        Ok(PoStProof {
            registered_proof,
            proof: proof.into(),
        })
    })
}

/// TODO: document
#[ffi_export]
fn get_num_partition_for_fallback_post(
    registered_proof: RegisteredPoStProof,
    num_sectors: libc::size_t,
) -> repr_c::Box<GetNumPartitionForFallbackPoStResponse> {
    catch_panic_response("get_num_partition_for_fallback_post", || {
        let result = filecoin_proofs_api::post::get_num_partition_for_fallback_post(
            registered_proof.into(),
            num_sectors,
        )?;
        Ok(result)
    })
}

/// TODO: document
#[ffi_export]
fn generate_single_window_post_with_vanilla(
    registered_proof: RegisteredPoStProof,
    randomness: ByteArray32,
    prover_id: ByteArray32,
    vanilla_proofs: &Array<VanillaProof>,
    partition_index: libc::size_t,
) -> repr_c::Box<GenerateSingleWindowPoStWithVanillaResponse> {
    catch_panic_response_raw("generate_single_window_post_with_vanilla", || {
        let vanilla_proofs: Vec<_> = vanilla_proofs
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

        let mut response = GenerateSingleWindowPoStWithVanillaResponse::default();

        match result {
            Ok(output) => {
                let partition_proof = PartitionSnarkProof {
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
#[ffi_export]
fn empty_sector_update_encode_into(
    registered_proof: RegisteredUpdateProof,
    new_replica_path: &Bytes,
    new_cache_dir_path: &Bytes,
    sector_key_path: &Bytes,
    sector_key_cache_dir_path: &Bytes,
    staged_data_path: &Bytes,
    pieces: &Array<PublicPieceInfo>,
) -> repr_c::Box<EmptySectorUpdateEncodeIntoResponse> {
    catch_panic_response("empty_sector_update_encode_into", || {
        let public_pieces = pieces.iter().map(Into::into).collect::<Vec<_>>();

        let output = update::empty_sector_update_encode_into(
            registered_proof.into(),
            new_replica_path.as_path()?,
            new_cache_dir_path.as_path()?,
            sector_key_path.as_path()?,
            sector_key_cache_dir_path.as_path()?,
            staged_data_path.as_path()?,
            &public_pieces,
        )?;

        Ok(EmptySectorUpdateEncodeInto {
            comm_r_new: output.comm_r_new,
            comm_r_last_new: output.comm_r_last_new,
            comm_d_new: output.comm_d_new,
        })
    })
}

/// TODO: document
#[ffi_export]
fn empty_sector_update_decode_from(
    registered_proof: RegisteredUpdateProof,
    out_data_path: &Bytes,
    replica_path: &Bytes,
    sector_key_path: &Bytes,
    sector_key_cache_dir_path: &Bytes,
    comm_d_new: ByteArray32,
) -> repr_c::Box<EmptySectorUpdateDecodeFromResponse> {
    catch_panic_response("empty_sector_update_decode_from", || {
        update::empty_sector_update_decode_from(
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
#[ffi_export]
fn empty_sector_update_remove_encoded_data(
    registered_proof: RegisteredUpdateProof,
    sector_key_path: &Bytes,
    sector_key_cache_dir_path: &Bytes,
    replica_path: &Bytes,
    replica_cache_path: &Bytes,
    data_path: &Bytes,
    comm_d_new: ByteArray32,
) -> repr_c::Box<EmptySectorUpdateRemoveEncodedDataResponse> {
    catch_panic_response("empty_sector_update_remove_encoded_data", || {
        update::empty_sector_update_remove_encoded_data(
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
#[ffi_export]
fn generate_empty_sector_update_partition_proofs(
    registered_proof: RegisteredUpdateProof,
    comm_r_old: ByteArray32,
    comm_r_new: ByteArray32,
    comm_d_new: ByteArray32,
    sector_key_path: &Bytes,
    sector_key_cache_dir_path: &Bytes,
    replica_path: &Bytes,
    replica_cache_path: &Bytes,
) -> repr_c::Box<PartitionProofResponse> {
    catch_panic_response("generate_empty_sector_update_partition_proofs", || {
        let output = update::generate_partition_proofs(
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
#[ffi_export]
fn verify_empty_sector_update_partition_proofs(
    registered_proof: RegisteredUpdateProof,
    proofs: &Array<ApiPartitionProof>,
    comm_r_old: ByteArray32,
    comm_r_new: ByteArray32,
    comm_d_new: ByteArray32,
) -> repr_c::Box<VerifyPartitionProofResponse> {
    catch_panic_response("verify_empty_sector_update_partition_proofs", || {
        let proofs: Vec<api::PartitionProofBytes> = proofs
            .iter()
            .map(|pp| api::PartitionProofBytes(pp.to_vec()))
            .collect();

        let result = update::verify_partition_proofs(
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
#[ffi_export]
fn generate_empty_sector_update_proof_with_vanilla(
    registered_proof: RegisteredUpdateProof,
    vanilla_proofs: &Array<ApiPartitionProof>,
    comm_r_old: ByteArray32,
    comm_r_new: ByteArray32,
    comm_d_new: ByteArray32,
) -> repr_c::Box<EmptySectorUpdateProofResponse> {
    catch_panic_response("generate_empty_sector_update_proof_with_vanilla", || {
        let partition_proofs: Vec<api::PartitionProofBytes> = vanilla_proofs
            .iter()
            .map(|partition_proof| api::PartitionProofBytes(partition_proof.to_vec()))
            .collect();

        let result = update::generate_empty_sector_update_proof_with_vanilla(
            registered_proof.into(),
            partition_proofs,
            comm_r_old.inner,
            comm_r_new.inner,
            comm_d_new.inner,
        )?;

        Ok(result.0.into())
    })
}

/// TODO: document
#[ffi_export]
fn generate_empty_sector_update_proof(
    registered_proof: RegisteredUpdateProof,
    comm_r_old: ByteArray32,
    comm_r_new: ByteArray32,
    comm_d_new: ByteArray32,
    sector_key_path: &Bytes,
    sector_key_cache_dir_path: &Bytes,
    replica_path: &Bytes,
    replica_cache_path: &Bytes,
) -> repr_c::Box<EmptySectorUpdateProofResponse> {
    catch_panic_response("generate_empty_sector_update_proof", || {
        let result = update::generate_empty_sector_update_proof(
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
#[ffi_export]
fn verify_empty_sector_update_proof(
    registered_proof: RegisteredUpdateProof,
    proof: &Bytes,
    comm_r_old: ByteArray32,
    comm_r_new: ByteArray32,
    comm_d_new: ByteArray32,
) -> repr_c::Box<VerifyEmptySectorUpdateProofResponse> {
    catch_panic_response("verify_empty_sector_update_proof", || {
        let proof_bytes: Vec<u8> = proof.to_vec();

        let result = update::verify_empty_sector_update_proof(
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
#[ffi_export]
unsafe fn generate_piece_commitment(
    registered_proof: RegisteredSealProof,
    piece_fd_raw: libc::c_int,
    unpadded_piece_size: u64,
) -> repr_c::Box<GeneratePieceCommitmentResponse> {
    catch_panic_response("generate_piece_commitment", || {
        use std::os::unix::io::{FromRawFd, IntoRawFd};

        let mut piece_file = fs::File::from_raw_fd(piece_fd_raw);

        let unpadded_piece_size = UnpaddedBytesAmount(unpadded_piece_size);
        let result = seal::generate_piece_commitment(
            registered_proof.into(),
            &mut piece_file,
            unpadded_piece_size,
        );

        // avoid dropping the File which closes it
        let _ = piece_file.into_raw_fd();

        let result = result.map(|meta| GeneratePieceCommitment {
            comm_p: meta.commitment,
            num_bytes_aligned: meta.size.into(),
        })?;

        Ok(result)
    })
}

/// Returns the merkle root for a sector containing the provided pieces.
#[ffi_export]
fn generate_data_commitment(
    registered_proof: RegisteredSealProof,
    pieces: &Array<PublicPieceInfo>,
) -> repr_c::Box<GenerateDataCommitmentResponse> {
    catch_panic_response("generate_data_commitment", || {
        let public_pieces: Vec<PieceInfo> = pieces.iter().map(Into::into).collect();
        let result = seal::compute_comm_d(registered_proof.into(), &public_pieces)?;

        Ok(result.into())
    })
}

#[ffi_export]
fn clear_cache(sector_size: u64, cache_dir_path: &Bytes) -> repr_c::Box<ClearCacheResponse> {
    catch_panic_response("clear_cache", || {
        let result = seal::clear_cache(sector_size, &cache_dir_path.as_path()?)?;

        Ok(result)
    })
}

#[ffi_export]
fn destroy_write_with_alignment_response(ptr: repr_c::Box<WriteWithAlignmentResponse>) {
    drop(ptr);
}

#[ffi_export]
fn destroy_write_without_alignment_response(ptr: repr_c::Box<WriteWithoutAlignmentResponse>) {
    drop(ptr);
}

#[ffi_export]
fn destroy_fauxrep_response(ptr: repr_c::Box<FauxRepResponse>) {
    drop(ptr);
}

#[ffi_export]
fn destroy_seal_pre_commit_phase1_response(ptr: repr_c::Box<SealPreCommitPhase1Response>) {
    drop(ptr);
}

#[ffi_export]
fn destroy_seal_pre_commit_phase2_response(ptr: repr_c::Box<SealPreCommitPhase2Response>) {
    drop(ptr);
}

#[ffi_export]
fn destroy_seal_commit_phase1_response(ptr: repr_c::Box<SealCommitPhase1Response>) {
    drop(ptr);
}

#[ffi_export]
fn destroy_seal_commit_phase2_response(ptr: repr_c::Box<SealCommitPhase2Response>) {
    drop(ptr);
}

#[ffi_export]
fn destroy_unseal_range_response(ptr: repr_c::Box<UnsealRangeResponse>) {
    drop(ptr);
}

#[ffi_export]
fn destroy_generate_piece_commitment_response(ptr: repr_c::Box<GeneratePieceCommitmentResponse>) {
    drop(ptr);
}

#[ffi_export]
fn destroy_generate_data_commitment_response(ptr: repr_c::Box<GenerateDataCommitmentResponse>) {
    drop(ptr);
}

#[ffi_export]
fn destroy_string_response(ptr: repr_c::Box<StringResponse>) {
    drop(ptr);
}

/// Returns the number of user bytes that will fit into a staged sector.
#[ffi_export]
fn get_max_user_bytes_per_staged_sector(registered_proof: RegisteredSealProof) -> u64 {
    u64::from(UnpaddedBytesAmount::from(
        api::RegisteredSealProof::from(registered_proof).sector_size(),
    ))
}

/// Returns the CID of the Groth parameter file for sealing.
#[ffi_export]
fn get_seal_params_cid(registered_proof: RegisteredSealProof) -> repr_c::Box<StringResponse> {
    registered_seal_proof_accessor(registered_proof, api::RegisteredSealProof::params_cid)
}

/// Returns the CID of the verifying key-file for verifying a seal proof.
#[ffi_export]
fn get_seal_verifying_key_cid(
    registered_proof: RegisteredSealProof,
) -> repr_c::Box<StringResponse> {
    registered_seal_proof_accessor(
        registered_proof,
        api::RegisteredSealProof::verifying_key_cid,
    )
}

/// Returns the path from which the proofs library expects to find the Groth
/// parameter file used when sealing.
#[ffi_export]
fn get_seal_params_path(registered_proof: RegisteredSealProof) -> repr_c::Box<StringResponse> {
    registered_seal_proof_accessor(registered_proof, |p| {
        p.cache_params_path()
            .map(|pb| String::from(pb.to_string_lossy()))
    })
}

/// Returns the path from which the proofs library expects to find the verifying
/// key-file used when verifying a seal proof.
#[ffi_export]
fn get_seal_verifying_key_path(
    registered_proof: RegisteredSealProof,
) -> repr_c::Box<StringResponse> {
    registered_seal_proof_accessor(registered_proof, |p| {
        p.cache_verifying_key_path()
            .map(|pb| String::from(pb.to_string_lossy()))
    })
}

/// Returns the identity of the circuit for the provided seal proof.
#[ffi_export]
fn get_seal_circuit_identifier(
    registered_proof: RegisteredSealProof,
) -> repr_c::Box<StringResponse> {
    registered_seal_proof_accessor(
        registered_proof,
        api::RegisteredSealProof::circuit_identifier,
    )
}

/// Returns the version of the provided seal proof type.
#[ffi_export]
fn get_seal_version(registered_proof: RegisteredSealProof) -> repr_c::Box<StringResponse> {
    registered_seal_proof_accessor(registered_proof, |p| Ok(format!("{:?}", p)))
}

/// Returns the CID of the Groth parameter file for generating a PoSt.
#[ffi_export]
fn get_post_params_cid(registered_proof: RegisteredPoStProof) -> repr_c::Box<StringResponse> {
    registered_post_proof_accessor(registered_proof, api::RegisteredPoStProof::params_cid)
}

/// Returns the CID of the verifying key-file for verifying a PoSt proof.
#[ffi_export]
fn get_post_verifying_key_cid(
    registered_proof: RegisteredPoStProof,
) -> repr_c::Box<StringResponse> {
    registered_post_proof_accessor(
        registered_proof,
        api::RegisteredPoStProof::verifying_key_cid,
    )
}

/// Returns the path from which the proofs library expects to find the Groth
/// parameter file used when generating a PoSt.
#[ffi_export]
fn get_post_params_path(registered_proof: RegisteredPoStProof) -> repr_c::Box<StringResponse> {
    registered_post_proof_accessor(registered_proof, |p| {
        p.cache_params_path()
            .map(|pb| String::from(pb.to_string_lossy()))
    })
}

/// Returns the path from which the proofs library expects to find the verifying
/// key-file used when verifying a PoSt proof.
#[ffi_export]
fn get_post_verifying_key_path(
    registered_proof: RegisteredPoStProof,
) -> repr_c::Box<StringResponse> {
    registered_post_proof_accessor(registered_proof, |p| {
        p.cache_verifying_key_path()
            .map(|pb| String::from(pb.to_string_lossy()))
    })
}

/// Returns the identity of the circuit for the provided PoSt proof type.
#[ffi_export]
fn get_post_circuit_identifier(
    registered_proof: RegisteredPoStProof,
) -> repr_c::Box<StringResponse> {
    registered_post_proof_accessor(
        registered_proof,
        api::RegisteredPoStProof::circuit_identifier,
    )
}

/// Returns the version of the provided seal proof.
#[ffi_export]
fn get_post_version(registered_proof: RegisteredPoStProof) -> repr_c::Box<StringResponse> {
    registered_post_proof_accessor(registered_proof, |p| Ok(format!("{:?}", p)))
}

fn registered_seal_proof_accessor(
    registered_proof: RegisteredSealProof,
    op: fn(api::RegisteredSealProof) -> anyhow::Result<String>,
) -> repr_c::Box<StringResponse> {
    let rsp: api::RegisteredSealProof = registered_proof.into();

    repr_c::Box::new(StringResponse::from(op(rsp).map(Into::into)))
}

fn registered_post_proof_accessor(
    registered_proof: RegisteredPoStProof,
    op: fn(api::RegisteredPoStProof) -> anyhow::Result<String>,
) -> repr_c::Box<StringResponse> {
    let rsp: api::RegisteredPoStProof = registered_proof.into();

    repr_c::Box::new(StringResponse::from(op(rsp).map(Into::into)))
}

/// Deallocates a VerifySealResponse.
#[ffi_export]
fn destroy_verify_seal_response(ptr: repr_c::Box<VerifySealResponse>) {
    drop(ptr);
}

/// Deallocates a VerifyAggregateSealProofResponse.
#[ffi_export]
fn destroy_verify_aggregate_seal_response(ptr: repr_c::Box<VerifyAggregateSealProofResponse>) {
    drop(ptr);
}

#[ffi_export]
fn destroy_finalize_ticket_response(ptr: repr_c::Box<FinalizeTicketResponse>) {
    drop(ptr);
}

/// Deallocates a VerifyPoStResponse.
#[ffi_export]
fn destroy_verify_winning_post_response(ptr: repr_c::Box<VerifyWinningPoStResponse>) {
    drop(ptr);
}

#[ffi_export]
fn destroy_verify_window_post_response(ptr: repr_c::Box<VerifyWindowPoStResponse>) {
    drop(ptr);
}

#[ffi_export]
fn destroy_generate_fallback_sector_challenges_response(
    ptr: repr_c::Box<GenerateFallbackSectorChallengesResponse>,
) {
    drop(ptr);
}

#[ffi_export]
fn destroy_generate_single_vanilla_proof_response(
    ptr: repr_c::Box<GenerateSingleVanillaProofResponse>,
) {
    drop(ptr);
}

#[ffi_export]
fn destroy_generate_single_window_post_with_vanilla_response(
    ptr: repr_c::Box<GenerateSingleWindowPoStWithVanillaResponse>,
) {
    drop(ptr);
}

#[ffi_export]
fn destroy_get_num_partition_for_fallback_post_response(
    ptr: repr_c::Box<GetNumPartitionForFallbackPoStResponse>,
) {
    drop(ptr);
}

#[ffi_export]
fn destroy_merge_window_post_partition_proofs_response(
    ptr: repr_c::Box<MergeWindowPoStPartitionProofsResponse>,
) {
    drop(ptr);
}

#[ffi_export]
fn destroy_generate_winning_post_response(ptr: repr_c::Box<GenerateWinningPoStResponse>) {
    drop(ptr);
}

#[ffi_export]
fn destroy_generate_window_post_response(ptr: repr_c::Box<GenerateWindowPoStResponse>) {
    drop(ptr);
}

#[ffi_export]
fn destroy_generate_winning_post_sector_challenge(
    ptr: repr_c::Box<GenerateWinningPoStSectorChallenge>,
) {
    drop(ptr);
}

#[ffi_export]
fn destroy_clear_cache_response(ptr: repr_c::Box<ClearCacheResponse>) {
    drop(ptr);
}

/// Deallocates a AggregateProof
#[ffi_export]
fn destroy_aggregate_proof(ptr: repr_c::Box<AggregateProof>) {
    drop(ptr);
}

/// Deallocates a EmptySectorUpdateProof
#[ffi_export]
fn destroy_empty_sector_update_generate_proof_response(
    ptr: repr_c::Box<EmptySectorUpdateProofResponse>,
) {
    drop(ptr);
}

/// Deallocates a VerifyEmptySectorUpdateProofResponse
#[ffi_export]
fn destroy_empty_sector_update_verify_proof_response(
    ptr: repr_c::Box<VerifyEmptySectorUpdateProofResponse>,
) {
    drop(ptr);
}

/// Deallocates a PartitionProofResponse
#[ffi_export]
fn destroy_generate_empty_sector_update_partition_proof_response(
    ptr: repr_c::Box<PartitionProofResponse>,
) {
    drop(ptr);
}

/// Deallocates a VerifyEmptySectorUpdateProofResponse
#[ffi_export]
fn destroy_verify_empty_sector_update_partition_proof_response(
    ptr: repr_c::Box<VerifyPartitionProofResponse>,
) {
    drop(ptr);
}

/// Deallocates a EmptySectorUpdateEncodeIntoResponse
#[ffi_export]
fn destroy_empty_sector_update_encode_into_response(
    ptr: repr_c::Box<EmptySectorUpdateEncodeIntoResponse>,
) {
    drop(ptr);
}

/// Deallocates a EmptySectorUpdateDecodeFromResponse
#[ffi_export]
fn destroy_empty_sector_update_decode_from_response(
    ptr: repr_c::Box<EmptySectorUpdateDecodeFromResponse>,
) {
    drop(ptr);
}

/// Deallocates a EmptySectorUpdateRemoveEncodedDataResponse
#[ffi_export]
fn destroy_empty_sector_update_remove_encoded_data_response(
    ptr: repr_c::Box<EmptySectorUpdateRemoveEncodedDataResponse>,
) {
    drop(ptr);
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

    /// This is a test method for ensuring that the elements of 1 file matches the other.
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
        let registered_proof = RegisteredSealProof::StackedDrg2KiBV1;

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
        {
            let resp = unsafe { write_without_alignment(registered_proof, src_fd_a, 127, dst_fd) };

            if resp.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp.error_msg.as_str().unwrap();
                panic!("write_without_alignment failed: {:?}", msg);
            }

            assert_eq!(
                resp.total_write_unpadded, 127,
                "should have added 127 bytes of (unpadded) left alignment"
            );
        }

        // write the second
        {
            let existing = vec![127u64];

            let resp = unsafe {
                write_with_alignment(registered_proof, src_fd_b, 508, dst_fd, &existing.into())
            };

            if resp.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp.error_msg.as_str().unwrap();
                panic!("write_with_alignment failed: {:?}", msg);
            }

            assert_eq!(
                resp.left_alignment_unpadded, 381,
                "should have added 381 bytes of (unpadded) left alignment"
            );
        }

        Ok(())
    }

    #[test]
    fn test_proof_types() {
        let seal_types = vec![
            RegisteredSealProof::StackedDrg2KiBV1,
            RegisteredSealProof::StackedDrg8MiBV1,
            RegisteredSealProof::StackedDrg512MiBV1,
            RegisteredSealProof::StackedDrg32GiBV1,
            RegisteredSealProof::StackedDrg64GiBV1,
            RegisteredSealProof::StackedDrg2KiBV1_1,
            RegisteredSealProof::StackedDrg8MiBV1_1,
            RegisteredSealProof::StackedDrg512MiBV1_1,
            RegisteredSealProof::StackedDrg32GiBV1_1,
            RegisteredSealProof::StackedDrg64GiBV1_1,
        ];

        let post_types = vec![
            RegisteredPoStProof::StackedDrgWinning2KiBV1,
            RegisteredPoStProof::StackedDrgWinning8MiBV1,
            RegisteredPoStProof::StackedDrgWinning512MiBV1,
            RegisteredPoStProof::StackedDrgWinning32GiBV1,
            RegisteredPoStProof::StackedDrgWinning64GiBV1,
            RegisteredPoStProof::StackedDrgWindow2KiBV1,
            RegisteredPoStProof::StackedDrgWindow8MiBV1,
            RegisteredPoStProof::StackedDrgWindow512MiBV1,
            RegisteredPoStProof::StackedDrgWindow32GiBV1,
            RegisteredPoStProof::StackedDrgWindow64GiBV1,
        ];

        let num_ops = (seal_types.len() + post_types.len()) * 6;

        let mut pairs = Vec::with_capacity(num_ops);

        for st in seal_types {
            pairs.push(("get_seal_params_cid", get_seal_params_cid(st)));
            pairs.push(("get_seal_verify_key_cid", get_seal_verifying_key_cid(st)));
            pairs.push(("get_seal_verify_key_cid", get_seal_params_path(st)));
            pairs.push(("get_seal_verify_key_cid", get_seal_verifying_key_path(st)));
            pairs.push((
                "get_seal_circuit_identifier",
                get_seal_circuit_identifier(st),
            ));
            pairs.push(("get_seal_version", get_seal_version(st)));
        }

        for pt in post_types {
            pairs.push(("get_post_params_cid", get_post_params_cid(pt)));
            pairs.push(("get_post_verify_key_cid", get_post_verifying_key_cid(pt)));
            pairs.push(("get_post_params_path", get_post_params_path(pt)));
            pairs.push((
                "get_post_verifying_key_path",
                get_post_verifying_key_path(pt),
            ));
            pairs.push((
                "get_post_circuit_identifier",
                get_post_circuit_identifier(pt),
            ));
            pairs.push(("get_post_version", get_post_version(pt)));
        }

        for (label, r) in pairs {
            assert_eq!(
                r.status_code,
                FCPResponseStatus::FCPNoError,
                "non-success exit code from {:?}: {:?}",
                label,
                r.error_msg.as_str().unwrap()
            );

            let y = r.as_str().unwrap();

            assert!(!y.is_empty());

            destroy_string_response(r);
        }
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn test_sealing_v1() -> Result<()> {
        test_sealing_inner(RegisteredSealProof::StackedDrg2KiBV1)
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn test_sealing_v1_1() -> Result<()> {
        test_sealing_inner(RegisteredSealProof::StackedDrg2KiBV1_1)
    }

    fn test_sealing_inner(registered_proof_seal: RegisteredSealProof) -> Result<()> {
        let wrap = |x| ByteArray32 { inner: x };

        // miscellaneous setup and shared values
        let registered_proof_winning_post = RegisteredPoStProof::StackedDrgWinning2KiBV1;
        let registered_proof_window_post = RegisteredPoStProof::StackedDrgWindow2KiBV1;

        let cache_dir = tempfile::tempdir()?;
        let cache_dir_path: Bytes = cache_dir.into_path().into();

        let prover_id = ByteArray32 { inner: [1u8; 32] };
        let randomness = ByteArray32 { inner: [7u8; 32] };
        let sector_id = 42;
        let sector_id2 = 43;
        let seed = ByteArray32 { inner: [5u8; 32] };
        let ticket = ByteArray32 { inner: [6u8; 32] };

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
        let staged_path: Bytes = staged_path.into();

        // create a temp file to be used as the byte destination
        let (sealed_file, sealed_path) = tempfile::NamedTempFile::new()?.keep()?;
        let sealed_path: Bytes = sealed_path.into();

        // last temp file is used to output unsealed bytes
        let (unseal_file, unseal_path) = tempfile::NamedTempFile::new()?.keep()?;

        // transmute temp files to file descriptors
        let piece_file_a_fd = piece_file_a.into_raw_fd();
        let piece_file_b_fd = piece_file_b.into_raw_fd();
        let staged_sector_fd = staged_file.into_raw_fd();

        {
            let resp_a1 = unsafe {
                write_without_alignment(
                    registered_proof_seal,
                    piece_file_a_fd,
                    127,
                    staged_sector_fd,
                )
            };

            if resp_a1.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_a1.error_msg.as_str().unwrap();
                panic!("write_without_alignment failed: {:?}", msg);
            }

            let existing_piece_sizes = vec![127];

            let resp_a2 = unsafe {
                write_with_alignment(
                    registered_proof_seal,
                    piece_file_b_fd,
                    1016,
                    staged_sector_fd,
                    &existing_piece_sizes.into(),
                )
            };

            if resp_a2.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_a2.error_msg.as_str().unwrap();
                panic!("write_with_alignment failed: {:?}", msg);
            }

            let pieces = vec![
                PublicPieceInfo {
                    num_bytes: 127,
                    comm_p: resp_a1.comm_p,
                },
                PublicPieceInfo {
                    num_bytes: 1016,
                    comm_p: resp_a2.comm_p,
                },
            ]
            .into();

            let resp_x = generate_data_commitment(registered_proof_seal, &pieces);

            if resp_x.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_x.error_msg.as_str().unwrap();
                panic!("generate_data_commitment failed: {:?}", msg);
            }

            let resp_b1 = seal_pre_commit_phase1(
                registered_proof_seal,
                &cache_dir_path,
                &staged_path,
                &sealed_path,
                sector_id,
                prover_id,
                ticket,
                &pieces,
            );

            if resp_b1.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_b1.error_msg.as_str().unwrap();
                panic!("seal_pre_commit_phase1 failed: {:?}", msg);
            }

            let resp_b2 = seal_pre_commit_phase2(&resp_b1, &cache_dir_path, &sealed_path);

            if resp_b2.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_b2.error_msg.as_str().unwrap();
                panic!("seal_pre_commit_phase2 failed: {:?}", msg);
            }

            let pre_computed_comm_d: &[u8; 32] = &resp_x;
            let pre_commit_comm_d: &[u8; 32] = &resp_b2.comm_d;

            assert_eq!(
                format!("{:x?}", &pre_computed_comm_d),
                format!("{:x?}", &pre_commit_comm_d),
                "pre-computed CommD and pre-commit CommD don't match"
            );

            let resp_c1 = seal_commit_phase1(
                registered_proof_seal,
                wrap(resp_b2.comm_r),
                wrap(resp_b2.comm_d),
                &cache_dir_path,
                &sealed_path,
                sector_id,
                prover_id,
                ticket,
                seed,
                &pieces,
            );

            if resp_c1.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_c1.error_msg.as_str().unwrap();
                panic!("seal_commit_phase1 failed: {:?}", msg);
            }

            let resp_c2 = seal_commit_phase2(&resp_c1, sector_id, prover_id);

            if resp_c2.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_c2.error_msg.as_str().unwrap();
                panic!("seal_commit_phase2 failed: {:?}", msg);
            }

            let resp_d = verify_seal(
                registered_proof_seal,
                wrap(resp_b2.comm_r),
                wrap(resp_b2.comm_d),
                prover_id,
                ticket,
                seed,
                sector_id,
                &resp_c2.proof,
            );

            if resp_d.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_d.error_msg.as_str().unwrap();
                panic!("seal_commit failed: {:?}", msg);
            }

            assert!(**resp_d, "proof was not valid");

            let resp_c22 = seal_commit_phase2(&resp_c1, sector_id, prover_id);

            if resp_c22.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_c22.error_msg.as_str().unwrap();
                panic!("seal_commit_phase2 failed: {:?}", msg);
            }

            let resp_d2 = verify_seal(
                registered_proof_seal,
                wrap(resp_b2.comm_r),
                wrap(resp_b2.comm_d),
                prover_id,
                ticket,
                seed,
                sector_id,
                &resp_c22.proof,
            );

            if resp_d2.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_d2.error_msg.as_str().unwrap();
                panic!("seal_commit failed: {:?}", msg);
            }

            assert!(**resp_d2, "proof was not valid");

            //////////////////////////////////////////////////////////////////
            // Begin Sector Upgrade testing
            /*
                At this point, upgrade the sector with additional data
                and generate sector update proofs, then test decoding,
                then finally remove the data and continue onward as
                normal.
            */
            let registered_proof_empty_sector_update = RegisteredUpdateProof::StackedDrg2KiBV1;

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

            let resp_new_a1 = unsafe {
                write_without_alignment(
                    registered_proof_seal,
                    piece_file_c_fd,
                    127,
                    new_staged_sector_fd,
                )
            };

            if resp_new_a1.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_new_a1.error_msg.as_str().unwrap();
                panic!("write_without_alignment failed: {:?}", msg);
            }

            let existing_piece_sizes = vec![127];

            let resp_new_a2 = unsafe {
                write_with_alignment(
                    registered_proof_seal,
                    piece_file_d_fd,
                    1016,
                    new_staged_sector_fd,
                    &existing_piece_sizes.into(),
                )
            };

            if resp_new_a2.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_new_a2.error_msg.as_str().unwrap();
                panic!("write_with_alignment failed: {:?}", msg);
            }

            let new_pieces = vec![
                PublicPieceInfo {
                    num_bytes: 127,
                    comm_p: resp_new_a1.comm_p,
                },
                PublicPieceInfo {
                    num_bytes: 1016,
                    comm_p: resp_new_a2.comm_p,
                },
            ]
            .into();

            let resp_new_x = generate_data_commitment(registered_proof_seal, &new_pieces);

            if resp_new_x.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_new_x.error_msg.as_str().unwrap();
                panic!("generate_data_commitment failed: {:?}", msg);
            }

            let new_cache_dir_path = new_cache_dir_path.into();
            let new_staged_path: Bytes = new_staged_path.into();
            let new_sealed_path: Bytes = new_sealed_path.into();
            let decoded_path: Bytes = decoded_path.into();
            let removed_data_path: Bytes = removed_data_path.into();
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

            let resp_encode = empty_sector_update_encode_into(
                registered_proof_empty_sector_update,
                &new_sealed_path,
                &new_cache_dir_path,
                &sealed_path,
                &cache_dir_path,
                &new_staged_path,
                &new_pieces,
            );

            if resp_encode.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_encode.error_msg.as_str().unwrap();
                panic!("empty_sector_update_encode_into failed: {:?}", msg);
            }

            // First generate all vanilla partition proofs
            let resp_partition_proofs = generate_empty_sector_update_partition_proofs(
                registered_proof_empty_sector_update,
                wrap(resp_b2.comm_r),
                wrap(resp_encode.comm_r_new),
                wrap(resp_encode.comm_d_new),
                &sealed_path,
                &cache_dir_path,
                &new_sealed_path,
                &new_cache_dir_path,
            );

            if resp_partition_proofs.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_partition_proofs.error_msg.as_str().unwrap();
                panic!("generate_partition_proofs failed: {:?}", msg);
            }

            // Verify vanilla partition proofs
            let resp_verify_partition_proofs = verify_empty_sector_update_partition_proofs(
                registered_proof_empty_sector_update,
                &resp_partition_proofs,
                wrap(resp_b2.comm_r),
                wrap(resp_encode.comm_r_new),
                wrap(resp_encode.comm_d_new),
            );

            if resp_verify_partition_proofs.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_verify_partition_proofs.error_msg.as_str().unwrap();
                panic!("verify_partition_proofs failed: {:?}", msg);
            }

            // Then generate the sector update proof with the vanilla proofs
            let resp_empty_sector_update = generate_empty_sector_update_proof_with_vanilla(
                registered_proof_empty_sector_update,
                &resp_partition_proofs,
                wrap(resp_b2.comm_r),
                wrap(resp_encode.comm_r_new),
                wrap(resp_encode.comm_d_new),
            );

            if resp_empty_sector_update.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_empty_sector_update.error_msg.as_str().unwrap();
                panic!(
                    "generate_empty_sector_update_proof_with_vanilla failed: {:?}",
                    msg
                );
            }

            // And verify that sector update proof
            let resp_verify_empty_sector_update = verify_empty_sector_update_proof(
                registered_proof_empty_sector_update,
                &resp_empty_sector_update,
                wrap(resp_b2.comm_r),
                wrap(resp_encode.comm_r_new),
                wrap(resp_encode.comm_d_new),
            );

            if resp_verify_empty_sector_update.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_verify_empty_sector_update.error_msg.as_str().unwrap();
                panic!("verify_empty_sector_update_proof failed: {:?}", msg);
            }

            // Now re-generate the empty sector update monolithically (the vanilla proofs are generated internally)
            let resp_empty_sector_update2 = generate_empty_sector_update_proof(
                registered_proof_empty_sector_update,
                wrap(resp_b2.comm_r),
                wrap(resp_encode.comm_r_new),
                wrap(resp_encode.comm_d_new),
                &sealed_path,
                &cache_dir_path,
                &new_sealed_path,
                &new_cache_dir_path,
            );

            if resp_empty_sector_update2.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_empty_sector_update2.error_msg.as_str().unwrap();
                panic!("generate_empty_sector_update_proof failed: {:?}", msg);
            }

            let resp_verify_empty_sector_update2 = verify_empty_sector_update_proof(
                registered_proof_empty_sector_update,
                &resp_empty_sector_update2,
                wrap(resp_b2.comm_r),
                wrap(resp_encode.comm_r_new),
                wrap(resp_encode.comm_d_new),
            );

            if resp_verify_empty_sector_update2.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_verify_empty_sector_update2.error_msg.as_str().unwrap();
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

            let resp_decode = empty_sector_update_decode_from(
                registered_proof_empty_sector_update,
                &decoded_path,
                &new_sealed_path,
                &sealed_path,
                &cache_dir_path,
                wrap(resp_encode.comm_d_new),
            );

            if resp_decode.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_decode.error_msg.as_str().unwrap();
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

            let resp_removed = empty_sector_update_remove_encoded_data(
                registered_proof_empty_sector_update,
                &removed_data_path,
                &removed_data_dir_path,
                &new_sealed_path, // new sealed file path
                &cache_dir_path,  // old replica dir path (for p_aux)
                &new_staged_path, // new staged file data path
                wrap(resp_encode.comm_d_new),
            );

            if resp_removed.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_removed.error_msg.as_str().unwrap();
                panic!("empty_sector_update_remove_encoded_data failed: {:?}", msg);
            }

            // When the data is removed, it MUST match the original sealed data.
            compare_elements(
                &removed_data_path.as_path().unwrap(),
                &sealed_path.as_path().unwrap(),
            )?;

            destroy_write_without_alignment_response(resp_new_a1);
            destroy_write_with_alignment_response(resp_new_a2);
            destroy_generate_data_commitment_response(resp_new_x);

            destroy_empty_sector_update_encode_into_response(resp_encode);
            destroy_empty_sector_update_decode_from_response(resp_decode);
            destroy_empty_sector_update_remove_encoded_data_response(resp_removed);

            destroy_generate_empty_sector_update_partition_proof_response(resp_partition_proofs);
            destroy_verify_empty_sector_update_partition_proof_response(
                resp_verify_partition_proofs,
            );

            destroy_empty_sector_update_generate_proof_response(resp_empty_sector_update);
            destroy_empty_sector_update_generate_proof_response(resp_empty_sector_update2);
            destroy_empty_sector_update_verify_proof_response(resp_verify_empty_sector_update);
            destroy_empty_sector_update_verify_proof_response(resp_verify_empty_sector_update2);

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

            let resp_e = unsafe {
                unseal_range(
                    registered_proof_seal,
                    &cache_dir_path,
                    sealed_file.into_raw_fd(),
                    unseal_file.into_raw_fd(),
                    sector_id,
                    prover_id,
                    ticket,
                    wrap(resp_b2.comm_d),
                    0,
                    2032,
                )
            };

            if resp_e.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_e.error_msg.as_str().unwrap();
                panic!("unseal failed: {:?}", msg);
            }

            // ensure unsealed bytes match what we had in our piece
            let mut buf_b = Vec::with_capacity(2032);
            let mut f = std::fs::File::open(&unseal_path)?;

            let _ = f.read_to_end(&mut buf_b)?;

            let piece_a_len = resp_a1.total_write_unpadded as usize;
            let piece_b_len = resp_a2.total_write_unpadded as usize;
            let piece_b_prefix_len = resp_a2.left_alignment_unpadded as usize;

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
            let resp_f = generate_winning_post_sector_challenge(
                registered_proof_winning_post,
                randomness,
                sectors.len() as u64,
                prover_id,
            );

            if resp_f.status_code != FCPResponseStatus::FCPNoError {
                panic!(
                    "generate_candidates failed: {}",
                    resp_f.error_msg.as_str().unwrap()
                );
            }

            // exercise the ticket-finalizing code path (but don't do anything with the results
            let result: &[u64] = &resp_f;

            if result.is_empty() {
                panic!("generate_candidates produced no results");
            }

            let private_replicas = vec![PrivateReplicaInfo {
                registered_proof: registered_proof_winning_post,
                cache_dir_path: cache_dir_path.clone(),
                comm_r: resp_b2.comm_r,
                replica_path: sealed_path.clone(),
                sector_id,
            }]
            .into();

            // winning post

            let resp_h = generate_winning_post(randomness, &private_replicas, prover_id);

            if resp_h.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_h.error_msg.as_str().unwrap();
                panic!("generate_winning_post failed: {:?}", msg);
            }
            let public_replicas = vec![PublicReplicaInfo {
                registered_proof: registered_proof_winning_post,
                sector_id,
                comm_r: resp_b2.comm_r,
            }]
            .into();

            let resp_i = verify_winning_post(randomness, &public_replicas, &resp_h, prover_id);

            if resp_i.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_i.error_msg.as_str().unwrap();
                panic!("verify_winning_post failed: {:?}", msg);
            }

            if !**resp_i {
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
            let resp_sc = generate_fallback_sector_challenges(
                registered_proof_winning_post,
                randomness,
                &sectors.into(),
                prover_id,
            );

            if resp_sc.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_sc.error_msg.as_str().unwrap();
                panic!("fallback_sector_challenges failed: {:?}", msg);
            }

            let sector_ids: Vec<u64> = resp_sc.ids.to_vec();
            let sector_challenges: Vec<u64> = resp_sc.challenges.to_vec();
            let challenges_stride = resp_sc.challenges_stride;
            let challenge_iterations = sector_challenges.len() / challenges_stride;
            assert_eq!(
                sector_ids.len(),
                challenge_iterations,
                "Challenge iterations must match the number of sector ids"
            );

            let mut vanilla_proofs: Vec<VanillaProof> = Vec::with_capacity(sector_ids.len());

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

                let resp_vp = generate_single_vanilla_proof(private_replica, &challenges);

                if resp_vp.status_code != FCPResponseStatus::FCPNoError {
                    let msg = resp_vp.error_msg.as_str().unwrap();
                    panic!("generate_single_vanilla_proof failed: {:?}", msg);
                }

                vanilla_proofs.push(resp_vp.value.clone());
                destroy_generate_single_vanilla_proof_response(resp_vp);
            }

            let resp_wpwv = generate_winning_post_with_vanilla(
                registered_proof_winning_post,
                randomness,
                prover_id,
                &vanilla_proofs.into(),
            );

            if resp_wpwv.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_wpwv.error_msg.as_str().unwrap();
                panic!("generate_winning_post_with_vanilla failed: {:?}", msg);
            }

            // Verify the second winning post (generated by the distributed post API)
            let resp_di = verify_winning_post(randomness, &public_replicas, &resp_wpwv, prover_id);

            if resp_di.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_di.error_msg.as_str().unwrap();
                panic!("verify_winning_post failed: {:?}", msg);
            }

            if !**resp_di {
                panic!("verify_winning_post rejected the provided proof as invalid");
            }

            // window post

            let private_replicas = vec![PrivateReplicaInfo {
                registered_proof: registered_proof_window_post,
                cache_dir_path: cache_dir_path.clone(),
                comm_r: resp_b2.comm_r,
                replica_path: sealed_path.clone(),
                sector_id,
            }];

            let resp_j = generate_window_post(randomness, &private_replicas.into(), prover_id);

            if resp_j.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_j.error_msg.as_str().unwrap();
                panic!("generate_window_post failed: {:?}", msg);
            }

            let public_replicas = vec![PublicReplicaInfo {
                registered_proof: registered_proof_window_post,
                sector_id,
                comm_r: resp_b2.comm_r,
            }];

            let resp_k = verify_window_post(
                randomness,
                &public_replicas.into(),
                &resp_j.proofs,
                prover_id,
            );

            if resp_k.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_k.error_msg.as_str().unwrap();
                panic!("verify_window_post failed: {:?}", msg);
            }

            if !**resp_k {
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
                PrivateReplicaInfo {
                    registered_proof: registered_proof_window_post,
                    cache_dir_path: cache_dir_path.clone(),
                    comm_r: resp_b2.comm_r,
                    replica_path: sealed_path.clone(),
                    sector_id,
                },
                PrivateReplicaInfo {
                    registered_proof: registered_proof_window_post,
                    cache_dir_path,
                    comm_r: resp_b2.comm_r,
                    replica_path: sealed_path.clone(),
                    sector_id: sector_id2,
                },
            ];
            let public_replicas = vec![
                PublicReplicaInfo {
                    registered_proof: registered_proof_window_post,
                    sector_id,
                    comm_r: resp_b2.comm_r,
                },
                PublicReplicaInfo {
                    registered_proof: registered_proof_window_post,
                    sector_id: sector_id2,
                    comm_r: resp_b2.comm_r,
                },
            ]
            .into();

            // Generate sector challenges.
            let resp_sc2 = generate_fallback_sector_challenges(
                registered_proof_window_post,
                randomness,
                &sectors,
                prover_id,
            );

            if resp_sc2.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_sc2.error_msg.as_str().unwrap();
                panic!("fallback_sector_challenges failed: {:?}", msg);
            }

            let sector_ids: Vec<u64> = resp_sc2.ids.to_vec();
            let sector_challenges: Vec<u64> = resp_sc2.challenges.to_vec();
            let challenges_stride = resp_sc2.challenges_stride;
            let challenge_iterations = sector_challenges.len() / challenges_stride;
            assert_eq!(
                sector_ids.len(),
                challenge_iterations,
                "Challenge iterations must match the number of sector ids"
            );

            let mut vanilla_proofs: Vec<VanillaProof> = Vec::with_capacity(sector_ids.len());

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

                let resp_vp = generate_single_vanilla_proof(private_replica, &challenges);

                if resp_vp.status_code != FCPResponseStatus::FCPNoError {
                    let msg = resp_vp.error_msg.as_str().unwrap();
                    panic!("generate_single_vanilla_proof failed: {:?}", msg);
                }

                vanilla_proofs.push(resp_vp.value.clone());
                destroy_generate_single_vanilla_proof_response(resp_vp);
            }

            let resp_wpwv2 = generate_window_post_with_vanilla(
                registered_proof_window_post,
                randomness,
                prover_id,
                &vanilla_proofs.into(),
            );

            if resp_wpwv2.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_wpwv2.error_msg.as_str().unwrap();
                panic!("generate_window_post_with_vanilla failed: {:?}", msg);
            }

            let resp_k2 =
                verify_window_post(randomness, &public_replicas, &resp_wpwv2.proofs, prover_id);

            if resp_k2.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_k2.error_msg.as_str().unwrap();
                panic!("verify_window_post failed: {:?}", msg);
            }

            if !**resp_k2 {
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

            let num_partitions_resp =
                get_num_partition_for_fallback_post(registered_proof_window_post, sectors.len());
            if num_partitions_resp.status_code != FCPResponseStatus::FCPNoError {
                let msg = num_partitions_resp.error_msg.as_str().unwrap();
                panic!("get_num_partition_for_fallback_post failed: {:?}", msg);
            }

            let mut partition_proofs: Vec<PartitionSnarkProof> =
                Vec::with_capacity(**num_partitions_resp);
            for partition_index in 0..**num_partitions_resp {
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

                    let resp_vp = generate_single_vanilla_proof(private_replica, &challenges);

                    if resp_vp.status_code != FCPResponseStatus::FCPNoError {
                        let msg = resp_vp.error_msg.as_str().unwrap();
                        panic!("generate_single_vanilla_proof failed: {:?}", msg);
                    }

                    vanilla_proofs.push(resp_vp.value.clone());
                    destroy_generate_single_vanilla_proof_response(resp_vp);
                }

                let single_partition_proof_resp = generate_single_window_post_with_vanilla(
                    registered_proof_window_post,
                    randomness,
                    prover_id,
                    &vanilla_proofs.into(),
                    partition_index,
                );

                if single_partition_proof_resp.status_code != FCPResponseStatus::FCPNoError {
                    let msg = single_partition_proof_resp.error_msg.as_str().unwrap();
                    panic!("generate_single_window_post_with_vanilla failed: {:?}", msg);
                }

                partition_proofs.push(single_partition_proof_resp.partition_proof.clone());
                destroy_generate_single_window_post_with_vanilla_response(
                    single_partition_proof_resp,
                );
            }

            destroy_get_num_partition_for_fallback_post_response(num_partitions_resp);

            let merged_proof_resp = merge_window_post_partition_proofs(
                registered_proof_window_post,
                &partition_proofs.into(),
            );

            if merged_proof_resp.status_code != FCPResponseStatus::FCPNoError {
                let msg = merged_proof_resp.error_msg.as_str().unwrap();
                panic!("merge_window_post_partition_proofs failed: {:?}", msg);
            }

            let resp_k3 = verify_window_post(
                randomness,
                &public_replicas,
                &vec![merged_proof_resp.value.clone()].into(),
                prover_id,
            );

            if resp_k3.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_k3.error_msg.as_str().unwrap();
                panic!("verify_window_post failed: {:?}", msg);
            }

            if !**resp_k3 {
                panic!("verify_window_post rejected the provided proof as invalid");
            }

            destroy_merge_window_post_partition_proofs_response(merged_proof_resp);

            ////////////////////
            // Cleanup responses
            ////////////////////

            destroy_write_without_alignment_response(resp_a1);
            destroy_write_with_alignment_response(resp_a2);
            destroy_generate_data_commitment_response(resp_x);

            destroy_seal_pre_commit_phase1_response(resp_b1);
            destroy_seal_pre_commit_phase2_response(resp_b2);
            destroy_seal_commit_phase1_response(resp_c1);
            destroy_seal_commit_phase2_response(resp_c2);

            destroy_verify_seal_response(resp_d);
            destroy_unseal_range_response(resp_e);

            destroy_generate_winning_post_sector_challenge(resp_f);
            destroy_generate_fallback_sector_challenges_response(resp_sc);
            destroy_generate_winning_post_response(resp_h);
            destroy_generate_winning_post_response(resp_wpwv);
            destroy_verify_winning_post_response(resp_i);
            destroy_verify_winning_post_response(resp_di);

            destroy_generate_fallback_sector_challenges_response(resp_sc2);
            destroy_generate_window_post_response(resp_j);
            destroy_generate_window_post_response(resp_wpwv2);
            destroy_verify_window_post_response(resp_k);
            destroy_verify_window_post_response(resp_k2);
            destroy_verify_window_post_response(resp_k3);

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
        test_faulty_sectors_inner(RegisteredSealProof::StackedDrg2KiBV1)
    }

    #[test]
    fn test_faulty_sectors_v1_1() -> Result<()> {
        test_faulty_sectors_inner(RegisteredSealProof::StackedDrg2KiBV1_1)
    }

    fn test_faulty_sectors_inner(registered_proof_seal: RegisteredSealProof) -> Result<()> {
        // miscellaneous setup and shared values
        let registered_proof_window_post = RegisteredPoStProof::StackedDrgWindow2KiBV1;

        let cache_dir = tempfile::tempdir()?;
        let cache_dir_path: Bytes = cache_dir.into_path().into();

        let prover_id = ByteArray32 { inner: [1u8; 32] };
        let randomness = ByteArray32 { inner: [7u8; 32] };
        let sector_id = 42;
        let ticket = ByteArray32 { inner: [6u8; 32] };

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
        let staged_path: Bytes = staged_path.into();

        // create a temp file to be used as the byte destination
        let (_sealed_file, sealed_path) = tempfile::NamedTempFile::new()?.keep()?;
        let sealed_path: Bytes = sealed_path.into();

        // transmute temp files to file descriptors
        let piece_file_a_fd = piece_file_a.into_raw_fd();
        let piece_file_b_fd = piece_file_b.into_raw_fd();
        let staged_sector_fd = staged_file.into_raw_fd();

        {
            let resp_a1 = unsafe {
                write_without_alignment(
                    registered_proof_seal,
                    piece_file_a_fd,
                    127,
                    staged_sector_fd,
                )
            };

            if resp_a1.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_a1.error_msg.as_str().unwrap();
                panic!("write_without_alignment failed: {:?}", msg);
            }

            let existing_piece_sizes = vec![127];

            let resp_a2 = unsafe {
                write_with_alignment(
                    registered_proof_seal,
                    piece_file_b_fd,
                    1016,
                    staged_sector_fd,
                    &existing_piece_sizes.into(),
                )
            };

            if resp_a2.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_a2.error_msg.as_str().unwrap();
                panic!("write_with_alignment failed: {:?}", msg);
            }

            let pieces = vec![
                PublicPieceInfo {
                    num_bytes: 127,
                    comm_p: resp_a1.comm_p,
                },
                PublicPieceInfo {
                    num_bytes: 1016,
                    comm_p: resp_a2.comm_p,
                },
            ]
            .into();

            let resp_x = generate_data_commitment(registered_proof_seal, &pieces);

            if resp_x.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_x.error_msg.as_str().unwrap();
                panic!("generate_data_commitment failed: {:?}", msg);
            }

            let resp_b1 = seal_pre_commit_phase1(
                registered_proof_seal,
                &cache_dir_path,
                &staged_path,
                &sealed_path,
                sector_id,
                prover_id,
                ticket,
                &pieces,
            );

            if resp_b1.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_b1.error_msg.as_str().unwrap();
                panic!("seal_pre_commit_phase1 failed: {:?}", msg);
            }

            let resp_b2 = seal_pre_commit_phase2(&resp_b1, &cache_dir_path, &sealed_path);

            if resp_b2.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_b2.error_msg.as_str().unwrap();
                panic!("seal_pre_commit_phase2 failed: {:?}", msg);
            }

            // window post

            let faulty_sealed_file = tempfile::NamedTempFile::new()?;
            let faulty_sealed_path = faulty_sealed_file.path();

            let private_replicas = vec![PrivateReplicaInfo {
                registered_proof: registered_proof_window_post,
                cache_dir_path,
                comm_r: resp_b2.comm_r,
                replica_path: faulty_sealed_path.into(),
                sector_id,
            }];

            let resp_j = generate_window_post(randomness, &private_replicas.into(), prover_id);

            assert_eq!(
                resp_j.status_code,
                FCPResponseStatus::FCPUnclassifiedError,
                "generate_window_post should have failed"
            );

            let faulty_sectors: &[u64] = &resp_j.faulty_sectors;
            assert_eq!(faulty_sectors, &[42], "sector 42 should be faulty");

            destroy_write_without_alignment_response(resp_a1);
            destroy_write_with_alignment_response(resp_a2);

            destroy_seal_pre_commit_phase1_response(resp_b1);
            destroy_seal_pre_commit_phase2_response(resp_b2);

            destroy_generate_window_post_response(resp_j);

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
            RegisteredSealProof::StackedDrg2KiBV1,
            RegisteredAggregationProof::SnarkPackV1,
        )
    }

    #[test]
    #[ignore]
    fn test_sealing_aggregation_v1_1() -> Result<()> {
        test_sealing_aggregation(
            RegisteredSealProof::StackedDrg2KiBV1_1,
            RegisteredAggregationProof::SnarkPackV1,
        )
    }

    fn test_sealing_aggregation(
        registered_proof_seal: RegisteredSealProof,
        registered_aggregation: RegisteredAggregationProof,
    ) -> Result<()> {
        let wrap = |x| ByteArray32 { inner: x };

        // miscellaneous setup and shared values
        let cache_dir = tempfile::tempdir()?;
        let cache_dir_path: Bytes = cache_dir.into_path().into();

        let prover_id = ByteArray32 { inner: [1u8; 32] };
        let sector_id = 42;
        let seed = ByteArray32 { inner: [5u8; 32] };
        let ticket = ByteArray32 { inner: [6u8; 32] };

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
        let staged_path: Bytes = staged_path.into();

        // create a temp file to be used as the byte destination
        let (_sealed_file, sealed_path) = tempfile::NamedTempFile::new()?.keep()?;
        let sealed_path: Bytes = sealed_path.into();

        // transmute temp files to file descriptors
        let piece_file_a_fd = piece_file_a.into_raw_fd();
        let piece_file_b_fd = piece_file_b.into_raw_fd();
        let staged_sector_fd = staged_file.into_raw_fd();

        {
            let resp_a1 = unsafe {
                write_without_alignment(
                    registered_proof_seal,
                    piece_file_a_fd,
                    127,
                    staged_sector_fd,
                )
            };

            if resp_a1.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_a1.error_msg.as_str().unwrap();
                panic!("write_without_alignment failed: {:?}", msg);
            }

            let existing_piece_sizes = vec![127];

            let resp_a2 = unsafe {
                write_with_alignment(
                    registered_proof_seal,
                    piece_file_b_fd,
                    1016,
                    staged_sector_fd,
                    &existing_piece_sizes.into(),
                )
            };

            if resp_a2.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_a2.error_msg.as_str().unwrap();
                panic!("write_with_alignment failed: {:?}", msg);
            }

            let pieces = vec![
                PublicPieceInfo {
                    num_bytes: 127,
                    comm_p: resp_a1.comm_p,
                },
                PublicPieceInfo {
                    num_bytes: 1016,
                    comm_p: resp_a2.comm_p,
                },
            ]
            .into();

            let resp_x = generate_data_commitment(registered_proof_seal, &pieces);

            if resp_x.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_x.error_msg.as_str().unwrap();
                panic!("generate_data_commitment failed: {:?}", msg);
            }

            let resp_b1 = seal_pre_commit_phase1(
                registered_proof_seal,
                &cache_dir_path,
                &staged_path,
                &sealed_path,
                sector_id,
                prover_id,
                ticket,
                &pieces,
            );

            if resp_b1.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_b1.error_msg.as_str().unwrap();
                panic!("seal_pre_commit_phase1 failed: {:?}", msg);
            }

            let resp_b2 = seal_pre_commit_phase2(&resp_b1, &cache_dir_path, &sealed_path);

            if resp_b2.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_b2.error_msg.as_str().unwrap();
                panic!("seal_pre_commit_phase2 failed: {:?}", msg);
            }

            let pre_computed_comm_d: &[u8; 32] = &resp_x;
            let pre_commit_comm_d: &[u8; 32] = &resp_b2.comm_d;

            assert_eq!(
                format!("{:x?}", &pre_computed_comm_d),
                format!("{:x?}", &pre_commit_comm_d),
                "pre-computed CommD and pre-commit CommD don't match"
            );

            let resp_c1 = seal_commit_phase1(
                registered_proof_seal,
                wrap(resp_b2.comm_r),
                wrap(resp_b2.comm_d),
                &cache_dir_path,
                &sealed_path,
                sector_id,
                prover_id,
                ticket,
                seed,
                &pieces,
            );

            if resp_c1.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_c1.error_msg.as_str().unwrap();
                panic!("seal_commit_phase1 failed: {:?}", msg);
            }

            let resp_c2 = seal_commit_phase2(&resp_c1, sector_id, prover_id);

            if resp_c2.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_c2.error_msg.as_str().unwrap();
                panic!("seal_commit_phase2 failed: {:?}", msg);
            }

            let resp_d = verify_seal(
                registered_proof_seal,
                wrap(resp_b2.comm_r),
                wrap(resp_b2.comm_d),
                prover_id,
                ticket,
                seed,
                sector_id,
                &resp_c2.proof,
            );

            if resp_d.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_d.error_msg.as_str().unwrap();
                panic!("seal_commit failed: {:?}", msg);
            }

            assert!(**resp_d, "proof was not valid");

            let resp_c22 = seal_commit_phase2(&resp_c1, sector_id, prover_id);

            if resp_c22.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_c22.error_msg.as_str().unwrap();
                panic!("seal_commit_phase2 failed: {:?}", msg);
            }

            let resp_d2 = verify_seal(
                registered_proof_seal,
                wrap(resp_b2.comm_r),
                wrap(resp_b2.comm_d),
                prover_id,
                ticket,
                seed,
                sector_id,
                &resp_c22.proof,
            );

            if resp_d2.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_d2.error_msg.as_str().unwrap();
                panic!("seal_commit failed: {:?}", msg);
            }

            assert!(**resp_d2, "proof was not valid");

            let seal_commit_responses: Vec<SealCommitPhase2> =
                vec![resp_c2.value.clone(), resp_c22.value.clone()];

            let comm_rs = vec![
                ByteArray32 {
                    inner: resp_b2.comm_r,
                },
                ByteArray32 {
                    inner: resp_b2.comm_r,
                },
            ];
            let seeds = vec![seed, seed];
            let resp_aggregate_proof = aggregate_seal_proofs(
                registered_proof_seal,
                registered_aggregation,
                comm_rs.into(),
                seeds.into(),
                &seal_commit_responses.into(),
            );

            if resp_aggregate_proof.status_code != FCPResponseStatus::FCPNoError {
                panic!(
                    "aggregate_seal_proofs failed: {}",
                    resp_aggregate_proof.error_msg.as_str().unwrap()
                );
            }

            let inputs: Vec<AggregationInputs> = vec![
                AggregationInputs {
                    comm_r: wrap(resp_b2.comm_r),
                    comm_d: wrap(resp_b2.comm_d),
                    sector_id,
                    ticket,
                    seed,
                },
                AggregationInputs {
                    comm_r: wrap(resp_b2.comm_r),
                    comm_d: wrap(resp_b2.comm_d),
                    sector_id,
                    ticket,
                    seed,
                },
            ];

            let resp_ad = verify_aggregate_seal_proof(
                registered_proof_seal,
                registered_aggregation,
                prover_id,
                &resp_aggregate_proof,
                &inputs.into(),
            );

            if resp_ad.status_code != FCPResponseStatus::FCPNoError {
                let msg = resp_ad.error_msg.as_str().unwrap();
                panic!("verify_aggregate_seal_proof failed: {:?}", msg);
            }

            assert!(**resp_ad, "aggregated proof was not valid");

            destroy_write_without_alignment_response(resp_a1);
            destroy_write_with_alignment_response(resp_a2);
            destroy_generate_data_commitment_response(resp_x);

            destroy_seal_pre_commit_phase1_response(resp_b1);
            destroy_seal_pre_commit_phase2_response(resp_b2);
            destroy_seal_commit_phase1_response(resp_c1);

            destroy_seal_commit_phase2_response(resp_c2);
            destroy_seal_commit_phase2_response(resp_c22);

            destroy_verify_seal_response(resp_d);
            destroy_verify_seal_response(resp_d2);

            destroy_verify_aggregate_seal_response(resp_ad);

            //destroy_aggregation_inputs_response(resp_c2_inputs);
            //destroy_aggregation_inputs_response(resp_c22_inputs);

            destroy_aggregate_proof(resp_aggregate_proof);

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
