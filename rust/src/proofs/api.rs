use std::mem;
use std::slice::from_raw_parts;
use std::sync::Once;

use ffi_toolkit::{
    c_str_to_pbuf, catch_panic_response, raw_ptr, rust_str_to_c_str, FCPResponseStatus,
};
use filecoin_proofs_api::{
    PaddedBytesAmount, PieceInfo, RegisteredPoStProof, RegisteredSealProof, SectorId,
    UnpaddedByteIndex, UnpaddedBytesAmount,
};
use libc;

use super::helpers::{bls_12_fr_into_bytes, c_to_rust_candidates, to_private_replica_info_map};
use super::types::*;
use crate::proofs::helpers::c_to_rust_post_proofs;
use filecoin_proofs_api::seal::SealPreCommitPhase2Output;
use std::path::PathBuf;

/// TODO: document
///
#[no_mangle]
#[cfg(not(target_os = "windows"))]
pub unsafe extern "C" fn fil_write_with_alignment(
    registered_proof: fil_RegisteredSealProof,
    src_fd: libc::c_int,
    src_size: u64,
    dst_fd: libc::c_int,
    existing_piece_sizes_ptr: *const u64,
    existing_piece_sizes_len: libc::size_t,
) -> *mut fil_WriteWithAlignmentResponse {
    catch_panic_response(|| {
        init_log();

        info!("write_with_alignment: start");

        let mut response = fil_WriteWithAlignmentResponse::default();

        let piece_sizes: Vec<UnpaddedBytesAmount> =
            from_raw_parts(existing_piece_sizes_ptr, existing_piece_sizes_len)
                .iter()
                .map(|n| UnpaddedBytesAmount(*n))
                .collect();

        let n = UnpaddedBytesAmount(src_size);

        match filecoin_proofs_api::seal::add_piece(
            registered_proof.into(),
            FileDescriptorRef::new(src_fd),
            FileDescriptorRef::new(dst_fd),
            n,
            &piece_sizes,
        ) {
            Ok((info, written)) => {
                response.comm_p = info.commitment;
                response.left_alignment_unpadded = (written - n).into();
                response.status_code = FCPResponseStatus::FCPNoError;
                response.total_write_unpadded = written.into();
            }
            Err(err) => {
                response.status_code = FCPResponseStatus::FCPUnclassifiedError;
                response.error_msg = rust_str_to_c_str(format!("{:?}", err));
            }
        }

        info!("write_with_alignment: finish");

        raw_ptr(response)
    })
}

/// TODO: document
///
#[no_mangle]
#[cfg(not(target_os = "windows"))]
pub unsafe extern "C" fn fil_write_without_alignment(
    registered_proof: fil_RegisteredSealProof,
    src_fd: libc::c_int,
    src_size: u64,
    dst_fd: libc::c_int,
) -> *mut fil_WriteWithoutAlignmentResponse {
    catch_panic_response(|| {
        init_log();

        info!("write_without_alignment: start");

        let mut response = fil_WriteWithoutAlignmentResponse::default();

        match filecoin_proofs_api::seal::write_and_preprocess(
            registered_proof.into(),
            FileDescriptorRef::new(src_fd),
            FileDescriptorRef::new(dst_fd),
            UnpaddedBytesAmount(src_size),
        ) {
            Ok((info, written)) => {
                response.comm_p = info.commitment;
                response.status_code = FCPResponseStatus::FCPNoError;
                response.total_write_unpadded = written.into();
            }
            Err(err) => {
                response.status_code = FCPResponseStatus::FCPUnclassifiedError;
                response.error_msg = rust_str_to_c_str(format!("{:?}", err));
            }
        }

        info!("write_without_alignment: finish");

        raw_ptr(response)
    })
}

/// TODO: document
///
#[no_mangle]
pub unsafe extern "C" fn fil_seal_pre_commit_phase1(
    registered_proof: fil_RegisteredSealProof,
    cache_dir_path: *const libc::c_char,
    staged_sector_path: *const libc::c_char,
    sealed_sector_path: *const libc::c_char,
    sector_id: u64,
    prover_id: fil_32ByteArray,
    ticket: fil_32ByteArray,
    pieces_ptr: *const fil_PublicPieceInfo,
    pieces_len: libc::size_t,
) -> *mut fil_SealPreCommitPhase1Response {
    catch_panic_response(|| {
        init_log();

        info!("seal_pre_commit_phase1: start");

        let public_pieces: Vec<PieceInfo> = from_raw_parts(pieces_ptr, pieces_len)
            .iter()
            .cloned()
            .map(Into::into)
            .collect();

        let mut response: fil_SealPreCommitPhase1Response = Default::default();

        let result = filecoin_proofs_api::seal::seal_pre_commit_phase1(
            registered_proof.into(),
            c_str_to_pbuf(cache_dir_path),
            c_str_to_pbuf(staged_sector_path),
            c_str_to_pbuf(sealed_sector_path),
            prover_id.inner,
            SectorId::from(sector_id),
            ticket.inner,
            &public_pieces,
        )
        .and_then(|output| serde_json::to_vec(&output).map_err(Into::into));

        match result {
            Ok(output) => {
                response.status_code = FCPResponseStatus::FCPNoError;
                response.seal_pre_commit_phase1_output_ptr = output.as_ptr();
                response.seal_pre_commit_phase1_output_len = output.len();
                mem::forget(output);
            }
            Err(err) => {
                response.status_code = FCPResponseStatus::FCPUnclassifiedError;
                response.error_msg = rust_str_to_c_str(format!("{:?}", err));
            }
        }

        info!("seal_pre_commit_phase1: finish");

        raw_ptr(response)
    })
}

/// TODO: document
///
#[no_mangle]
pub unsafe extern "C" fn fil_seal_pre_commit_phase2(
    seal_pre_commit_phase1_output_ptr: *const u8,
    seal_pre_commit_phase1_output_len: libc::size_t,
    cache_dir_path: *const libc::c_char,
    sealed_sector_path: *const libc::c_char,
) -> *mut fil_SealPreCommitPhase2Response {
    catch_panic_response(|| {
        init_log();

        info!("seal_pre_commit_phase2: start");

        let mut response: fil_SealPreCommitPhase2Response = Default::default();

        let phase_1_output = serde_json::from_slice(from_raw_parts(
            seal_pre_commit_phase1_output_ptr,
            seal_pre_commit_phase1_output_len,
        ))
        .map_err(Into::into);

        let result = phase_1_output.and_then(|o| {
            filecoin_proofs_api::seal::seal_pre_commit_phase2::<PathBuf, PathBuf>(
                o,
                c_str_to_pbuf(cache_dir_path),
                c_str_to_pbuf(sealed_sector_path),
            )
        });

        match result {
            Ok(output) => {
                response.status_code = FCPResponseStatus::FCPNoError;
                response.comm_r = output.comm_r;
                response.comm_d = output.comm_d;
                response.registered_proof = output.registered_proof.into();
            }
            Err(err) => {
                response.status_code = FCPResponseStatus::FCPUnclassifiedError;
                response.error_msg = rust_str_to_c_str(format!("{:?}", err));
            }
        }

        info!("seal_pre_commit_phase2: finish");

        raw_ptr(response)
    })
}

/// TODO: document
///
#[no_mangle]
pub unsafe extern "C" fn fil_seal_commit_phase1(
    registered_proof: fil_RegisteredSealProof,
    comm_r: fil_32ByteArray,
    comm_d: fil_32ByteArray,
    cache_dir_path: *const libc::c_char,
    replica_path: *const libc::c_char,
    sector_id: u64,
    prover_id: fil_32ByteArray,
    ticket: fil_32ByteArray,
    seed: fil_32ByteArray,
    pieces_ptr: *const fil_PublicPieceInfo,
    pieces_len: libc::size_t,
) -> *mut fil_SealCommitPhase1Response {
    catch_panic_response(|| {
        init_log();

        info!("seal_commit_phase1: start");

        let mut response = fil_SealCommitPhase1Response::default();

        let spcp2o = SealPreCommitPhase2Output {
            registered_proof: registered_proof.into(),
            comm_r: comm_r.inner,
            comm_d: comm_d.inner,
        };

        let public_pieces: Vec<PieceInfo> = from_raw_parts(pieces_ptr, pieces_len)
            .iter()
            .cloned()
            .map(Into::into)
            .collect();

        let result = filecoin_proofs_api::seal::seal_commit_phase1(
            c_str_to_pbuf(cache_dir_path),
            c_str_to_pbuf(replica_path),
            prover_id.inner,
            SectorId::from(sector_id),
            ticket.inner,
            seed.inner,
            spcp2o,
            &public_pieces,
        );

        match result.and_then(|output| serde_json::to_vec(&output).map_err(Into::into)) {
            Ok(output) => {
                response.status_code = FCPResponseStatus::FCPNoError;
                response.seal_commit_phase1_output_ptr = output.as_ptr();
                response.seal_commit_phase1_output_len = output.len();
                mem::forget(output);
            }
            Err(err) => {
                response.status_code = FCPResponseStatus::FCPUnclassifiedError;
                response.error_msg = rust_str_to_c_str(format!("{:?}", err));
            }
        }

        info!("seal_commit_phase1: finish");

        raw_ptr(response)
    })
}

#[no_mangle]
pub unsafe extern "C" fn fil_seal_commit_phase2(
    seal_commit_phase1_output_ptr: *const u8,
    seal_commit_phase1_output_len: libc::size_t,
    sector_id: u64,
    prover_id: fil_32ByteArray,
) -> *mut fil_SealCommitPhase2Response {
    catch_panic_response(|| {
        init_log();

        info!("seal_commit_phase2: start");

        let mut response = fil_SealCommitPhase2Response::default();

        let scp1o = serde_json::from_slice(from_raw_parts(
            seal_commit_phase1_output_ptr,
            seal_commit_phase1_output_len,
        ))
        .map_err(Into::into);

        let result = scp1o.and_then(|o| {
            filecoin_proofs_api::seal::seal_commit_phase2(
                o,
                prover_id.inner,
                SectorId::from(sector_id),
            )
        });

        match result {
            Ok(output) => {
                response.status_code = FCPResponseStatus::FCPNoError;
                response.proof_ptr = output.proof.as_ptr();
                response.proof_len = output.proof.len();
                mem::forget(output.proof);
            }
            Err(err) => {
                response.status_code = FCPResponseStatus::FCPUnclassifiedError;
                response.error_msg = rust_str_to_c_str(format!("{:?}", err));
            }
        }

        info!("seal_commit_phase2: finish");

        raw_ptr(response)
    })
}

/// TODO: document
#[no_mangle]
pub unsafe extern "C" fn fil_unseal(
    registered_proof: fil_RegisteredSealProof,
    cache_dir_path: *const libc::c_char,
    sealed_sector_path: *const libc::c_char,
    unseal_output_path: *const libc::c_char,
    sector_id: u64,
    prover_id: fil_32ByteArray,
    ticket: fil_32ByteArray,
    comm_d: fil_32ByteArray,
) -> *mut fil_UnsealResponse {
    catch_panic_response(|| {
        init_log();

        info!("unseal: start");
        let registered_proof: RegisteredSealProof = registered_proof.into();
        let result = filecoin_proofs_api::seal::get_unsealed_range(
            registered_proof,
            c_str_to_pbuf(cache_dir_path),
            c_str_to_pbuf(sealed_sector_path),
            c_str_to_pbuf(unseal_output_path),
            prover_id.inner,
            SectorId::from(sector_id),
            comm_d.inner,
            ticket.inner,
            UnpaddedByteIndex(0u64),
            UnpaddedBytesAmount::from(PaddedBytesAmount(u64::from(registered_proof.sector_size()))),
        );

        let mut response = fil_UnsealResponse::default();

        match result {
            Ok(_) => {
                response.status_code = FCPResponseStatus::FCPNoError;
            }
            Err(err) => {
                response.status_code = FCPResponseStatus::FCPUnclassifiedError;
                response.error_msg = rust_str_to_c_str(format!("{:?}", err));
            }
        };

        info!("unseal: finish");

        raw_ptr(response)
    })
}

/// TODO: document
#[no_mangle]
pub unsafe extern "C" fn fil_unseal_range(
    registered_proof: fil_RegisteredSealProof,
    cache_dir_path: *const libc::c_char,
    sealed_sector_path: *const libc::c_char,
    unseal_output_path: *const libc::c_char,
    sector_id: u64,
    prover_id: fil_32ByteArray,
    ticket: fil_32ByteArray,
    comm_d: fil_32ByteArray,
    offset: u64,
    length: u64,
) -> *mut fil_UnsealRangeResponse {
    catch_panic_response(|| {
        init_log();

        info!("unseal_range: start");

        let result = filecoin_proofs_api::seal::get_unsealed_range(
            registered_proof.into(),
            c_str_to_pbuf(cache_dir_path),
            c_str_to_pbuf(sealed_sector_path),
            c_str_to_pbuf(unseal_output_path),
            prover_id.inner,
            SectorId::from(sector_id),
            comm_d.inner,
            ticket.inner,
            UnpaddedByteIndex(offset),
            UnpaddedBytesAmount(length),
        );

        let mut response = fil_UnsealRangeResponse::default();

        match result {
            Ok(_) => {
                response.status_code = FCPResponseStatus::FCPNoError;
            }
            Err(err) => {
                response.status_code = FCPResponseStatus::FCPUnclassifiedError;
                response.error_msg = rust_str_to_c_str(format!("{:?}", err));
            }
        };

        info!("unseal_range: finish");

        raw_ptr(response)
    })
}

/// Verifies the output of seal.
///
#[no_mangle]
pub unsafe extern "C" fn fil_verify_seal(
    registered_proof: fil_RegisteredSealProof,
    comm_r: fil_32ByteArray,
    comm_d: fil_32ByteArray,
    prover_id: fil_32ByteArray,
    ticket: fil_32ByteArray,
    seed: fil_32ByteArray,
    sector_id: u64,
    proof_ptr: *const u8,
    proof_len: libc::size_t,
) -> *mut super::types::fil_VerifySealResponse {
    catch_panic_response(|| {
        init_log();

        info!("verify_seal: start");

        let mut proof_bytes: Vec<u8> = vec![0; proof_len];
        proof_bytes.clone_from_slice(from_raw_parts(proof_ptr, proof_len));

        let result = filecoin_proofs_api::seal::verify_seal(
            registered_proof.into(),
            comm_r.inner,
            comm_d.inner,
            prover_id.inner,
            SectorId::from(sector_id),
            ticket.inner,
            seed.inner,
            &proof_bytes,
        );

        let mut response = fil_VerifySealResponse::default();

        match result {
            Ok(true) => {
                response.status_code = FCPResponseStatus::FCPNoError;
                response.is_valid = true;
            }
            Ok(false) => {
                response.status_code = FCPResponseStatus::FCPNoError;
                response.is_valid = false;
            }
            Err(err) => {
                response.status_code = FCPResponseStatus::FCPUnclassifiedError;
                response.error_msg = rust_str_to_c_str(format!("{:?}", err));
            }
        };

        info!("verify_seal: finish");

        raw_ptr(response)
    })
}

/// Finalize a partial_ticket.
#[no_mangle]
pub unsafe extern "C" fn fil_finalize_ticket(
    partial_ticket: fil_32ByteArray,
) -> *mut fil_FinalizeTicketResponse {
    catch_panic_response(|| {
        init_log();

        let partial_ticket = partial_ticket.inner;

        info!("finalize_ticket: start");

        let mut response = fil_FinalizeTicketResponse::default();

        match filecoin_proofs_api::post::finalize_ticket(&partial_ticket) {
            Ok(ticket) => {
                response.status_code = FCPResponseStatus::FCPNoError;
                response.ticket = ticket;
            }
            Err(err) => {
                response.status_code = FCPResponseStatus::FCPUnclassifiedError;
                response.error_msg = rust_str_to_c_str(format!("{:?}", err));
            }
        };

        info!("finalize_ticket: finish");

        raw_ptr(response)
    })
}

/// Verifies that a proof-of-spacetime is valid.
#[no_mangle]
pub unsafe extern "C" fn fil_verify_post(
    randomness: fil_32ByteArray,
    challenge_count: u64,
    replicas_ptr: *const fil_PublicReplicaInfo,
    replicas_len: libc::size_t,
    proofs_ptr: *const fil_PoStProof,
    proofs_len: libc::size_t,
    winners_ptr: *const fil_Candidate,
    winners_len: libc::size_t,
    prover_id: fil_32ByteArray,
) -> *mut fil_VerifyPoStResponse {
    catch_panic_response(|| {
        init_log();

        info!("verify_post: start");

        let mut response = fil_VerifyPoStResponse::default();

        let convert = super::helpers::to_public_replica_info_map(replicas_ptr, replicas_len);

        let result = convert.and_then(|map| {
            let winners = c_to_rust_candidates(winners_ptr, winners_len)?;
            let post_proofs = c_to_rust_post_proofs(proofs_ptr, proofs_len)?;

            let proofs: Vec<Vec<u8>> = post_proofs.iter().map(|pp| pp.clone().proof).collect();

            filecoin_proofs_api::post::verify_post(
                &randomness.inner,
                challenge_count,
                &proofs,
                &map,
                &winners,
                prover_id.inner,
            )
        });

        match result {
            Ok(is_valid) => {
                response.status_code = FCPResponseStatus::FCPNoError;
                response.is_valid = is_valid;
            }
            Err(err) => {
                response.status_code = FCPResponseStatus::FCPUnclassifiedError;
                response.error_msg = rust_str_to_c_str(format!("{:?}", err));
            }
        };

        info!("verify_post: {}", "finish");
        raw_ptr(response)
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
    catch_panic_response(|| {
        init_log();

        use std::os::unix::io::{FromRawFd, IntoRawFd};

        let mut piece_file = std::fs::File::from_raw_fd(piece_fd_raw);

        let unpadded_piece_size = UnpaddedBytesAmount(unpadded_piece_size);
        let result = filecoin_proofs_api::seal::generate_piece_commitment(
            registered_proof.into(),
            &mut piece_file,
            unpadded_piece_size,
        );

        // avoid dropping the File which closes it
        let _ = piece_file.into_raw_fd();

        let mut response = fil_GeneratePieceCommitmentResponse::default();

        match result {
            Ok(meta) => {
                response.status_code = FCPResponseStatus::FCPNoError;
                response.comm_p = meta.commitment;
                response.num_bytes_aligned = meta.size.into();
            }
            Err(err) => {
                response.status_code = FCPResponseStatus::FCPUnclassifiedError;
                response.error_msg = rust_str_to_c_str(format!("{:?}", err));
            }
        }

        raw_ptr(response)
    })
}

/// Returns the merkle root for a sector containing the provided pieces.
#[no_mangle]
pub unsafe extern "C" fn fil_generate_data_commitment(
    registered_proof: fil_RegisteredSealProof,
    pieces_ptr: *const fil_PublicPieceInfo,
    pieces_len: libc::size_t,
) -> *mut fil_GenerateDataCommitmentResponse {
    catch_panic_response(|| {
        init_log();

        info!("generate_data_commitment: start");

        let public_pieces: Vec<PieceInfo> = from_raw_parts(pieces_ptr, pieces_len)
            .iter()
            .cloned()
            .map(Into::into)
            .collect();

        let result =
            filecoin_proofs_api::seal::compute_comm_d(registered_proof.into(), &public_pieces);

        let mut response = fil_GenerateDataCommitmentResponse::default();

        match result {
            Ok(commitment) => {
                response.status_code = FCPResponseStatus::FCPNoError;
                response.comm_d = commitment;
            }
            Err(err) => {
                response.status_code = FCPResponseStatus::FCPUnclassifiedError;
                response.error_msg = rust_str_to_c_str(format!("{:?}", err));
            }
        }

        info!("generate_data_commitment: finish");

        raw_ptr(response)
    })
}

#[no_mangle]
pub unsafe extern "C" fn fil_clear_cache(
    cache_dir_path: *const libc::c_char,
) -> *mut fil_ClearCacheResponse {
    catch_panic_response(|| {
        init_log();

        let result = filecoin_proofs_api::seal::clear_cache(&c_str_to_pbuf(cache_dir_path));

        let mut response = fil_ClearCacheResponse::default();

        match result {
            Ok(_) => {
                response.status_code = FCPResponseStatus::FCPNoError;
            }
            Err(err) => {
                response.status_code = FCPResponseStatus::FCPUnclassifiedError;
                response.error_msg = rust_str_to_c_str(format!("{:?}", err));
            }
        };

        raw_ptr(response)
    })
}

/// TODO: document
///
#[no_mangle]
pub unsafe extern "C" fn fil_generate_candidates(
    randomness: fil_32ByteArray,
    challenge_count: u64,
    replicas_ptr: *const fil_PrivateReplicaInfo,
    replicas_len: libc::size_t,
    prover_id: fil_32ByteArray,
) -> *mut fil_GenerateCandidatesResponse {
    catch_panic_response(|| {
        init_log();

        info!("generate_candidates: start");

        let mut response = fil_GenerateCandidatesResponse::default();

        let result = to_private_replica_info_map(replicas_ptr, replicas_len).and_then(|rs| {
            filecoin_proofs_api::post::generate_candidates(
                &randomness.inner,
                challenge_count,
                &rs,
                prover_id.inner,
            )
        });

        match result {
            Ok(output) => {
                let mapped: Vec<fil_Candidate> = output
                    .iter()
                    .map(|x| fil_Candidate {
                        sector_id: x.sector_id.into(),
                        partial_ticket: bls_12_fr_into_bytes(x.partial_ticket),
                        ticket: x.ticket,
                        sector_challenge_index: x.sector_challenge_index,
                    })
                    .collect();

                response.status_code = FCPResponseStatus::FCPNoError;
                response.candidates_ptr = mapped.as_ptr();
                response.candidates_len = mapped.len();
                mem::forget(mapped);
            }
            Err(err) => {
                response.status_code = FCPResponseStatus::FCPUnclassifiedError;
                response.error_msg = rust_str_to_c_str(format!("{:?}", err));
            }
        }

        info!("generate_candidates: finish");

        raw_ptr(response)
    })
}

/// TODO: document
///
#[no_mangle]
pub unsafe extern "C" fn fil_generate_post(
    randomness: fil_32ByteArray,
    replicas_ptr: *const fil_PrivateReplicaInfo,
    replicas_len: libc::size_t,
    winners_ptr: *const fil_Candidate,
    winners_len: libc::size_t,
    prover_id: fil_32ByteArray,
) -> *mut fil_GeneratePoStResponse {
    catch_panic_response(|| {
        init_log();

        info!("generate_post: start");

        let mut response = fil_GeneratePoStResponse::default();

        let result = to_private_replica_info_map(replicas_ptr, replicas_len).and_then(|rs| {
            filecoin_proofs_api::post::generate_post(
                &randomness.inner,
                &rs,
                c_to_rust_candidates(winners_ptr, winners_len)?,
                prover_id.inner,
            )
        });

        match result {
            Ok(output) => {
                let mapped: Vec<fil_PoStProof> = output
                    .iter()
                    .cloned()
                    .map(|(t, proof)| {
                        let out = fil_PoStProof {
                            registered_proof: (t).into(),
                            proof_len: proof.len(),
                            proof_ptr: proof.as_ptr(),
                        };

                        mem::forget(proof);

                        out
                    })
                    .collect();

                response.status_code = FCPResponseStatus::FCPNoError;
                response.proofs_ptr = mapped.as_ptr();
                response.proofs_len = mapped.len();
                mem::forget(mapped);
            }
            Err(err) => {
                response.status_code = FCPResponseStatus::FCPUnclassifiedError;
                response.error_msg = rust_str_to_c_str(format!("{:?}", err));
            }
        }

        info!("generate_post: finish");

        raw_ptr(response)
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
pub unsafe extern "C" fn fil_destroy_unseal_response(ptr: *mut fil_UnsealResponse) {
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
///
#[no_mangle]
pub unsafe extern "C" fn fil_get_max_user_bytes_per_staged_sector(
    registered_proof: fil_RegisteredSealProof,
) -> u64 {
    u64::from(UnpaddedBytesAmount::from(
        RegisteredSealProof::from(registered_proof).sector_size(),
    ))
}

/// Returns the CID of the Groth parameter file for sealing.
///
#[no_mangle]
pub unsafe extern "C" fn fil_get_seal_params_cid(
    registered_proof: fil_RegisteredSealProof,
) -> *mut fil_StringResponse {
    registered_seal_proof_accessor(registered_proof, RegisteredSealProof::params_cid)
}

/// Returns the CID of the verifying key-file for verifying a seal proof.
///
#[no_mangle]
pub unsafe extern "C" fn fil_get_seal_verifying_key_cid(
    registered_proof: fil_RegisteredSealProof,
) -> *mut fil_StringResponse {
    registered_seal_proof_accessor(registered_proof, RegisteredSealProof::verifying_key_cid)
}

/// Returns the path from which the proofs library expects to find the Groth
/// parameter file used when sealing.
///
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
///
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
///
#[no_mangle]
pub unsafe extern "C" fn fil_get_seal_circuit_identifier(
    registered_proof: fil_RegisteredSealProof,
) -> *mut fil_StringResponse {
    registered_seal_proof_accessor(registered_proof, RegisteredSealProof::circuit_identifier)
}

/// Returns the version of the provided seal proof type.
///
#[no_mangle]
pub unsafe extern "C" fn fil_get_seal_version(
    registered_proof: fil_RegisteredSealProof,
) -> *mut fil_StringResponse {
    registered_seal_proof_accessor(registered_proof, |p| Ok(format!("{:?}", p)))
}

/// Returns the CID of the Groth parameter file for generating a PoSt.
///
#[no_mangle]
pub unsafe extern "C" fn fil_get_post_params_cid(
    registered_proof: fil_RegisteredPoStProof,
) -> *mut fil_StringResponse {
    registered_post_proof_accessor(registered_proof, RegisteredPoStProof::params_cid)
}

/// Returns the CID of the verifying key-file for verifying a PoSt proof.
///
#[no_mangle]
pub unsafe extern "C" fn fil_get_post_verifying_key_cid(
    registered_proof: fil_RegisteredPoStProof,
) -> *mut fil_StringResponse {
    registered_post_proof_accessor(registered_proof, RegisteredPoStProof::verifying_key_cid)
}

/// Returns the path from which the proofs library expects to find the Groth
/// parameter file used when generating a PoSt.
///
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
///
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
///
#[no_mangle]
pub unsafe extern "C" fn fil_get_post_circuit_identifier(
    registered_proof: fil_RegisteredPoStProof,
) -> *mut fil_StringResponse {
    registered_post_proof_accessor(registered_proof, RegisteredPoStProof::circuit_identifier)
}

/// Returns the version of the provided seal proof.
///
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
    let mut response = fil_StringResponse::default();

    let rsp: RegisteredSealProof = registered_proof.into();

    match op(rsp) {
        Ok(s) => {
            response.status_code = FCPResponseStatus::FCPNoError;
            response.string_val = rust_str_to_c_str(s);
        }
        Err(err) => {
            response.status_code = FCPResponseStatus::FCPUnclassifiedError;
            response.error_msg = rust_str_to_c_str(format!("{:?}", err));
        }
    }

    raw_ptr(response)
}

unsafe fn registered_post_proof_accessor(
    registered_proof: fil_RegisteredPoStProof,
    op: fn(RegisteredPoStProof) -> anyhow::Result<String>,
) -> *mut fil_StringResponse {
    let mut response = fil_StringResponse::default();

    let rsp: RegisteredPoStProof = registered_proof.into();

    match op(rsp) {
        Ok(s) => {
            response.status_code = FCPResponseStatus::FCPNoError;
            response.string_val = rust_str_to_c_str(s);
        }
        Err(err) => {
            response.status_code = FCPResponseStatus::FCPUnclassifiedError;
            response.error_msg = rust_str_to_c_str(format!("{:?}", err));
        }
    }

    raw_ptr(response)
}

/// Deallocates a VerifySealResponse.
///
#[no_mangle]
pub unsafe extern "C" fn fil_destroy_verify_seal_response(ptr: *mut fil_VerifySealResponse) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_finalize_ticket_response(
    ptr: *mut fil_FinalizeTicketResponse,
) {
    let _ = Box::from_raw(ptr);
}

/// Deallocates a VerifyPoStResponse.
///
#[no_mangle]
pub unsafe extern "C" fn fil_destroy_verify_post_response(ptr: *mut fil_VerifyPoStResponse) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_generate_post_response(ptr: *mut fil_GeneratePoStResponse) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_generate_candidates_response(
    ptr: *mut fil_GenerateCandidatesResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_clear_cache_response(ptr: *mut fil_ClearCacheResponse) {
    let _ = Box::from_raw(ptr);
}

/// Protects the init off the logger.
static LOG_INIT: Once = Once::new();

/// Ensures the logger is initialized.
fn init_log() {
    LOG_INIT.call_once(|| {
        fil_logger::init();
    });
}

#[cfg(test)]
pub mod tests {
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::io::IntoRawFd;

    use anyhow::Result;
    use ffi_toolkit::{c_str_to_rust_str, FCPResponseStatus};
    use rand::{thread_rng, Rng};

    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_write_with_and_without_alignment() -> Result<()> {
        let registered_proof = fil_RegisteredSealProof::StackedDrg2KiBV1;

        // write some bytes to a temp file to be used as the byte source
        let mut rng = thread_rng();
        let buf: Vec<u8> = (0..508).map(|_| rng.gen()).collect();

        // first temp file occupies 4 nodes in a merkle tree built over the
        // destination (after preprocessing)
        let mut src_file_a = tempfile::tempfile()?;
        let _ = src_file_a.write_all(&buf[0..127])?;
        src_file_a.seek(SeekFrom::Start(0))?;

        // second occupies 16 nodes
        let mut src_file_b = tempfile::tempfile()?;
        let _ = src_file_b.write_all(&buf[0..508])?;
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
                let msg = c_str_to_rust_str((*resp).error_msg);
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

            let resp = fil_write_with_alignment(
                registered_proof,
                src_fd_b,
                508,
                dst_fd,
                existing.as_ptr(),
                existing.len(),
            );

            if (*resp).status_code != FCPResponseStatus::FCPNoError {
                let msg = c_str_to_rust_str((*resp).error_msg);
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
    fn test_proof_types() -> Result<()> {
        let seal_types = vec![
            fil_RegisteredSealProof::StackedDrg2KiBV1,
            fil_RegisteredSealProof::StackedDrg8MiBV1,
            fil_RegisteredSealProof::StackedDrg512MiBV1,
            fil_RegisteredSealProof::StackedDrg32GiBV1,
        ];

        let post_types = vec![
            fil_RegisteredPoStProof::StackedDrg2KiBV1,
            fil_RegisteredPoStProof::StackedDrg8MiBV1,
            fil_RegisteredPoStProof::StackedDrg512MiBV1,
            fil_RegisteredPoStProof::StackedDrg32GiBV1,
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
                    c_str_to_rust_str((*r).error_msg)
                );

                let x = CString::from_raw((*r).string_val as *mut libc::c_char);
                let y = x.into_string().unwrap_or(String::from(""));

                assert!(y.len() > 0);

                fil_destroy_string_response(r);
            }
        }

        Ok(())
    }

    #[test]
    fn test_sealing() -> Result<()> {
        let wrap = |x| fil_32ByteArray { inner: x };

        // miscellaneous setup and shared values
        let registered_proof_seal = fil_RegisteredSealProof::StackedDrg2KiBV1;
        let registered_proof_post = fil_RegisteredPoStProof::StackedDrg2KiBV1;

        let cache_dir = tempfile::tempdir()?;
        let cache_dir_path = cache_dir.into_path();

        let challenge_count = 2;
        let prover_id = fil_32ByteArray { inner: [1u8; 32] };
        let randomness = fil_32ByteArray { inner: [7u8; 32] };
        let sector_id = 42;
        let seed = fil_32ByteArray { inner: [5u8; 32] };
        let ticket = fil_32ByteArray { inner: [6u8; 32] };

        // create a byte source (a user's piece)
        let mut rng = thread_rng();
        let buf_a: Vec<u8> = (0..2032).map(|_| rng.gen()).collect();

        let mut piece_file_a = tempfile::tempfile()?;
        let _ = piece_file_a.write_all(&buf_a[0..127])?;
        piece_file_a.seek(SeekFrom::Start(0))?;

        let mut piece_file_b = tempfile::tempfile()?;
        let _ = piece_file_b.write_all(&buf_a[0..1016])?;
        piece_file_b.seek(SeekFrom::Start(0))?;

        // create the staged sector (the byte destination)
        let (staged_file, staged_path) = tempfile::NamedTempFile::new()?.keep()?;

        // create a temp file to be used as the byte destination
        let (_, sealed_path) = tempfile::NamedTempFile::new()?.keep()?;

        // last temp file is used to output unsealed bytes
        let (_, unseal_path) = tempfile::NamedTempFile::new()?.keep()?;

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
                let msg = c_str_to_rust_str((*resp_a1).error_msg);
                panic!("write_without_alignment failed: {:?}", msg);
            }

            let existing_piece_sizes = vec![127];

            let resp_a2 = fil_write_with_alignment(
                registered_proof_seal,
                piece_file_b_fd,
                1016,
                staged_sector_fd,
                existing_piece_sizes.as_ptr(),
                existing_piece_sizes.len(),
            );

            if (*resp_a2).status_code != FCPResponseStatus::FCPNoError {
                let msg = c_str_to_rust_str((*resp_a2).error_msg);
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
            ];

            let resp_x =
                fil_generate_data_commitment(registered_proof_seal, pieces.as_ptr(), pieces.len());

            if (*resp_x).status_code != FCPResponseStatus::FCPNoError {
                let msg = c_str_to_rust_str((*resp_x).error_msg);
                panic!("generate_data_commitment failed: {:?}", msg);
            }

            let cache_dir_path_c_str = rust_str_to_c_str(cache_dir_path.to_str().unwrap());
            let staged_path_c_str = rust_str_to_c_str(staged_path.to_str().unwrap());
            let replica_path_c_str = rust_str_to_c_str(sealed_path.to_str().unwrap());
            let unseal_path_c_str = rust_str_to_c_str(unseal_path.to_str().unwrap());

            let resp_b1 = fil_seal_pre_commit_phase1(
                registered_proof_seal,
                cache_dir_path_c_str,
                staged_path_c_str,
                replica_path_c_str,
                sector_id,
                prover_id.clone(),
                ticket,
                pieces.as_ptr(),
                pieces.len(),
            );

            if (*resp_b1).status_code != FCPResponseStatus::FCPNoError {
                let msg = c_str_to_rust_str((*resp_b1).error_msg);
                panic!("seal_pre_commit_phase1 failed: {:?}", msg);
            }

            let resp_b2 = fil_seal_pre_commit_phase2(
                (*resp_b1).seal_pre_commit_phase1_output_ptr,
                (*resp_b1).seal_pre_commit_phase1_output_len,
                cache_dir_path_c_str,
                replica_path_c_str,
            );

            if (*resp_b2).status_code != FCPResponseStatus::FCPNoError {
                let msg = c_str_to_rust_str((*resp_b2).error_msg);
                panic!("seal_pre_commit_phase2 failed: {:?}", msg);
            }

            let pre_computed_comm_d = &(*resp_x).comm_d;
            let pre_commit_comm_d = &(*resp_b2).comm_d;

            assert_eq!(
                format!("{:x?}", &pre_computed_comm_d),
                format!("{:x?}", &pre_commit_comm_d),
                "pre-computed CommD and pre-commit CommD don't match"
            );

            let resp_c1 = fil_seal_commit_phase1(
                registered_proof_seal,
                wrap((*resp_b2).comm_r),
                wrap((*resp_b2).comm_d),
                cache_dir_path_c_str,
                replica_path_c_str,
                sector_id,
                prover_id,
                ticket,
                seed,
                pieces.as_ptr(),
                pieces.len(),
            );

            if (*resp_c1).status_code != FCPResponseStatus::FCPNoError {
                let msg = c_str_to_rust_str((*resp_c1).error_msg);
                panic!("seal_commit_phase1 failed: {:?}", msg);
            }

            let resp_c2 = fil_seal_commit_phase2(
                (*resp_c1).seal_commit_phase1_output_ptr,
                (*resp_c1).seal_commit_phase1_output_len,
                sector_id,
                prover_id,
            );

            if (*resp_c2).status_code != FCPResponseStatus::FCPNoError {
                let msg = c_str_to_rust_str((*resp_c2).error_msg);
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
                (*resp_c2).proof_ptr,
                (*resp_c2).proof_len,
            );

            if (*resp_d).status_code != FCPResponseStatus::FCPNoError {
                let msg = c_str_to_rust_str((*resp_d).error_msg);
                panic!("seal_commit failed: {:?}", msg);
            }

            assert!((*resp_d).is_valid, "proof was not valid");

            let resp_e = fil_unseal(
                registered_proof_seal,
                cache_dir_path_c_str,
                replica_path_c_str,
                unseal_path_c_str,
                sector_id,
                prover_id,
                ticket,
                wrap((*resp_b2).comm_d),
            );

            if (*resp_e).status_code != FCPResponseStatus::FCPNoError {
                let msg = c_str_to_rust_str((*resp_e).error_msg);
                panic!("unseal failed: {:?}", msg);
            }

            // ensure unsealed bytes match what we had in our piece
            let mut buf_b = Vec::with_capacity(2032);
            let mut f = std::fs::File::open(unseal_path)?;
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

            let private_replicas = vec![fil_PrivateReplicaInfo {
                registered_proof: registered_proof_post,
                cache_dir_path: cache_dir_path_c_str,
                comm_r: (*resp_b2).comm_r,
                replica_path: replica_path_c_str,
                sector_id,
            }];

            let resp_f = fil_generate_candidates(
                randomness,
                challenge_count,
                private_replicas.as_ptr(),
                private_replicas.len(),
                prover_id,
            );

            if (*resp_f).status_code != FCPResponseStatus::FCPNoError {
                let msg = c_str_to_rust_str((*resp_f).error_msg);
                panic!("generate_candidates failed: {:?}", msg);
            }

            // exercise the ticket-finalizing code path (but don't do anything
            // with the results
            let result = c_to_rust_candidates((*resp_f).candidates_ptr, (*resp_f).candidates_len)?;
            if result.len() < 1 {
                panic!("generate_candidates produced no results");
            }

            let resp_g = fil_finalize_ticket(fil_32ByteArray {
                inner: bls_12_fr_into_bytes(result[0].partial_ticket),
            });
            if (*resp_g).status_code != FCPResponseStatus::FCPNoError {
                let msg = c_str_to_rust_str((*resp_g).error_msg);
                panic!("finalize_ticket failed: {:?}", msg);
            }

            let resp_h = fil_generate_post(
                randomness,
                private_replicas.as_ptr(),
                private_replicas.len(),
                (*resp_f).candidates_ptr,
                (*resp_f).candidates_len,
                prover_id,
            );

            if (*resp_h).status_code != FCPResponseStatus::FCPNoError {
                let msg = c_str_to_rust_str((*resp_h).error_msg);
                panic!("generate_post failed: {:?}", msg);
            }
            let public_replicas = vec![fil_PublicReplicaInfo {
                registered_proof: registered_proof_post,
                sector_id,
                comm_r: (*resp_b2).comm_r,
            }];

            let resp_i = fil_verify_post(
                randomness,
                challenge_count,
                public_replicas.as_ptr(),
                public_replicas.len(),
                (*resp_h).proofs_ptr,
                (*resp_h).proofs_len,
                (*resp_f).candidates_ptr,
                (*resp_f).candidates_len,
                prover_id,
            );

            if (*resp_i).status_code != FCPResponseStatus::FCPNoError {
                let msg = c_str_to_rust_str((*resp_i).error_msg);
                panic!("verify_post failed: {:?}", msg);
            }

            if !(*resp_i).is_valid {
                panic!("verify_post rejected the provided proof as invalid");
            }

            fil_destroy_write_without_alignment_response(resp_a1);
            fil_destroy_write_with_alignment_response(resp_a2);
            fil_destroy_generate_data_commitment_response(resp_x);
            fil_destroy_seal_pre_commit_phase1_response(resp_b1);
            fil_destroy_seal_pre_commit_phase2_response(resp_b2);
            fil_destroy_seal_commit_phase1_response(resp_c1);
            fil_destroy_seal_commit_phase2_response(resp_c2);
            fil_destroy_verify_seal_response(resp_d);
            fil_destroy_unseal_response(resp_e);
            fil_destroy_generate_candidates_response(resp_f);
            fil_destroy_finalize_ticket_response(resp_g);
            fil_destroy_generate_post_response(resp_h);
            fil_destroy_verify_post_response(resp_i);

            c_str_to_rust_str(cache_dir_path_c_str);
            c_str_to_rust_str(staged_path_c_str);
            c_str_to_rust_str(replica_path_c_str);
            c_str_to_rust_str(unseal_path_c_str);
        }

        Ok(())
    }
}
