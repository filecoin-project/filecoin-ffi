use std::slice::from_raw_parts;

use ffi_toolkit::{raw_ptr, rust_str_to_c_str};
use filecoin_proofs as api_fns;
use filecoin_proofs::types as api_types;
use libc;
use once_cell::sync::OnceCell;

use crate::helpers;
use crate::responses::*;
use storage_proofs::sector::SectorId;

/// Verifies the output of seal.
///
#[no_mangle]
pub unsafe extern "C" fn verify_seal(
    sector_size: u64,
    comm_r: &[u8; 32],
    comm_d: &[u8; 32],
    prover_id: &[u8; 32],
    ticket: &[u8; 32],
    sector_id: u64,
    proof_ptr: *const u8,
    proof_len: libc::size_t,
) -> *mut VerifySealResponse {
    init_log();

    info!("verify_seal: start");

    let porep_bytes = helpers::try_into_porep_proof_bytes(proof_ptr, proof_len);

    let result = porep_bytes.and_then(|bs| {
        helpers::porep_proof_partitions_try_from_bytes(&bs).and_then(|ppp| {
            let cfg = api_types::PoRepConfig(api_types::SectorSize(sector_size), ppp);

            api_fns::verify_seal(
                cfg,
                *comm_r,
                *comm_d,
                *prover_id,
                SectorId::from(sector_id),
                *ticket,
                &bs,
            )
        })
    });

    let mut response = VerifySealResponse::default();

    match result {
        Ok(true) => {
            response.status_code = 0;
            response.is_valid = true;
        }
        Ok(false) => {
            response.status_code = 0;
            response.is_valid = false;
        }
        Err(err) => {
            response.status_code = 1;
            response.error_msg = rust_str_to_c_str(format!("{}", err));
        }
    };

    info!("verify_seal: finish");

    raw_ptr(response)
}

/// Verifies that a proof-of-spacetime is valid.
///
#[no_mangle]
pub unsafe extern "C" fn verify_post(
    sector_size: u64,
    challenge_seed: &[u8; 32],
    sector_ids_ptr: *const u64,
    sector_ids_len: libc::size_t,
    faulty_sector_ids_ptr: *const u64,
    faulty_sector_ids_len: libc::size_t,
    flattened_comm_rs_ptr: *const u8,
    flattened_comm_rs_len: libc::size_t,
    proof_ptr: *const u8,
    proof_len: libc::size_t,
) -> *mut VerifyPoStResponse {
    init_log();

    info!("verify_post: start");

    let mut response = VerifyPoStResponse::default();

    let convert = helpers::to_public_replica_info_map(
        sector_ids_ptr,
        sector_ids_len,
        flattened_comm_rs_ptr,
        flattened_comm_rs_len,
        faulty_sector_ids_ptr,
        faulty_sector_ids_len,
    );

    let result = convert.and_then(|map| {
        ensure!(!proof_ptr.is_null(), "proof_ptr must not be null");

        api_fns::verify_post(
            api_types::PoStConfig(api_types::SectorSize(sector_size)),
            challenge_seed,
            from_raw_parts(proof_ptr, proof_len),
            &map,
        )
    });

    match result {
        Ok(is_valid) => {
            response.status_code = 0;
            response.is_valid = is_valid;
        }
        Err(err) => {
            response.status_code = 1;
            response.error_msg = rust_str_to_c_str(format!("{}", err));
        }
    };

    info!("verify_post: {}", "finish");
    raw_ptr(response)
}

/// Verifies that a piece inclusion proof is valid for a given merkle root, piece root, padded and
/// aligned piece size, and tree size.
#[no_mangle]
pub unsafe extern "C" fn verify_piece_inclusion_proof(
    comm_d: &[u8; 32],
    comm_p: &[u8; 32],
    piece_inclusion_proof_ptr: *const u8,
    piece_inclusion_proof_len: libc::size_t,
    unpadded_piece_size: u64,
    sector_size: u64,
) -> *mut VerifyPieceInclusionProofResponse {
    init_log();

    info!("verify_piece_inclusion_proof: {}", "start");

    let bytes = Ok(()).and_then(|_| {
        ensure!(
            !piece_inclusion_proof_ptr.is_null(),
            "piece_inclusion_proof_ptr must not be null"
        );
        Ok(from_raw_parts(
            piece_inclusion_proof_ptr,
            piece_inclusion_proof_len,
        ))
    });

    let unpadded_piece_size = api_types::UnpaddedBytesAmount(unpadded_piece_size);
    let sector_size = api_types::SectorSize(sector_size);

    let result = bytes.and_then(|bytes| {
        api_fns::verify_piece_inclusion_proof(
            bytes,
            comm_d,
            comm_p,
            unpadded_piece_size,
            sector_size,
        )
    });

    let mut response = VerifyPieceInclusionProofResponse::default();

    match result {
        Ok(true) => {
            response.status_code = 0;
            response.is_valid = true;
        }
        Ok(false) => {
            response.status_code = 0;
            response.is_valid = false;
        }
        Err(err) => {
            response.status_code = 1;
            response.error_msg = rust_str_to_c_str(format!("{}", err));
        }
    };

    info!("verify_piece_inclusion_proof: {}", "finish");

    raw_ptr(response)
}

#[no_mangle]
pub unsafe extern "C" fn destroy_verify_piece_inclusion_proof_response(
    ptr: *mut VerifyPieceInclusionProofResponse,
) {
    let _ = Box::from_raw(ptr);
}

/// Returns the merkle root for a piece after piece padding and alignment.
/// The caller is responsible for closing the passed in file descriptor.
#[no_mangle]
#[cfg(not(target_os = "windows"))]
pub unsafe extern "C" fn generate_piece_commitment(
    piece_fd_raw: libc::c_int,
    unpadded_piece_size: u64,
) -> *mut GeneratePieceCommitmentResponse {
    init_log();

    use std::os::unix::io::{FromRawFd, IntoRawFd};

    let mut piece_file = std::fs::File::from_raw_fd(piece_fd_raw);

    let unpadded_piece_size = api_types::UnpaddedBytesAmount(unpadded_piece_size);

    let result = api_fns::generate_piece_commitment(&mut piece_file, unpadded_piece_size);

    // avoid dropping the File which closes it
    let _ = piece_file.into_raw_fd();

    let mut response = GeneratePieceCommitmentResponse::default();

    match result {
        Ok(comm_p) => {
            response.status_code = 0;
            response.comm_p = comm_p;
        }
        Err(err) => {
            response.status_code = 1;
            response.error_msg = rust_str_to_c_str(format!("{}", err));
        }
    }

    raw_ptr(response)
}

#[no_mangle]
pub unsafe extern "C" fn destroy_generate_piece_commitment_response(
    ptr: *mut GeneratePieceCommitmentResponse,
) {
    let _ = Box::from_raw(ptr);
}

/// Returns the number of user bytes that will fit into a staged sector.
///
#[no_mangle]
pub unsafe extern "C" fn get_max_user_bytes_per_staged_sector(sector_size: u64) -> u64 {
    u64::from(api_types::UnpaddedBytesAmount::from(api_types::SectorSize(
        sector_size,
    )))
}

/// Deallocates a VerifySealResponse.
///
#[no_mangle]
pub unsafe extern "C" fn destroy_verify_seal_response(ptr: *mut VerifySealResponse) {
    let _ = Box::from_raw(ptr);
}

/// Deallocates a VerifyPoStResponse.
///
#[no_mangle]
pub unsafe extern "C" fn destroy_verify_post_response(ptr: *mut VerifyPoStResponse) {
    let _ = Box::from_raw(ptr);
}

/// Protects the init off the logger.
static LOG_INIT: OnceCell<bool> = OnceCell::new();

/// Ensures the logger is initialized.
fn init_log() {
    LOG_INIT.get_or_init(|| {
        let _ = pretty_env_logger::try_init_timed();
        true
    });
}
