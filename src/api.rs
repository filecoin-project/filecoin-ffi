use std::slice::from_raw_parts;

use ffi_toolkit::{catch_panic_response, raw_ptr, rust_str_to_c_str, FCPResponseStatus};
use filecoin_proofs as api_fns;
use filecoin_proofs::{
    types as api_types, PieceInfo, PoRepConfig, PoRepProofPartitions, SectorSize,
    UnpaddedBytesAmount,
};
use libc;
use once_cell::sync::OnceCell;
use storage_proofs::sector::SectorId;

use crate::helpers;
use crate::responses::*;

#[repr(C)]
#[derive(Clone)]
pub struct FFIPublicPieceInfo {
    pub num_bytes: u64,
    pub comm_p: [u8; 32],
}

impl From<FFIPublicPieceInfo> for PieceInfo {
    fn from(x: FFIPublicPieceInfo) -> Self {
        let FFIPublicPieceInfo { num_bytes, comm_p } = x;
        PieceInfo {
            commitment: comm_p,
            size: UnpaddedBytesAmount(num_bytes),
        }
    }
}

/// Verifies the output of seal.
///
#[no_mangle]
pub unsafe extern "C" fn verify_seal(
    sector_size: u64,
    comm_r: &[u8; 32],
    comm_d: &[u8; 32],
    prover_id: &[u8; 32],
    ticket: &[u8; 32],
    seed: &[u8; 32],
    sector_id: u64,
    proof_ptr: *const u8,
    proof_len: libc::size_t,
) -> *mut VerifySealResponse {
    catch_panic_response(|| {
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
                    *seed,
                    &bs,
                )
            })
        });

        let mut response = VerifySealResponse::default();

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
                response.error_msg = rust_str_to_c_str(format!("{}", err));
            }
        };

        info!("verify_seal: finish");

        raw_ptr(response)
    })
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
    catch_panic_response(|| {
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
                response.status_code = FCPResponseStatus::FCPNoError;
                response.is_valid = is_valid;
            }
            Err(err) => {
                response.status_code = FCPResponseStatus::FCPUnclassifiedError;
                response.error_msg = rust_str_to_c_str(format!("{}", err));
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
pub unsafe extern "C" fn generate_piece_commitment(
    piece_fd_raw: libc::c_int,
    unpadded_piece_size: u64,
) -> *mut GeneratePieceCommitmentResponse {
    catch_panic_response(|| {
        init_log();

        use std::os::unix::io::{FromRawFd, IntoRawFd};

        let mut piece_file = std::fs::File::from_raw_fd(piece_fd_raw);

        let unpadded_piece_size = api_types::UnpaddedBytesAmount(unpadded_piece_size);

        let result = api_fns::generate_piece_commitment(&mut piece_file, unpadded_piece_size);

        // avoid dropping the File which closes it
        let _ = piece_file.into_raw_fd();

        let mut response = GeneratePieceCommitmentResponse::default();

        match result {
            Ok(meta) => {
                response.status_code = FCPResponseStatus::FCPNoError;
                response.comm_p = meta.commitment;
                response.num_bytes_aligned = meta.size.into();
            }
            Err(err) => {
                response.status_code = FCPResponseStatus::FCPUnclassifiedError;
                response.error_msg = rust_str_to_c_str(format!("{}", err));
            }
        }

        raw_ptr(response)
    })
}

/// Returns the merkle root for a sector containing the provided pieces.
#[no_mangle]
pub unsafe extern "C" fn generate_data_commitment(
    sector_size: u64,
    pieces_ptr: *const FFIPublicPieceInfo,
    pieces_len: libc::size_t,
) -> *mut GenerateDataCommitmentResponse {
    catch_panic_response(|| {
        init_log();

        let public_pieces: Vec<PieceInfo> = from_raw_parts(pieces_ptr, pieces_len)
            .iter()
            .cloned()
            .map(Into::into)
            .collect();

        let result = api_fns::compute_comm_d(
            PoRepConfig(SectorSize(sector_size), PoRepProofPartitions(0)),
            &public_pieces,
        );

        let mut response = GenerateDataCommitmentResponse::default();

        match result {
            Ok(commitment) => {
                response.status_code = FCPResponseStatus::FCPNoError;
                response.comm_d = commitment;
            }
            Err(err) => {
                response.status_code = FCPResponseStatus::FCPUnclassifiedError;
                response.error_msg = rust_str_to_c_str(format!("{}", err));
            }
        }

        raw_ptr(response)
    })
}

#[no_mangle]
pub unsafe extern "C" fn destroy_generate_piece_commitment_response(
    ptr: *mut GeneratePieceCommitmentResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn destroy_generate_data_commitment_response(
    ptr: *mut GenerateDataCommitmentResponse,
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
