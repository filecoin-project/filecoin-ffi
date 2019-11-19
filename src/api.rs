use std::collections::HashMap;
use std::slice::from_raw_parts;
use std::sync::Mutex;

use ffi_toolkit::{
    c_str_to_pbuf, catch_panic_response, raw_ptr, rust_str_to_c_str, FCPResponseStatus,
};
use filecoin_proofs as api_fns;
use filecoin_proofs::{
    types as api_types, Candidate, PaddedBytesAmount, PieceInfo, PoRepConfig, PoRepProofPartitions,
    SectorClass, SectorSize, UnpaddedByteIndex, UnpaddedBytesAmount,
};
use libc;
use once_cell::sync::{Lazy, OnceCell};
use storage_proofs::hasher::Domain;
use storage_proofs::sector::SectorId;

use crate::helpers;
use crate::types::*;
use std::mem;
use storage_proofs::hasher::pedersen::PedersenDomain;

static TEMPORAY_AUX_MAP: Lazy<Mutex<HashMap<u64, api_types::TemporaryAux>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// TODO: document
///
#[no_mangle]
#[cfg(not(target_os = "windows"))]
pub unsafe extern "C" fn write_with_alignment(
    src_fd: libc::c_int,
    src_size: u64,
    dst_fd: libc::c_int,
    existing_piece_sizes_ptr: *const u64,
    existing_piece_sizes_len: libc::size_t,
) -> *mut WriteWithAlignmentResponse {
    catch_panic_response(|| {
        init_log();

        info!("write_with_alignment: start");

        let mut response = WriteWithAlignmentResponse::default();

        let piece_sizes: Vec<UnpaddedBytesAmount> =
            from_raw_parts(existing_piece_sizes_ptr, existing_piece_sizes_len)
                .iter()
                .map(|n| UnpaddedBytesAmount(*n))
                .collect();

        let n = UnpaddedBytesAmount(src_size);

        match api_fns::add_piece(
            FileDescriptorRef::new(src_fd),
            FileDescriptorRef::new(dst_fd),
            n,
            &piece_sizes,
        ) {
            Ok((aligned_bytes_written, comm_p)) => {
                response.comm_p = comm_p;
                response.left_alignment_unpadded = (aligned_bytes_written - n).into();
                response.status_code = FCPResponseStatus::FCPNoError;
                response.total_write_unpadded = aligned_bytes_written.into();
            }
            Err(err) => {
                response.status_code = FCPResponseStatus::FCPUnclassifiedError;
                response.error_msg = rust_str_to_c_str(format!("{}", err));
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
pub unsafe extern "C" fn write_without_alignment(
    src_fd: libc::c_int,
    src_size: u64,
    dst_fd: libc::c_int,
) -> *mut WriteWithoutAlignmentResponse {
    catch_panic_response(|| {
        init_log();

        info!("write_without_alignment: start");

        let mut response = WriteWithoutAlignmentResponse::default();

        match api_fns::write_and_preprocess(
            FileDescriptorRef::new(src_fd),
            FileDescriptorRef::new(dst_fd),
            UnpaddedBytesAmount(src_size),
        ) {
            Ok((total_bytes_written, comm_p)) => {
                response.comm_p = comm_p;
                response.status_code = FCPResponseStatus::FCPNoError;
                response.total_write_unpadded = total_bytes_written.into();
            }
            Err(err) => {
                response.status_code = FCPResponseStatus::FCPUnclassifiedError;
                response.error_msg = rust_str_to_c_str(format!("{}", err));
            }
        }

        info!("write_without_alignment: finish");

        raw_ptr(response)
    })
}

/// TODO: document
///
#[no_mangle]
pub unsafe extern "C" fn seal_pre_commit(
    sector_class: FFISectorClass,
    cache_dir_path: *const libc::c_char,
    staged_sector_path: *const libc::c_char,
    sealed_sector_path: *const libc::c_char,
    sector_id: u64,
    prover_id: &[u8; 32],
    ticket: &[u8; 32],
    pieces_ptr: *const FFIPublicPieceInfo,
    pieces_len: libc::size_t,
) -> *mut SealPreCommitResponse {
    catch_panic_response(|| {
        init_log();

        info!("seal_pre_commit: start");

        let mut response = SealPreCommitResponse::default();

        let public_pieces: Vec<PieceInfo> = from_raw_parts(pieces_ptr, pieces_len)
            .iter()
            .cloned()
            .map(Into::into)
            .collect();

        let sc: SectorClass = sector_class.into();

        match api_fns::seal_pre_commit(
            sc.into(),
            c_str_to_pbuf(cache_dir_path),
            c_str_to_pbuf(staged_sector_path),
            c_str_to_pbuf(sealed_sector_path),
            *prover_id,
            SectorId::from(sector_id),
            *ticket,
            &public_pieces,
        ) {
            Ok(output) => {
                response.status_code = FCPResponseStatus::FCPNoError;

                let mut x: FFISealPreCommitOutput = Default::default();
                x.p_aux_comm_c
                    .copy_from_slice(&output.p_aux.comm_c.into_bytes());
                x.p_aux_comm_r_last
                    .copy_from_slice(&output.p_aux.comm_r_last.into_bytes());
                x.comm_r = output.comm_r;
                x.comm_d = output.comm_d;

                response.seal_pre_commit_output = x;

                let warning = "Until the merkle cache is complete, \
                               seal_pre_commit puts TemporaryAux in a \
                               heap-allocated, global, in-memory lookup table. \
                               If this process is killed before seal_commit is \
                               called, TemporaryAux (and the sector) will be \
                               lost. Also, seal_commit must be called from the \
                               same process which called seal_pre_commit.";

                warn!(
                    "seal_pre_commit warning for sector id = {:?}: {:?}",
                    sector_id, warning
                );

                let mut aux_map = TEMPORAY_AUX_MAP
                    .lock()
                    .expect("error acquiring TemporaryAux mutex");

                let _ = aux_map.insert(sector_id, output.t_aux);
            }
            Err(err) => {
                response.status_code = FCPResponseStatus::FCPUnclassifiedError;
                response.error_msg = rust_str_to_c_str(format!("{}", err));
            }
        }

        info!("seal_pre_commit: finish");

        raw_ptr(response)
    })
}

/// TODO: document
///
#[no_mangle]
pub unsafe extern "C" fn seal_commit(
    sector_class: FFISectorClass,
    cache_dir_path: *const libc::c_char,
    sector_id: u64,
    prover_id: &[u8; 32],
    ticket: &[u8; 32],
    seed: &[u8; 32],
    pieces_ptr: *const FFIPublicPieceInfo,
    pieces_len: libc::size_t,
    spco: FFISealPreCommitOutput,
) -> *mut SealCommitResponse {
    catch_panic_response(|| {
        init_log();

        info!("seal_commit: start");

        let mut response = SealCommitResponse::default();

        let t_aux = {
            let mut aux_map = TEMPORAY_AUX_MAP
                .lock()
                .expect("error acquiring TemporaryAux mutex");

            aux_map.remove(&sector_id)
        };

        let comm_r_last = PedersenDomain::try_from_bytes(&spco.p_aux_comm_r_last[..]);
        let comm_c = PedersenDomain::try_from_bytes(&spco.p_aux_comm_c[..]);

        if t_aux.is_none() {
            response.status_code = FCPResponseStatus::FCPUnclassifiedError;
            response.error_msg = rust_str_to_c_str(format!(
                "no TemporaryAux in map for sector id={:?} - has it ben pre-committed yet?",
                sector_id
            ));
            info!("seal_commit: finish");
            return raw_ptr(response);
        }

        if comm_r_last.is_err() {
            response.status_code = FCPResponseStatus::FCPUnclassifiedError;
            response.error_msg = rust_str_to_c_str("cannot xform comm_r_last to PedersenDomain");
            info!("seal_commit: finish");
            return raw_ptr(response);
        }

        if comm_c.is_err() {
            response.status_code = FCPResponseStatus::FCPUnclassifiedError;
            response.error_msg = rust_str_to_c_str("cannot xform comm_c to PedersenDomain");
            info!("seal_commit: finish");
            return raw_ptr(response);
        }

        let spco = api_types::SealPreCommitOutput {
            comm_r: spco.comm_r,
            comm_d: spco.comm_d,
            p_aux: api_types::PersistentAux {
                comm_c: comm_c.unwrap(),
                comm_r_last: comm_r_last.unwrap(),
            },
            t_aux: t_aux.unwrap(),
        };

        let public_pieces: Vec<PieceInfo> = from_raw_parts(pieces_ptr, pieces_len)
            .iter()
            .cloned()
            .map(Into::into)
            .collect();

        let sc: SectorClass = sector_class.into();

        match api_fns::seal_commit(
            sc.into(),
            c_str_to_pbuf(cache_dir_path),
            *prover_id,
            SectorId::from(sector_id),
            *ticket,
            *seed,
            spco,
            &public_pieces,
        ) {
            Ok(output) => {
                response.status_code = FCPResponseStatus::FCPNoError;
                response.proof_ptr = output.proof.as_ptr();
                response.proof_len = output.proof.len();
                mem::forget(output.proof);
            }
            Err(err) => {
                response.status_code = FCPResponseStatus::FCPUnclassifiedError;
                response.error_msg = rust_str_to_c_str(format!("{}", err));
            }
        }

        info!("seal_commit: finish");

        raw_ptr(response)
    })
}

/// TODO: document
///
#[no_mangle]
pub unsafe extern "C" fn unseal(
    sector_class: FFISectorClass,
    sealed_sector_path: *const libc::c_char,
    unseal_output_path: *const libc::c_char,
    sector_id: u64,
    prover_id: &[u8; 32],
    ticket: &[u8; 32],
    comm_d: &[u8; 32],
) -> *mut UnsealResponse {
    catch_panic_response(|| {
        init_log();

        info!("unseal: start");

        let sc: SectorClass = sector_class.clone().into();

        let result = api_fns::get_unsealed_range(
            sc.into(),
            c_str_to_pbuf(sealed_sector_path),
            c_str_to_pbuf(unseal_output_path),
            *prover_id,
            SectorId::from(sector_id),
            *comm_d,
            *ticket,
            UnpaddedByteIndex(0u64),
            UnpaddedBytesAmount::from(PaddedBytesAmount(sector_class.sector_size)),
        );

        let mut response = UnsealResponse::default();

        match result {
            Ok(_) => {
                response.status_code = FCPResponseStatus::FCPNoError;
            }
            Err(err) => {
                response.status_code = FCPResponseStatus::FCPUnclassifiedError;
                response.error_msg = rust_str_to_c_str(format!("{}", err));
            }
        };

        info!("unseal: finish");

        raw_ptr(response)
    })
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

/// Finalize a partial_ticket.
#[no_mangle]
pub unsafe extern "C" fn finalize_ticket(partial_ticket: &[u8; 32]) -> *mut FinalizeTicketResponse {
    catch_panic_response(|| {
        init_log();

        info!("finalize_ticket: start");

        let mut response = FinalizeTicketResponse::default();

        match filecoin_proofs::finalize_ticket(partial_ticket) {
            Ok(ticket) => {
                response.status_code = FCPResponseStatus::FCPNoError;
                response.ticket = ticket;
            }
            Err(err) => {
                response.status_code = FCPResponseStatus::FCPUnclassifiedError;
                response.error_msg = rust_str_to_c_str(format!("{}", err));
            }
        };

        info!("finalize_ticket: finish");

        raw_ptr(response)
    })
}

/// Verifies that a proof-of-spacetime is valid.
#[no_mangle]
pub unsafe extern "C" fn verify_post(
    sector_size: u64,
    randomness: &[u8; 32],
    sector_ids_ptr: *const u64,
    sector_ids_len: libc::size_t,
    flattened_comm_rs_ptr: *const u8,
    flattened_comm_rs_len: libc::size_t,
    flattened_proofs_ptr: *const u8,
    flattened_proofs_len: libc::size_t,
    winners_ptr: *const FFICandidate,
    winners_len: libc::size_t,
    prover_id: &[u8; 32],
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
        );

        let result = convert.and_then(|map| {
            ensure!(
                !flattened_proofs_ptr.is_null(),
                "flattened_proof_ptr must not be null"
            );
            let proofs: Vec<Vec<u8>> = from_raw_parts(flattened_proofs_ptr, flattened_proofs_len)
                .chunks(filecoin_proofs::SINGLE_PARTITION_PROOF_LEN)
                .map(Into::into)
                .collect();

            ensure!(!winners_ptr.is_null(), "winners_ptr must not be null");
            let winners: Vec<Candidate> = from_raw_parts(winners_ptr, winners_len)
                .iter()
                .cloned()
                .map(|c| c.try_into_candidate())
                .collect::<Result<_, _>>()?;

            api_fns::verify_post(
                api_types::PoStConfig(api_types::SectorSize(sector_size)),
                randomness,
                &proofs,
                &map,
                &winners,
                *prover_id,
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
pub unsafe extern "C" fn destroy_write_alignment_response(ptr: *mut WriteWithAlignmentResponse) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn destroy_write_without_alignment_response(
    ptr: *mut WriteWithoutAlignmentResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn destroy_seal_pre_commit_response(ptr: *mut SealPreCommitResponse) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn destroy_seal_commit_response(ptr: *mut SealCommitResponse) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn destroy_unseal_response(ptr: *mut UnsealResponse) {
    let _ = Box::from_raw(ptr);
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

#[no_mangle]
pub unsafe extern "C" fn destroy_finalize_ticket_response(ptr: *mut FinalizeTicketResponse) {
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

#[cfg(test)]
pub mod tests {
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::io::IntoRawFd;

    use ffi_toolkit::{c_str_to_rust_str, FCPResponseStatus};
    use rand::{thread_rng, Rng};

    use super::*;

    #[test]
    fn test_write_with_and_without_alignment() -> Result<(), failure::Error> {
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
            let resp = write_without_alignment(src_fd_a, 127, dst_fd);

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

            let resp =
                write_with_alignment(src_fd_b, 508, dst_fd, existing.as_ptr(), existing.len());

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
    fn test_sealing() -> Result<(), failure::Error> {
        // miscellaneous setup and shared values
        let sector_class = FFISectorClass {
            sector_size: 1024,
            porep_proof_partitions: 2,
        };

        let cache_dir = tempfile::tempdir()?;
        let cache_dir_path = cache_dir.into_path();

        let prover_id = [1u8; 32];
        let sector_id = 42;
        let seed = [5u8; 32];
        let ticket = [6u8; 32];

        // create a byte source (a user's piece)
        let mut rng = thread_rng();
        let buf_a: Vec<u8> = (0..1016).map(|_| rng.gen()).collect();
        let mut piece_file = tempfile::tempfile()?;
        let _ = piece_file.write_all(&buf_a)?;
        piece_file.seek(SeekFrom::Start(0))?;

        // create the staged sector (the byte destination)
        let (staged_file, staged_path) = tempfile::NamedTempFile::new()?.keep()?;

        // create a temp file to be used as the byte destination
        let (_, sealed_path) = tempfile::NamedTempFile::new()?.keep()?;

        // last temp file is used to output unsealed bytes
        let (_, unseal_path) = tempfile::NamedTempFile::new()?.keep()?;

        // transmute temp files to file descriptors
        let piece_file_fd = piece_file.into_raw_fd();
        let staged_sector_fd = staged_file.into_raw_fd();

        unsafe {
            let resp_a = write_without_alignment(piece_file_fd, 1016, staged_sector_fd);

            if (*resp_a).status_code != FCPResponseStatus::FCPNoError {
                let msg = c_str_to_rust_str((*resp_a).error_msg);
                panic!("write_without_alignment failed: {:?}", msg);
            }

            let pieces = vec![FFIPublicPieceInfo {
                num_bytes: 1016,
                comm_p: (*resp_a).comm_p,
            }];

            let cache_dir_path_c_str = rust_str_to_c_str(cache_dir_path.to_str().unwrap());
            let staged_path_c_str = rust_str_to_c_str(staged_path.to_str().unwrap());
            let sealed_path_c_str = rust_str_to_c_str(sealed_path.to_str().unwrap());
            let unseal_path_c_str = rust_str_to_c_str(unseal_path.to_str().unwrap());

            let resp_b = seal_pre_commit(
                sector_class.clone(),
                cache_dir_path_c_str,
                staged_path_c_str,
                sealed_path_c_str,
                sector_id,
                &prover_id,
                &ticket,
                pieces.as_ptr(),
                pieces.len(),
            );

            if (*resp_b).status_code != FCPResponseStatus::FCPNoError {
                let msg = c_str_to_rust_str((*resp_a).error_msg);
                panic!("seal_pre_commit failed: {:?}", msg);
            }

            let resp_c = seal_commit(
                sector_class.clone(),
                cache_dir_path_c_str,
                sector_id,
                &prover_id,
                &ticket,
                &seed,
                pieces.as_ptr(),
                pieces.len(),
                (*(resp_b)).seal_pre_commit_output,
            );

            if (*resp_c).status_code != FCPResponseStatus::FCPNoError {
                let msg = c_str_to_rust_str((*resp_a).error_msg);
                panic!("seal_commit failed: {:?}", msg);
            }

            let resp_d = verify_seal(
                1024,
                &(*resp_b).seal_pre_commit_output.comm_r,
                &(*resp_b).seal_pre_commit_output.comm_d,
                &prover_id,
                &ticket,
                &seed,
                sector_id,
                (*resp_c).proof_ptr,
                (*resp_c).proof_len,
            );

            if (*resp_d).status_code != FCPResponseStatus::FCPNoError {
                let msg = c_str_to_rust_str((*resp_a).error_msg);
                panic!("seal_commit failed: {:?}", msg);
            }

            assert!((*resp_d).is_valid, "proof was not valid");

            let resp_e = unseal(
                sector_class.clone(),
                sealed_path_c_str,
                unseal_path_c_str,
                sector_id,
                &prover_id,
                &ticket,
                &(*resp_b).seal_pre_commit_output.comm_d,
            );

            if (*resp_e).status_code != FCPResponseStatus::FCPNoError {
                let msg = c_str_to_rust_str((*resp_a).error_msg);
                panic!("unseal failed: {:?}", msg);
            }

            // ensure unsealed bytes match what we had in our piece
            let mut buf_b = Vec::with_capacity(1016);
            let mut f = std::fs::File::open(unseal_path)?;
            let _ = f.read_to_end(&mut buf_b)?;
            assert_eq!(
                format!("{:x?}", &buf_a),
                format!("{:x?}", &buf_b),
                "original bytes don't match unsealed bytes"
            );

            destroy_write_without_alignment_response(resp_a);
            destroy_seal_pre_commit_response(resp_b);
            destroy_seal_commit_response(resp_c);
            destroy_verify_seal_response(resp_d);
            destroy_unseal_response(resp_e);

            c_str_to_rust_str(cache_dir_path_c_str);
            c_str_to_rust_str(staged_path_c_str);
            c_str_to_rust_str(sealed_path_c_str);
            c_str_to_rust_str(unseal_path_c_str);
        }

        Ok(())
    }
}
