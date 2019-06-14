use std::slice::from_raw_parts;

use filecoin_proofs::constants as api_constants;
use filecoin_proofs::types as api_types;
use libc;

use crate::error::Result;

/// Copy the provided dynamic array's bytes into a vector of vectors, splitting
/// at the boundary established by the number of partitions used to create each
/// proof.
///
pub unsafe fn try_into_post_proofs_bytes(
    proof_partitions: u8,
    flattened_proofs_ptr: *const u8,
    flattened_proofs_len: libc::size_t,
) -> Result<Vec<Vec<u8>>> {
    let chunk_size = proof_partitions as usize * api_constants::SINGLE_PARTITION_PROOF_LEN;

    ensure!(
        flattened_proofs_len % chunk_size == 0,
        "proofs array len={:?} incompatible with partitions={:?}",
        flattened_proofs_len,
        proof_partitions
    );

    Ok(into_proof_vecs(
        chunk_size,
        flattened_proofs_ptr,
        flattened_proofs_len,
    ))
}

/// Copy the provided dynamic array's bytes into a vector and return the vector.
///
pub unsafe fn try_into_porep_proof_bytes(
    proof_ptr: *const u8,
    proof_len: libc::size_t,
) -> Result<Vec<u8>> {
    into_proof_vecs(proof_len, proof_ptr, proof_len)
        .first()
        .map(Vec::clone)
        .ok_or_else(|| format_err!("no proofs in chunked vec"))
}

/// Copies the bytes from the provided challenge seed (pointer) to a 32-item,
/// stack allocated byte array.
pub fn into_safe_challenge_seed(challenge_seed: &[u8; 32]) -> [u8; 32] {
    let mut cs = [0; 32];
    cs.copy_from_slice(challenge_seed);
    cs[31] &= 0b0011_1111;
    cs
}

/// Splits the flattened, dynamic array of CommR bytes into a vector of
/// 32-element byte arrays and returns the vector. Each byte array's
/// little-endian value represents an Fr.
///
pub unsafe fn into_commitments(
    flattened_comms_ptr: *const u8,
    flattened_comms_len: libc::size_t,
) -> Vec<[u8; 32]> {
    from_raw_parts(flattened_comms_ptr, flattened_comms_len)
        .iter()
        .step_by(32)
        .fold(Default::default(), |mut acc: Vec<[u8; 32]>, item| {
            let sliced = from_raw_parts(item, 32);
            let mut x: [u8; 32] = Default::default();
            x.copy_from_slice(&sliced[..32]);
            acc.push(x);
            acc
        })
}

/// Return the number of partitions used to create the given proof.
///
pub fn porep_proof_partitions_try_from_bytes(
    proof: &[u8],
) -> Result<api_types::PoRepProofPartitions> {
    let n = proof.len();

    ensure!(
        n % api_constants::SINGLE_PARTITION_PROOF_LEN == 0,
        "no PoRepProofPartitions mapping for {:x?}",
        proof
    );

    Ok(api_types::PoRepProofPartitions(
        (n / api_constants::SINGLE_PARTITION_PROOF_LEN) as u8,
    ))
}

unsafe fn into_proof_vecs(
    proof_chunk: usize,
    flattened_proofs_ptr: *const u8,
    flattened_proofs_len: libc::size_t,
) -> Vec<Vec<u8>> {
    from_raw_parts(flattened_proofs_ptr, flattened_proofs_len)
        .iter()
        .step_by(proof_chunk)
        .fold(Default::default(), |mut acc: Vec<Vec<u8>>, item| {
            let sliced = from_raw_parts(item, proof_chunk);
            acc.push(sliced.to_vec());
            acc
        })
}
