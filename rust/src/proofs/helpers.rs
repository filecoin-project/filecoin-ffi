use std::collections::btree_map::BTreeMap;
use std::slice::from_raw_parts;

use anyhow::Result;
use ffi_toolkit::{c_str_to_pbuf, c_str_to_rust_str};
use filecoin_proofs_api::fr32::fr_into_bytes;
use filecoin_proofs_api::{
    Candidate, PrivateReplicaInfo, PublicReplicaInfo, RegisteredPoStProof, RegisteredSealProof,
    SectorId,
};
use libc;
use paired::bls12_381::{Bls12, Fr};

use super::types::{
    FFICandidate, FFIPrivateReplicaInfo, FFIPublicReplicaInfo, FFIRegisteredPoStProof,
    FFIRegisteredSealProof,
};

#[derive(Debug, Clone)]
struct PublicReplicaInfoTmp {
    pub registered_proof: FFIRegisteredPoStProof,
    pub comm_r: [u8; 32],
    pub sector_id: u64,
}

/// Produce a map from sector id to replica info by pairing sector ids and
/// replica commitments (by index in their respective arrays), setting the
/// storage fault-boolean if the sector id is present in the provided dynamic
/// array. This function's return value should be provided to the verify_post
/// call.
#[allow(clippy::type_complexity)]
pub unsafe fn to_public_replica_info_map(
    replicas_ptr: *const FFIPublicReplicaInfo,
    replicas_len: libc::size_t,
    flattened_proofs_ptr: *const u8,
    flattened_proofs_len: libc::size_t,
    winners_ptr: *const FFICandidate,
    winners_len: libc::size_t,
) -> Result<(BTreeMap<SectorId, PublicReplicaInfo>, Vec<Vec<u8>>)> {
    use rayon::prelude::*;

    ensure!(!replicas_ptr.is_null(), "replicas_ptr must not be null");
    ensure!(
        !flattened_proofs_ptr.is_null(),
        "flattened_proof_ptr must not be null"
    );

    let mut sector_id_to_num_times_won: BTreeMap<SectorId, usize> = Default::default();

    let winners = from_raw_parts(winners_ptr, winners_len);

    for winner in winners {
        let k = SectorId::from(winner.sector_id);

        let r = if let Some(v) = sector_id_to_num_times_won.get(&k) {
            *v
        } else {
            0
        };

        sector_id_to_num_times_won.insert(k, r + 1);
    }

    let proofs_slice = from_raw_parts(flattened_proofs_ptr, flattened_proofs_len);
    let mut proofs_index = 0;

    let mut replicas = Vec::new();
    let mut proofs = Vec::new();

    for ffi_info in from_raw_parts(replicas_ptr, replicas_len) {
        replicas.push(PublicReplicaInfoTmp {
            sector_id: ffi_info.sector_id,
            registered_proof: ffi_info.registered_proof,
            comm_r: ffi_info.comm_r,
        });

        let proof_len =
            RegisteredPoStProof::from(ffi_info.registered_proof).single_partition_proof_len();

        let num_times_won =
            if let Some(n) = sector_id_to_num_times_won.get(&SectorId::from(ffi_info.sector_id)) {
                *n
            } else {
                0
            };

        // handle the scenario in which a single replica won multiple times
        for _ in 0..num_times_won {
            proofs.push(proofs_slice[proofs_index..proofs_index + proof_len].to_vec());
            proofs_index += proof_len;
        }
    }

    let map = replicas
        .into_par_iter()
        .map(|info| {
            let PublicReplicaInfoTmp {
                registered_proof,
                comm_r,
                sector_id,
            } = info;

            (
                SectorId::from(sector_id),
                PublicReplicaInfo::new(registered_proof.into(), comm_r),
            )
        })
        .collect();

    Ok((map, proofs))
}

/// Copy the provided dynamic array's bytes into a vector and return the vector.
pub unsafe fn try_into_porep_proof_bytes(
    registered_proof: FFIRegisteredSealProof,
    proof_ptr: *const u8,
    proof_len: libc::size_t,
) -> Result<Vec<u8>> {
    into_proof_vecs(
        RegisteredSealProof::from(registered_proof).single_partition_proof_len(),
        proof_ptr,
        proof_len,
    )?
    .first()
    .map(Vec::clone)
    .ok_or_else(|| format_err!("no proofs in chunked vec"))
}

unsafe fn into_proof_vecs(
    proof_chunk: usize,
    flattened_proofs_ptr: *const u8,
    flattened_proofs_len: libc::size_t,
) -> Result<Vec<Vec<u8>>> {
    ensure!(
        !flattened_proofs_ptr.is_null(),
        "flattened_proofs_ptr must not be a null pointer"
    );
    ensure!(proof_chunk > 0, "Invalid proof chunk of 0 passed");

    let res = from_raw_parts(flattened_proofs_ptr, flattened_proofs_len)
        .iter()
        .step_by(proof_chunk)
        .fold(Default::default(), |mut acc: Vec<Vec<u8>>, item| {
            let sliced = from_raw_parts(item, proof_chunk);
            acc.push(sliced.to_vec());
            acc
        });

    Ok(res)
}

pub fn bls_12_fr_into_bytes(fr: Fr) -> [u8; 32] {
    let mut commitment = [0; 32];
    for (i, b) in fr_into_bytes::<Bls12>(&fr).iter().enumerate() {
        commitment[i] = *b;
    }
    commitment
}

#[derive(Debug, Clone)]
struct PrivateReplicaInfoTmp {
    pub registered_proof: FFIRegisteredPoStProof,
    pub cache_dir_path: std::path::PathBuf,
    pub comm_r: [u8; 32],
    pub replica_path: String,
    pub sector_id: u64,
}

pub unsafe fn to_private_replica_info_map(
    replicas_ptr: *const FFIPrivateReplicaInfo,
    replicas_len: libc::size_t,
) -> Result<BTreeMap<SectorId, PrivateReplicaInfo>> {
    use rayon::prelude::*;

    ensure!(!replicas_ptr.is_null(), "replicas_ptr must not be null");

    let replicas: Vec<_> = from_raw_parts(replicas_ptr, replicas_len)
        .iter()
        .map(|ffi_info| {
            let cache_dir_path = c_str_to_pbuf(ffi_info.cache_dir_path);
            let replica_path = c_str_to_rust_str(ffi_info.replica_path).to_string();

            PrivateReplicaInfoTmp {
                registered_proof: ffi_info.registered_proof,
                cache_dir_path,
                comm_r: ffi_info.comm_r,
                replica_path,
                sector_id: ffi_info.sector_id,
            }
        })
        .collect();

    let map = replicas
        .into_par_iter()
        .map(|info| {
            let PrivateReplicaInfoTmp {
                registered_proof,
                cache_dir_path,
                comm_r,
                replica_path,
                sector_id,
            } = info;

            (
                SectorId::from(sector_id),
                PrivateReplicaInfo::new(
                    registered_proof.into(),
                    replica_path,
                    comm_r,
                    cache_dir_path,
                ),
            )
        })
        .collect();

    Ok(map)
}

pub unsafe fn c_to_rust_candidates(
    winners_ptr: *const FFICandidate,
    winners_len: libc::size_t,
) -> Result<Vec<Candidate>> {
    ensure!(!winners_ptr.is_null(), "winners_ptr must not be null");

    from_raw_parts(winners_ptr, winners_len)
        .iter()
        .cloned()
        .map(|c| c.try_into_candidate().map_err(Into::into))
        .collect()
}
