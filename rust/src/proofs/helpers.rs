use anyhow::Result;
use ffi_toolkit::{c_str_to_pbuf, c_str_to_rust_str};
use filecoin_proofs_api::fr32::fr_into_bytes;
use filecoin_proofs_api::{
    Candidate, PrivateReplicaInfo, PublicReplicaInfo, RegisteredPoStProof, SectorId,
};
use libc;
use paired::bls12_381::{Bls12, Fr};
use std::collections::btree_map::BTreeMap;
use std::path::PathBuf;
use std::slice::from_raw_parts;

use super::types::{
    fil_Candidate, fil_PrivateReplicaInfo, fil_PublicReplicaInfo, fil_RegisteredPoStProof,
};
use crate::proofs::types::{fil_PoStProof, PoStProof};

#[derive(Debug, Clone)]
struct PublicReplicaInfoTmp {
    pub registered_proof: fil_RegisteredPoStProof,
    pub comm_r: [u8; 32],
    pub sector_id: u64,
}

#[allow(clippy::type_complexity)]
pub unsafe fn to_public_replica_info_map(
    replicas_ptr: *const fil_PublicReplicaInfo,
    replicas_len: libc::size_t,
) -> Result<BTreeMap<SectorId, PublicReplicaInfo>> {
    use rayon::prelude::*;

    ensure!(!replicas_ptr.is_null(), "replicas_ptr must not be null");

    let mut replicas = Vec::new();

    for ffi_info in from_raw_parts(replicas_ptr, replicas_len) {
        replicas.push(PublicReplicaInfoTmp {
            sector_id: ffi_info.sector_id,
            registered_proof: ffi_info.registered_proof,
            comm_r: ffi_info.comm_r,
        });
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

    Ok(map)
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
    pub registered_proof: fil_RegisteredPoStProof,
    pub cache_dir_path: std::path::PathBuf,
    pub comm_r: [u8; 32],
    pub replica_path: std::path::PathBuf,
    pub sector_id: u64,
}

pub unsafe fn to_private_replica_info_map(
    replicas_ptr: *const fil_PrivateReplicaInfo,
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
                replica_path: PathBuf::from(replica_path),
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
                    comm_r,
                    cache_dir_path,
                    replica_path,
                ),
            )
        })
        .collect();

    Ok(map)
}

pub unsafe fn c_to_rust_candidates(
    winners_ptr: *const fil_Candidate,
    winners_len: libc::size_t,
) -> Result<Vec<Candidate>> {
    ensure!(!winners_ptr.is_null(), "winners_ptr must not be null");

    from_raw_parts(winners_ptr, winners_len)
        .iter()
        .cloned()
        .map(|c| c.try_into_candidate().map_err(Into::into))
        .collect()
}

pub unsafe fn c_to_rust_post_proofs(
    post_proofs_ptr: *const fil_PoStProof,
    post_proofs_len: libc::size_t,
) -> Result<Vec<PoStProof>> {
    ensure!(
        !post_proofs_ptr.is_null(),
        "post_proofs_ptr must not be null"
    );

    let out = from_raw_parts(post_proofs_ptr, post_proofs_len)
        .iter()
        .map(|fpp| PoStProof {
            registered_proof: RegisteredPoStProof::StackedDrg2KiBV1,
            proof: from_raw_parts(fpp.proof_ptr, fpp.proof_len)
                .iter()
                .cloned()
                .collect(),
        })
        .collect();

    Ok(out)
}
