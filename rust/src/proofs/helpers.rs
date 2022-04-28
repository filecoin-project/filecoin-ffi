use std::collections::btree_map::BTreeMap;

use anyhow::Result;
use filecoin_proofs_api::{self as api, SectorId};
use safer_ffi::prelude::*;

use super::types::{PrivateReplicaInfo, PublicReplicaInfo, RegisteredPoStProof};
use crate::util::types::as_path_buf;

#[derive(Debug, Clone)]
struct PublicReplicaInfoTmp {
    pub registered_proof: RegisteredPoStProof,
    pub comm_r: [u8; 32],
    pub sector_id: u64,
}

pub fn to_public_replica_info_map(
    replicas: c_slice::Ref<PublicReplicaInfo>,
) -> BTreeMap<SectorId, api::PublicReplicaInfo> {
    use rayon::prelude::*;

    let replicas = replicas
        .iter()
        .map(|ffi_info| PublicReplicaInfoTmp {
            sector_id: ffi_info.sector_id,
            registered_proof: ffi_info.registered_proof,
            comm_r: ffi_info.comm_r,
        })
        .collect::<Vec<_>>();

    replicas
        .into_par_iter()
        .map(|info| {
            let PublicReplicaInfoTmp {
                registered_proof,
                comm_r,
                sector_id,
            } = info;

            (
                SectorId::from(sector_id),
                api::PublicReplicaInfo::new(registered_proof.into(), comm_r),
            )
        })
        .collect()
}

#[derive(Debug, Clone)]
struct PrivateReplicaInfoTmp {
    pub registered_proof: RegisteredPoStProof,
    pub cache_dir_path: std::path::PathBuf,
    pub comm_r: [u8; 32],
    pub replica_path: std::path::PathBuf,
    pub sector_id: u64,
}

pub fn to_private_replica_info_map(
    replicas: c_slice::Ref<PrivateReplicaInfo>,
) -> Result<BTreeMap<SectorId, api::PrivateReplicaInfo>> {
    use rayon::prelude::*;

    let replicas: Vec<_> = replicas
        .iter()
        .map(|ffi_info| {
            let cache_dir_path = as_path_buf(&ffi_info.cache_dir_path)?;
            let replica_path = as_path_buf(&ffi_info.replica_path)?;

            Ok(PrivateReplicaInfoTmp {
                registered_proof: ffi_info.registered_proof,
                cache_dir_path,
                comm_r: ffi_info.comm_r,
                replica_path,
                sector_id: ffi_info.sector_id,
            })
        })
        .collect::<Result<_>>()?;

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
                api::PrivateReplicaInfo::new(
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
