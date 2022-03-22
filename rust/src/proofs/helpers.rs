use anyhow::Result;
use filecoin_proofs_api::{PrivateReplicaInfo, PublicReplicaInfo, SectorId};
use std::collections::btree_map::BTreeMap;

use super::types::{fil_PrivateReplicaInfo, fil_PublicReplicaInfo, fil_RegisteredPoStProof};
use crate::util::types::fil_Array;

#[derive(Debug, Clone)]
struct PublicReplicaInfoTmp {
    pub registered_proof: fil_RegisteredPoStProof,
    pub comm_r: [u8; 32],
    pub sector_id: u64,
}

pub unsafe fn to_public_replica_info_map(
    replicas: &fil_Array<fil_PublicReplicaInfo>,
) -> BTreeMap<SectorId, PublicReplicaInfo> {
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
                PublicReplicaInfo::new(registered_proof.into(), comm_r),
            )
        })
        .collect()
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
    replicas: &fil_Array<fil_PrivateReplicaInfo>,
) -> Result<BTreeMap<SectorId, PrivateReplicaInfo>> {
    use rayon::prelude::*;

    let replicas: Vec<_> = replicas
        .iter()
        .map(|ffi_info| {
            let cache_dir_path = ffi_info.cache_dir_path.as_path()?;
            let replica_path = ffi_info.replica_path.as_path()?;

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
