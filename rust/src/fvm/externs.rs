use anyhow::{anyhow, Context};

use fvm2::externs::{Consensus as Consensus2, Externs as Externs2, Rand as Rand2};
use fvm3::externs::{Chain as Chain3, Consensus as Consensus3, Externs as Externs3, Rand as Rand3};

use fvm2_shared::address::Address as Address2;
use fvm3_shared::address::Address;

use fvm3_shared::clock::ChainEpoch;

use fvm2_shared::consensus::{
    ConsensusFault as ConsensusFault2, ConsensusFaultType as ConsensusFaultType2,
};
use fvm3_shared::consensus::ConsensusFault as ConsensusFault3;

use num_traits::FromPrimitive;

use super::cgo::*;

/// An implementation of [`fvm::externs::Externs`] that can call out to go. See the `cgo` directory
/// in this repo for the go side.
///
/// Importantly, this allows Filecoin client written in go to expose chain randomness and consensus
/// fault verification to the FVM.
pub struct CgoExterns {
    handle: u64,
}

impl CgoExterns {
    /// Construct a new externs from a handle.
    pub fn new(handle: u64) -> CgoExterns {
        CgoExterns { handle }
    }
}

impl Rand3 for CgoExterns {
    fn get_chain_randomness(
        &self,
        pers: i64,
        round: ChainEpoch,
        entropy: &[u8],
    ) -> anyhow::Result<[u8; 32]> {
        unsafe {
            let mut buf = [0u8; 32];
            match cgo_extern_get_chain_randomness(
                self.handle,
                pers,
                round,
                entropy.as_ptr(),
                entropy.len() as i32,
                &mut buf,
            ) {
                0 => Ok(buf),
                r @ 1.. => panic!("invalid return value from has: {}", r),
                x if x == FvmError::InvalidHandle as i32 => {
                    panic!("extern {} not registered", self.handle)
                }
                e => Err(anyhow!(
                    "cgo extern 'get_chain_randomness' failed with error code {}",
                    e
                )),
            }
        }
    }

    fn get_beacon_randomness(
        &self,
        pers: i64,
        round: ChainEpoch,
        entropy: &[u8],
    ) -> anyhow::Result<[u8; 32]> {
        unsafe {
            let mut buf = [0u8; 32];
            match cgo_extern_get_beacon_randomness(
                self.handle,
                pers,
                round,
                entropy.as_ptr(),
                entropy.len() as i32,
                &mut buf,
            ) {
                0 => Ok(buf),
                r @ 1.. => panic!("invalid return value from has: {}", r),
                x if x == FvmError::InvalidHandle as i32 => {
                    panic!("extern {} not registered", self.handle)
                }
                e => Err(anyhow!(
                    "cgo extern 'get_beacon_randomness' failed with error code {}",
                    e
                )),
            }
        }
    }
}

impl Rand2 for CgoExterns {
    fn get_chain_randomness(
        &self,
        pers: i64,
        round: ChainEpoch,
        entropy: &[u8],
    ) -> anyhow::Result<[u8; 32]> {
        Rand3::get_chain_randomness(self, pers, round, entropy)
    }

    fn get_beacon_randomness(
        &self,
        pers: i64,
        round: ChainEpoch,
        entropy: &[u8],
    ) -> anyhow::Result<[u8; 32]> {
        Rand3::get_beacon_randomness(self, pers, round, entropy)
    }
}

impl Consensus3 for CgoExterns {
    fn verify_consensus_fault(
        &self,
        h1: &[u8],
        h2: &[u8],
        extra: &[u8],
    ) -> anyhow::Result<(Option<ConsensusFault3>, i64)> {
        unsafe {
            let mut miner_id: u64 = 0;
            let mut epoch: i64 = 0;
            let mut fault_type: i64 = 0;
            let mut gas_used: i64 = 0;
            match cgo_extern_verify_consensus_fault(
                self.handle,
                h1.as_ptr(),
                h1.len() as i32,
                h2.as_ptr(),
                h2.len() as i32,
                extra.as_ptr(),
                extra.len() as i32,
                &mut miner_id,
                &mut epoch,
                &mut fault_type,
                &mut gas_used,
            ) {
                0 => Ok((
                    match fault_type {
                        0 => None,
                        _ => Some(ConsensusFault3 {
                            target: Address::new_id(miner_id),
                            epoch,
                            fault_type: FromPrimitive::from_i64(fault_type)
                                .context("invalid fault type")?,
                        }),
                    },
                    gas_used,
                )),
                r @ 1.. => panic!("invalid return value from has: {}", r),
                x if x == FvmError::InvalidHandle as i32 => {
                    panic!("extern {} not registered", self.handle)
                }
                e => Err(anyhow!(
                    "cgo extern 'verify_consensus_fault' failed with error code {}",
                    e
                )),
            }
        }
    }
}

impl Consensus2 for CgoExterns {
    fn verify_consensus_fault(
        &self,
        h1: &[u8],
        h2: &[u8],
        extra: &[u8],
    ) -> anyhow::Result<(Option<ConsensusFault2>, i64)> {
        let res = Consensus3::verify_consensus_fault(self, h1, h2, extra);
        match res {
            Ok((Some(res), x)) => Ok((
                Some(ConsensusFault2 {
                    target: Address2::from_bytes(&res.target.to_bytes()).unwrap(),
                    epoch: res.epoch,
                    fault_type: ConsensusFaultType2::from_u8(res.fault_type as u8).unwrap(),
                }),
                x,
            )),
            Ok((None, x)) => Ok((None, x)),
            Err(x) => Err(x),
        }
    }
}

impl Chain3 for CgoExterns {
    fn get_tipset_cid(&self, epoch: ChainEpoch) -> anyhow::Result<cid::Cid> {
        unsafe {
            let mut buf = [0; fvm3_shared::MAX_CID_LEN];
            match cgo_extern_get_tipset_cid(self.handle, epoch, buf.as_mut_ptr(), buf.len() as i32)
            {
                0 => Ok(buf[..].try_into()?),
                r @ 1.. => panic!("invalid return value from has: {}", r),
                x if x == FvmError::InvalidHandle as i32 => {
                    panic!("extern {} not registered", self.handle)
                }
                e => Err(anyhow!(
                    "cgo extern 'get_tipset_cid' failed with error code {}",
                    e
                )),
            }
        }
    }
}

impl Externs3 for CgoExterns {}
impl Externs2 for CgoExterns {}
