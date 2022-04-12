use std::convert::TryFrom;
use std::sync::Mutex;

use anyhow::anyhow;
use cid::Cid;
use futures::executor::block_on;
use fvm::call_manager::DefaultCallManager;
use fvm::executor::{ApplyKind, DefaultExecutor, Executor};
use fvm::machine::DefaultMachine;
use fvm::{Config, DefaultKernel};
use fvm_ipld_blockstore::Blockstore;
use fvm_ipld_car::load_car;
use fvm_shared::receipt::Receipt;
use fvm_shared::{clock::ChainEpoch, econ::TokenAmount, message::Message, version::NetworkVersion};
use lazy_static::lazy_static;
use log::info;
use safer_ffi::prelude::*;

use super::blockstore::{CgoBlockstore, FakeBlockstore, OverlayBlockstore};
use super::externs::CgoExterns;
use super::types::*;
use crate::destructor;
use crate::util::types::{catch_panic_response, catch_panic_response_no_default, Result};

pub type CgoExecutor = DefaultExecutor<
    DefaultKernel<DefaultCallManager<DefaultMachine<OverlayBlockstore<CgoBlockstore>, CgoExterns>>>,
>;

lazy_static! {
    static ref ENGINE: fvm::machine::Engine = fvm::machine::Engine::default();
}

/// Note: the incoming args as u64 and odd conversions to i32/i64
/// for some types is due to the generated bindings not liking the
/// 32bit types as incoming args
///
#[ffi_export]
fn create_fvm_machine(
    fvm_version: FvmRegisteredVersion,
    chain_epoch: u64,
    base_fee_hi: u64,
    base_fee_lo: u64,
    base_circ_supply_hi: u64,
    base_circ_supply_lo: u64,
    network_version: u64,
    state_root: c_slice::Ref<u8>,
    manifest_cid: c_slice::Ref<u8>,
    blockstore_id: u64,
    externs_id: u64,
) -> repr_c::Box<Result<repr_c::Box<FvmMachine>>> {
    unsafe {
        catch_panic_response_no_default("create_fvm_machine", || {
            match fvm_version {
                FvmRegisteredVersion::V1 => info!("using FVM V1"),
                //_ => panic!("unsupported FVM Registered Version")
            }

            let config = Config::default();
            let chain_epoch = chain_epoch as ChainEpoch;

            let base_circ_supply = TokenAmount::from(
                ((base_circ_supply_hi as u128) << u64::BITS) | base_circ_supply_lo as u128,
            );
            let base_fee =
                TokenAmount::from(((base_fee_hi as u128) << u64::BITS) | base_fee_lo as u128);

            let network_version = NetworkVersion::try_from(network_version as u32)
                .map_err(|_| anyhow!("unsupported network version: {}", network_version))?;
            let state_root = Cid::try_from(&state_root[..])
                .map_err(|err| anyhow!("invalid state root: {}", err))?;

            let manifest_cid = if !manifest_cid.is_empty() {
                let cid = Cid::try_from(&manifest_cid[..])
                    .map_err(|err| anyhow!("invalid manifest: {}", err))?;
                Some(cid)
            } else {
                // handle cid.Undef for no manifest
                // this can mean two things:
                // - for pre nv16, use the builtin bundles
                // - for nv16 or higher, it means we have already migrated state for system
                //   actor and we can pass None to the machine constructor to fish it from state.
                // The presence of the manifest cid argument allows us to test with new bundles
                // with minimum friction.
                None
            };

            let blockstore = FakeBlockstore::new(CgoBlockstore::new(blockstore_id));

            let builtin_actors = import_actors(&blockstore, manifest_cid, network_version)
                .map_err(|err| anyhow!("couldn't load builtin actors: {}", err))?;

            let blockstore = blockstore.finish();

            let externs = CgoExterns::new(externs_id);
            let machine = fvm::machine::DefaultMachine::new(
                config,
                ENGINE.clone(),
                chain_epoch,
                base_fee,
                base_circ_supply,
                network_version,
                state_root,
                builtin_actors,
                blockstore,
                externs,
            )
            .map_err(|err| anyhow!("failed to create machine: {}", err))?;

            Ok(repr_c::Box::new(FvmMachine {
                machine: Some(Mutex::new(CgoExecutor::new(machine))),
            }))
        })
    }
}

#[ffi_export]
fn fvm_machine_execute_message(
    executor: &'_ FvmMachine,
    message: c_slice::Ref<u8>,
    chain_len: u64,
    apply_kind: u64, /* 0: Explicit, _: Implicit */
) -> repr_c::Box<Result<FvmMachineExecuteResponse>> {
    catch_panic_response("fvm_machine_execute_message", || {
        let apply_kind = if apply_kind == 0 {
            ApplyKind::Explicit
        } else {
            ApplyKind::Implicit
        };

        let message: Message = fvm_ipld_encoding::from_slice(&message)?;

        let mut executor = executor
            .machine
            .as_ref()
            .expect("missing executor")
            .lock()
            .unwrap();
        let apply_ret = executor.execute_message(message, apply_kind, chain_len as usize)?;

        // TODO: use the non-bigint token amount everywhere in the FVM
        let penalty: u128 = apply_ret.penalty.try_into().unwrap();
        let miner_tip: u128 = apply_ret.miner_tip.try_into().unwrap();

        let Receipt {
            exit_code,
            return_data,
            gas_used,
        } = apply_ret.msg_receipt;

        let return_val = if return_data.is_empty() {
            None
        } else {
            let bytes: Vec<u8> = return_data.into();
            Some(bytes.into_boxed_slice().into())
        };

        // TODO: Do something with the backtrace.

        Ok(FvmMachineExecuteResponse {
            exit_code: exit_code as u64,
            return_val,
            gas_used: gas_used as u64,
            penalty_hi: (penalty >> u64::BITS) as u64,
            penalty_lo: penalty as u64,
            miner_tip_hi: (miner_tip >> u64::BITS) as u64,
            miner_tip_lo: miner_tip as u64,
        })
    })
}

#[ffi_export]
fn fil_fvm_machine_flush(executor: &'_ FvmMachine) -> repr_c::Box<Result<c_slice::Box<u8>>> {
    catch_panic_response("fvm_machine_flush", || {
        let mut executor = executor
            .machine
            .as_ref()
            .expect("missing executor")
            .lock()
            .unwrap();
        let cid = executor.flush()?;

        Ok(cid.to_bytes().into_boxed_slice().into())
    })
}

destructor!(drop_fvm_machine, FvmMachine);
destructor!(
    destroy_create_fvm_machine_response,
    Result<repr_c::Box<FvmMachine>>
);

destructor!(
    destroy_fvm_machine_execute_response,
    Result<FvmMachineExecuteResponse>
);

destructor!(destroy_fvm_machine_flush_response, Result<c_slice::Box<u8>>);

fn import_actors(
    blockstore: &impl Blockstore,
    manifest_cid: Option<Cid>,
    network_version: NetworkVersion,
) -> std::result::Result<Option<Cid>, &'static str> {
    if manifest_cid.is_some() {
        return Ok(manifest_cid);
    }
    let car = match network_version {
        NetworkVersion::V14 => Ok(actors_v6::BUNDLE_CAR),
        NetworkVersion::V15 => Ok(actors_v7::BUNDLE_CAR),
        NetworkVersion::V16 => {
            return Ok(None);
        }
        _ => Err("unsupported network version"),
    }?;
    let roots = block_on(async { load_car(blockstore, car).await.unwrap() });
    assert_eq!(roots.len(), 1);
    Ok(Some(roots[0]))
}
