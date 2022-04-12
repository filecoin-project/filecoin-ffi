use std::convert::{TryFrom, TryInto};
use std::sync::Mutex;

use cid::Cid;
use futures::executor::block_on;
use fvm::call_manager::DefaultCallManager;
use fvm::executor::{ApplyKind, DefaultExecutor, Executor};
use fvm::machine::DefaultMachine;
use fvm::{Config, DefaultKernel};
use fvm_ipld_blockstore::Blockstore;
use fvm_ipld_car::load_car;
use fvm_shared::{clock::ChainEpoch, econ::TokenAmount, message::Message, version::NetworkVersion};
use lazy_static::lazy_static;
use log::info;
use safer_ffi::prelude::*;

use super::blockstore::{CgoBlockstore, FakeBlockstore, OverlayBlockstore};
use super::externs::CgoExterns;
use super::types::*;
use crate::destructor;
use crate::util::api::init_log;
use crate::util::types::{catch_panic_response, Result};

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
) -> repr_c::Box<Result<FvmMachine>> {
    catch_panic_response("create_fvm_machine", || {
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
            .map_err(|_| format!("unsupported network version: {}", network_version))?;
        let state_root =
            Cid::try_from(&state_root).map_err(|err| format!("invalid state root: {}", err))?;

        let manifest_cid = if !manifest_cid.is_empty() {
            let cid =
                Cid::try_from(&manifest_cid).map_err(|err| format!("invalid manifest: {}", err))?;
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
            .map_err(|err| format!("couldn't load builtin actors: {}", err))?;

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
        .map_err(|err| format!("failed to create machine: {}", err))?;

        Ok(FvmMachine {
            machine: Mutex::new(CgoExecutor::new(machine)),
        })
    })
}

destructor!(drop_fvm_machine, Result<FvmMachine>);

#[ffi_export]
fn fvm_machine_execute_message(
    executor: *mut libc::c_void,
    message_ptr: *const u8,
    message_len: libc::size_t,
    chain_len: u64,
    apply_kind: u64, /* 0: Explicit, _: Implicit */
) -> *mut fil_FvmMachineExecuteResponse {
    catch_panic_response(|| {
        init_log();

        info!("fil_fvm_machine_execute_message: start");

        let mut response = fil_FvmMachineExecuteResponse::default();

        let apply_kind = if apply_kind == 0 {
            ApplyKind::Explicit
        } else {
            ApplyKind::Implicit
        };

        let message_bytes = std::slice::from_raw_parts(message_ptr, message_len);
        let message: Message = match fvm_ipld_encoding::from_slice(message_bytes) {
            Ok(x) => x,
            Err(err) => {
                response.status_code = FCPResponseStatus::FCPUnclassifiedError;
                response.error_msg = rust_str_to_c_str(format!("{:?}", err));
                return raw_ptr(response);
            }
        };

        let mut executor = unsafe { &*(executor as *mut Mutex<CgoExecutor>) }
            .lock()
            .unwrap();
        let apply_ret = match executor.execute_message(message, apply_kind, chain_len as usize) {
            Ok(x) => x,
            Err(err) => {
                response.status_code = FCPResponseStatus::FCPUnclassifiedError;
                response.error_msg = rust_str_to_c_str(format!("{:?}", err));
                return raw_ptr(response);
            }
        };

        // TODO: use the non-bigint token amount everywhere in the FVM
        let penalty: u128 = apply_ret.penalty.try_into().unwrap();
        let miner_tip: u128 = apply_ret.miner_tip.try_into().unwrap();

        // Only do this if the return data is non-empty. The empty vec pointer is non-null and not
        // valid in go.
        if !apply_ret.msg_receipt.return_data.is_empty() {
            let return_bytes = Vec::from(apply_ret.msg_receipt.return_data).into_boxed_slice();
            response.return_ptr = return_bytes.as_ptr();
            response.return_len = return_bytes.len();
            Box::leak(return_bytes);
        }

        // TODO: Do something with the backtrace.
        response.status_code = FCPResponseStatus::FCPNoError;
        response.exit_code = apply_ret.msg_receipt.exit_code as u64;
        response.gas_used = apply_ret.msg_receipt.gas_used as u64;
        response.penalty_hi = (penalty >> u64::BITS) as u64;
        response.penalty_lo = penalty as u64;
        response.miner_tip_hi = (miner_tip >> u64::BITS) as u64;
        response.miner_tip_lo = miner_tip as u64;

        info!("fil_fvm_machine_execute_message: end");

        raw_ptr(response)
    })
}

#[no_mangle]
pub unsafe extern "C" fn fil_fvm_machine_flush(
    executor: *mut libc::c_void,
) -> *mut fil_FvmMachineFlushResponse {
    catch_panic_response(|| {
        init_log();

        info!("fil_fvm_machine_flush: start");

        let mut executor = unsafe { &*(executor as *mut Mutex<CgoExecutor>) }
            .lock()
            .unwrap();
        let mut response = fil_FvmMachineFlushResponse::default();
        match executor.flush() {
            Ok(cid) => {
                let bytes = cid.to_bytes().into_boxed_slice();
                response.state_root_ptr = bytes.as_ptr();
                response.state_root_len = bytes.len();
                Box::leak(bytes);
            }
            Err(e) => {
                response.status_code = FCPResponseStatus::FCPReceiverError;
                response.error_msg = rust_str_to_c_str(e.to_string());
            }
        }
        info!("fil_fvm_machine_flush: end");

        raw_ptr(response)
    })
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_create_fvm_machine_response(
    ptr: *mut fil_CreateFvmMachineResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_fvm_machine_execute_response(
    ptr: *mut fil_FvmMachineExecuteResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_fvm_machine_flush_response(
    ptr: *mut fil_FvmMachineFlushResponse,
) {
    let _ = Box::from_raw(ptr);
}

fn import_actors(
    blockstore: &impl Blockstore,
    manifest_cid: Option<Cid>,
    network_version: NetworkVersion,
) -> Result<Option<Cid>, &'static str> {
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
