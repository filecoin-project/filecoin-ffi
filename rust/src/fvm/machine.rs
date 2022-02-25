use std::convert::{TryFrom, TryInto};
use std::sync::Mutex;

use cid::Cid;
use ffi_toolkit::{catch_panic_response, raw_ptr, rust_str_to_c_str, FCPResponseStatus};
use fvm::call_manager::DefaultCallManager;
use fvm::executor::{ApplyKind, DefaultExecutor, Executor};
use fvm::machine::DefaultMachine;
use fvm::{Config, DefaultKernel};
use fvm_shared::{clock::ChainEpoch, econ::TokenAmount, message::Message, version::NetworkVersion};
use lazy_static::lazy_static;
use log::info;

use super::blockstore::CgoBlockstore;
use super::externs::CgoExterns;
use super::types::*;
use crate::util::api::init_log;

pub type CgoExecutor =
    DefaultExecutor<DefaultKernel<DefaultCallManager<DefaultMachine<CgoBlockstore, CgoExterns>>>>;

lazy_static! {
    static ref ENGINE: fvm::machine::Engine = fvm::machine::Engine::default();
}

/// Note: the incoming args as u64 and odd conversions to i32/i64
/// for some types is due to the generated bindings not liking the
/// 32bit types as incoming args
///
#[no_mangle]
#[cfg(not(target_os = "windows"))]
pub unsafe extern "C" fn fil_create_fvm_machine(
    fvm_version: fil_FvmRegisteredVersion,
    chain_epoch: u64,
    base_fee_hi: u64,
    base_fee_lo: u64,
    base_circ_supply_hi: u64,
    base_circ_supply_lo: u64,
    network_version: u64,
    state_root_ptr: *const u8,
    state_root_len: libc::size_t,
    blockstore_id: u64,
    externs_id: u64,
) -> *mut fil_CreateFvmMachineResponse {
    catch_panic_response(|| {
        init_log();

        info!("fil_create_fvm_machine: start");

        let mut response = fil_CreateFvmMachineResponse::default();
        match fvm_version {
            fil_FvmRegisteredVersion::V1 => info!("using FVM V1"),
            //_ => panic!("unsupported FVM Registered Version")
        }

        let config = Config::default();
        let chain_epoch = chain_epoch as ChainEpoch;

        let base_circ_supply = TokenAmount::from(
            ((base_circ_supply_hi as u128) << u64::BITS) | base_circ_supply_lo as u128,
        );
        let base_fee =
            TokenAmount::from(((base_fee_hi as u128) << u64::BITS) | base_fee_lo as u128);

        let network_version = match NetworkVersion::try_from(network_version as u32) {
            Ok(x) => x,
            Err(_) => {
                response.status_code = FCPResponseStatus::FCPUnclassifiedError;
                response.error_msg =
                    rust_str_to_c_str(format!("unsupported network version: {}", network_version));
                return raw_ptr(response);
            }
        };
        let state_root_bytes: Vec<u8> =
            std::slice::from_raw_parts(state_root_ptr, state_root_len).to_vec();
        let state_root = match Cid::try_from(state_root_bytes) {
            Ok(x) => x,
            Err(err) => {
                response.status_code = FCPResponseStatus::FCPUnclassifiedError;
                response.error_msg = rust_str_to_c_str(format!("invalid state root: {}", err));
                return raw_ptr(response);
            }
        };

        let blockstore = CgoBlockstore::new(blockstore_id);
        let externs = CgoExterns::new(externs_id);
        let machine = fvm::machine::DefaultMachine::new(
            config,
            ENGINE.clone(),
            chain_epoch,
            base_fee,
            base_circ_supply,
            network_version,
            state_root,
            blockstore,
            externs,
        );
        match machine {
            Ok(machine) => {
                response.status_code = FCPResponseStatus::FCPNoError;
                response.executor = Box::into_raw(Box::new(Mutex::new(CgoExecutor::new(machine))))
                    as *mut libc::c_void;
            }
            Err(err) => {
                response.status_code = FCPResponseStatus::FCPUnclassifiedError;
                response.error_msg =
                    rust_str_to_c_str(format!("failed to create machine: {}", err));
                return raw_ptr(response);
            }
        }

        info!("fil_create_fvm_machine: finish");

        raw_ptr(response)
    })
}

#[no_mangle]
pub unsafe extern "C" fn fil_drop_fvm_machine(executor: *mut libc::c_void) {
    let _ = Box::from_raw(executor as *mut Mutex<CgoExecutor>);
}

#[no_mangle]
pub unsafe extern "C" fn fil_fvm_machine_execute_message(
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
        let message: Message = match fvm_shared::encoding::from_slice(message_bytes) {
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

        let return_bytes = Vec::from(apply_ret.msg_receipt.return_data).into_boxed_slice();

        // TODO: Do something with the backtrace.
        response.status_code = FCPResponseStatus::FCPNoError;
        response.exit_code = apply_ret.msg_receipt.exit_code as u64;
        response.return_ptr = return_bytes.as_ptr();
        response.return_len = return_bytes.len();
        response.gas_used = apply_ret.msg_receipt.gas_used as u64;
        response.penalty_hi = (penalty >> u64::BITS) as u64;
        response.penalty_lo = penalty as u64;
        response.miner_tip_hi = (miner_tip >> u64::BITS) as u64;
        response.miner_tip_lo = miner_tip as u64;

        Box::leak(return_bytes);

        info!("fil_fvm_machine_execute_message: end");

        raw_ptr(response)
    })
}

#[no_mangle]
pub unsafe extern "C" fn fil_fvm_machine_flush(
    executor: *mut libc::c_void,
) -> *const fil_FvmMachineFlushResponse {
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
