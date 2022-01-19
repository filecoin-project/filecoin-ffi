use fvm_cgo::blockstore::CgoBlockstore;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::sync::{atomic::AtomicU64, Mutex};

use cid::Cid;
use ffi_toolkit::{
    catch_panic_response, raw_ptr, rust_str_to_c_str, FCPResponseStatus,
};
use fvm::call_manager::DefaultCallManager;
use fvm::executor::{ApplyKind, DefaultExecutor, Executor};
use fvm::externs::cgo::CgoExterns;
use fvm::machine::DefaultMachine;
use fvm::{Config, DefaultKernel};
use fvm_shared::{
    clock::ChainEpoch,
    econ::TokenAmount,
    message::Message,
    version::NetworkVersion,
};
use log::info;
use once_cell::sync::Lazy;

use super::types::*;
use crate::util::api::init_log;

type CgoExecutor =
    DefaultExecutor<DefaultKernel<DefaultCallManager<DefaultMachine<CgoBlockstore, CgoExterns>>>>;

static FVM_MAP: Lazy<Mutex<HashMap<u64, CgoExecutor>>> =
    Lazy::new(|| Mutex::new(HashMap::with_capacity(1)));

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

fn add_fvm_machine(machine: CgoExecutor) -> u64 {
    let next_id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let mut machines = FVM_MAP.lock().unwrap();
    machines.insert(next_id, machine);
    next_id
}

fn get_default_config() -> fvm::Config {
    Config {
        max_call_depth: 4096, // FIXME
        initial_pages: 1024,  // FIXME
        max_pages: 32768,     // FIXME
        engine: wasmtime::Config::new(),
        debug: false,
    }
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
    token_amount_hi: u64,
    token_amount_lo: u64,
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

        let config = get_default_config();
        let chain_epoch = chain_epoch as ChainEpoch;

        let token_amount =
            TokenAmount::from(token_amount_hi) << 64_u64 | TokenAmount::from(token_amount_lo);
        let base_circ_supply = TokenAmount::from(base_circ_supply_hi) << 64_u64
            | TokenAmount::from(base_circ_supply_lo);
        let network_version = match NetworkVersion::try_from(network_version as u32) {
            Ok(x) => x,
            Err(err) => {
                response.status_code = FCPResponseStatus::FCPUnclassifiedError;
                response.error_msg = rust_str_to_c_str(format!("{:?}", err));
                return raw_ptr(response);
            }
        };
        let state_root_bytes: Vec<u8> =
            std::slice::from_raw_parts(state_root_ptr, state_root_len).to_vec();
        let state_root = match Cid::try_from(state_root_bytes) {
            Ok(x) => x,
            Err(err) => {
                response.status_code = FCPResponseStatus::FCPUnclassifiedError;
                response.error_msg = rust_str_to_c_str(format!("{:?}", err));
                return raw_ptr(response);
            }
        };

        let blockstore = CgoBlockstore::new(blockstore_id as i32);
        let externs = CgoExterns::new(externs_id as i32);
        let machine = fvm::machine::DefaultMachine::new(
            config,
            chain_epoch,
            token_amount,
            base_circ_supply,
            network_version,
            state_root,
            blockstore,
            externs,
        );
        match machine {
            Ok(machine) => {
                response.status_code = FCPResponseStatus::FCPNoError;
                response.machine_id = add_fvm_machine(DefaultExecutor::new(machine));
            }
            Err(err) => {
                response.status_code = FCPResponseStatus::FCPUnclassifiedError;
                response.error_msg = rust_str_to_c_str(format!("{:?}", err));
                return raw_ptr(response);
            }
        }

        info!("fil_create_fvm_machine: finish");

        raw_ptr(response)
    })
}

#[no_mangle]
pub unsafe extern "C" fn fil_drop_fvm_machine(machine_id: u64) -> *mut fil_DropFvmMachineResponse {
    catch_panic_response(|| {
        init_log();

        info!("fil_drop_fvm_machine: start");

        let mut response = fil_DropFvmMachineResponse::default();

        let mut machines = FVM_MAP.lock().unwrap();
        let machine = machines.remove(&machine_id);
        match machine {
            Some(_machine) => {
                response.status_code = FCPResponseStatus::FCPNoError;
            }
            None => {
                response.status_code = FCPResponseStatus::FCPUnclassifiedError;
                response.error_msg = rust_str_to_c_str("invalid machine id".to_string());
            }
        }

        info!("fil_drop_fvm_machine: end");

        raw_ptr(response)
    })
}

#[no_mangle]
pub unsafe extern "C" fn fil_fvm_machine_execute_message(
    machine_id: u64,
    message_ptr: *const u8,
    message_len: libc::size_t,
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

        let mut executors = FVM_MAP.lock().unwrap();
        let executor = executors.get_mut(&machine_id);
        match executor {
            Some(executor) => {
                let _apply_ret = match executor.execute_message(message, apply_kind, message_len) {
                    Ok(x) => x,
                    Err(err) => {
                        response.status_code = FCPResponseStatus::FCPUnclassifiedError;
                        response.error_msg = rust_str_to_c_str(format!("{:?}", err));
                        return raw_ptr(response);
                    }
                };

                response.status_code = FCPResponseStatus::FCPNoError;
                // FIXME: Return serialized ApplyRet type
            }
            None => {
                response.status_code = FCPResponseStatus::FCPUnclassifiedError;
                response.error_msg = rust_str_to_c_str("invalid machine id".to_string());
            }
        }

        info!("fil_fvm_machine_execute_message: end");

        raw_ptr(response)
    })
}

#[no_mangle]
pub unsafe extern "C" fn fil_fvm_machine_finish_message(
    machine_id: u64,
    // TODO: actual message
) {
    // catch_panic_response(|| {
    init_log();

    info!("fil_fvm_machine_flush_message: start");

    let machines = FVM_MAP.lock().unwrap();
    let machine = machines.get(&machine_id);
    match machine {
        Some(_machine) => {
            todo!("execute message")
        }
        None => {
            todo!("invalid machine id")
        }
    }

    //info!("fil_fvm_machine_flush_message: end");
    // })
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_create_fvm_machine_response(
    ptr: *mut fil_CreateFvmMachineResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_drop_fvm_machine_response(
    ptr: *mut fil_DropFvmMachineResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_fvm_machine_execute_response(
    ptr: *mut fil_FvmMachineExecuteResponse,
) {
    let _ = Box::from_raw(ptr);
}
