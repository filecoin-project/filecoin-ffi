use std::convert::{TryFrom, TryInto};
use std::sync::Mutex;

use anyhow::anyhow;
use cid::Cid;
use ffi_toolkit::{catch_panic_response, raw_ptr, rust_str_to_c_str, FCPResponseStatus};
use futures::executor::block_on;
use fvm::call_manager::{DefaultCallManager, InvocationResult};
use fvm::executor::{ApplyKind, DefaultExecutor, Executor};
use fvm::machine::DefaultMachine;
use fvm::trace::ExecutionEvent;
use fvm::DefaultKernel;
use fvm_ipld_blockstore::Blockstore;
use fvm_ipld_car::load_car;
use fvm_ipld_encoding::tuple::{Deserialize_tuple, Serialize_tuple};
use fvm_shared::receipt::Receipt;
use fvm_shared::{clock::ChainEpoch, econ::TokenAmount, message::Message, version::NetworkVersion};
use lazy_static::lazy_static;
use log::info;

use super::blockstore::{CgoBlockstore, FakeBlockstore, OverlayBlockstore};
use super::externs::CgoExterns;
use super::types::*;
use crate::util::api::init_log;
use fvm_ipld_encoding::{to_vec, RawBytes};
use fvm_shared::address::Address;
use fvm_shared::error::{ErrorNumber, ExitCode};

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
    manifest_cid_ptr: *const u8,
    manifest_cid_len: libc::size_t,
    tracing: bool,
    blockstore_id: u64,
    externs_id: u64,
) -> *mut fil_CreateFvmMachineResponse {
    use fvm::machine::NetworkConfig;

    catch_panic_response(|| {
        init_log();

        info!("fil_create_fvm_machine: start");

        let mut response = fil_CreateFvmMachineResponse::default();
        match fvm_version {
            fil_FvmRegisteredVersion::V1 => info!("using FVM V1"),
            //_ => panic!("unsupported FVM Registered Version")
        }

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

        let manifest_cid = if manifest_cid_len > 0 {
            let manifest_cid_bytes: Vec<u8> =
                std::slice::from_raw_parts(manifest_cid_ptr, manifest_cid_len).to_vec();
            match Cid::try_from(manifest_cid_bytes) {
                Ok(x) => Some(x),
                Err(err) => {
                    response.status_code = FCPResponseStatus::FCPUnclassifiedError;
                    response.error_msg = rust_str_to_c_str(format!("invalid manifest: {}", err));
                    return raw_ptr(response);
                }
            }
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

        let mut network_config = NetworkConfig::new(network_version);
        match import_actors(&blockstore, manifest_cid, network_version) {
            Ok(Some(manifest)) => {
                network_config.override_actors(manifest);
            }
            Ok(None) => {}
            Err(err) => {
                response.status_code = FCPResponseStatus::FCPUnclassifiedError;
                response.error_msg =
                    rust_str_to_c_str(format!("couldn't load builtin actors: {}", err));
                return raw_ptr(response);
            }
        }

        let mut machine_context = network_config.for_epoch(chain_epoch, state_root);

        machine_context
            .set_base_fee(base_fee)
            .set_circulating_supply(base_circ_supply);

        if tracing {
            machine_context.enable_tracing();
        }
        let blockstore = blockstore.finish();

        let externs = CgoExterns::new(externs_id);
        let machine =
            fvm::machine::DefaultMachine::new(&ENGINE, &machine_context, blockstore, externs);
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

        if !apply_ret.exec_trace.is_empty() {
            let mut trace_iter = apply_ret.exec_trace.into_iter();
            if let Ok(Ok(lotus_t_bytes)) = build_lotus_trace(
                &trace_iter
                    .next()
                    .expect("already checked trace for emptiness"),
                &mut trace_iter,
            )
            .map(|lotus_trace| to_vec(&lotus_trace).map(|v| v.into_boxed_slice()))
            {
                response.exec_trace_ptr = lotus_t_bytes.as_ptr();
                response.exec_trace_len = lotus_t_bytes.len();
                Box::leak(lotus_t_bytes);
            }
        }

        if let Some(info) = apply_ret.failure_info {
            let info_bytes = info.to_string().into_boxed_str().into_boxed_bytes();
            response.failure_info_ptr = info_bytes.as_ptr();
            response.failure_info_len = info_bytes.len();
            Box::leak(info_bytes);
        }

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
        response.exit_code = apply_ret.msg_receipt.exit_code.value() as u64;
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

#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple)]
struct LotusTrace {
    pub msg: Message,
    pub msg_receipt: Receipt,
    pub error: String,
    pub subcalls: Vec<LotusTrace>,
}

fn build_lotus_trace(
    new_call: &ExecutionEvent,
    trace_iter: &mut impl Iterator<Item = ExecutionEvent>,
) -> anyhow::Result<LotusTrace> {
    let mut new_trace = LotusTrace {
        msg: match new_call {
            ExecutionEvent::Call(send_params) => Message {
                version: 0,
                from: Address::new_id(send_params.from),
                to: send_params.to,
                sequence: 0,
                value: send_params.value.clone(),
                method_num: send_params.method,
                params: send_params.params.clone(),
                gas_limit: 0,
                gas_fee_cap: TokenAmount::default(),
                gas_premium: TokenAmount::default(),
            },
            _ => {
                return Err(anyhow!("expected ExecutionEvent of type Call"));
            }
        },
        msg_receipt: Receipt {
            exit_code: ExitCode::OK,
            return_data: RawBytes::default(),
            gas_used: 0,
        },
        error: String::new(),
        subcalls: vec![],
    };

    while let Some(trace) = trace_iter.next() {
        match trace {
            ExecutionEvent::Return(res) => {
                new_trace.msg_receipt = match res {
                    Ok(InvocationResult::Return(return_data)) => Receipt {
                        exit_code: ExitCode::OK,
                        return_data,
                        gas_used: 0,
                    },
                    Ok(InvocationResult::Failure(exit_code)) => {
                        if exit_code.is_success() {
                            return Err(anyhow!("actor failed with status OK"));
                        }
                        Receipt {
                            exit_code,
                            return_data: Default::default(),
                            gas_used: 0,
                        }
                    }
                    Err(syscall_err) => {
                        // Errors indicate the message couldn't be dispatched at all
                        // (as opposed to failing during execution of the receiving actor).
                        // These errors are mapped to exit codes that persist on chain.
                        let exit_code = match syscall_err.1 {
                            ErrorNumber::InsufficientFunds => ExitCode::SYS_INSUFFICIENT_FUNDS,
                            ErrorNumber::NotFound => ExitCode::SYS_INVALID_RECEIVER,

                            ErrorNumber::IllegalArgument => ExitCode::SYS_ASSERTION_FAILED,
                            ErrorNumber::IllegalOperation => ExitCode::SYS_ASSERTION_FAILED,
                            ErrorNumber::LimitExceeded => ExitCode::SYS_ASSERTION_FAILED,
                            ErrorNumber::AssertionFailed => ExitCode::SYS_ASSERTION_FAILED,
                            ErrorNumber::InvalidHandle => ExitCode::SYS_ASSERTION_FAILED,
                            ErrorNumber::IllegalCid => ExitCode::SYS_ASSERTION_FAILED,
                            ErrorNumber::IllegalCodec => ExitCode::SYS_ASSERTION_FAILED,
                            ErrorNumber::Serialization => ExitCode::SYS_ASSERTION_FAILED,
                            ErrorNumber::Forbidden => ExitCode::SYS_ASSERTION_FAILED,
                        };

                        Receipt {
                            exit_code,
                            return_data: Default::default(),
                            gas_used: 0,
                        }
                    }
                };

                return Ok(new_trace);
            }

            _ => {
                new_trace
                    .subcalls
                    .push(build_lotus_trace(&trace, trace_iter)?);
            }
        };
    }

    Err(anyhow!("should have returned on an ExecutionEvent:Return"))
}

#[cfg(test)]
mod test {
    use crate::fvm::machine::build_lotus_trace;
    use fvm::kernel::SyscallError;
    use fvm::trace::{ExecutionEvent, SendParams};
    use fvm_ipld_encoding::RawBytes;
    use fvm_shared::address::Address;
    use fvm_shared::econ::TokenAmount;
    use fvm_shared::error::ErrorNumber::IllegalArgument;
    use fvm_shared::ActorID;

    #[test]
    fn test_lotus_trace() {
        let call_event = ExecutionEvent::Call(SendParams {
            from: ActorID::default(),
            method: 0,
            params: RawBytes::default(),
            to: Address::new_id(0),
            value: TokenAmount::default(),
        });
        let return_result =
            ExecutionEvent::Return(Err(SyscallError::new(IllegalArgument, "illegal")));
        let trace = vec![
            call_event.clone(),
            call_event.clone(),
            return_result.clone(),
            call_event.clone(),
            call_event,
            return_result.clone(),
            return_result.clone(),
            return_result,
        ];

        let mut trace_iter = trace.into_iter();

        let lotus_trace = build_lotus_trace(&trace_iter.next().unwrap(), &mut trace_iter).unwrap();

        assert!(trace_iter.next().is_none());

        assert_eq!(lotus_trace.subcalls.len(), 2);
        assert_eq!(lotus_trace.subcalls[0].subcalls.len(), 0);
        assert_eq!(lotus_trace.subcalls[1].subcalls.len(), 1);
        assert_eq!(lotus_trace.subcalls[1].subcalls[0].subcalls.len(), 0);
    }
}
