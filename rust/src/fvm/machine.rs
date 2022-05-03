use std::convert::{TryFrom, TryInto};
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::sync::Mutex;
use std::time::Instant;

use anyhow::{anyhow, bail};
use cid::Cid;
use futures::executor::block_on;
use fvm::call_manager::{DefaultCallManager, InvocationResult};
use fvm::executor::{ApplyKind, DefaultExecutor, Executor};
use fvm::machine::{DefaultMachine, Machine};
use fvm::trace::ExecutionEvent;
use fvm::DefaultKernel;
use fvm_ipld_blockstore::Blockstore;
use fvm_ipld_car::load_car;
use fvm_ipld_encoding::tuple::{Deserialize_tuple, Serialize_tuple};
use fvm_ipld_encoding::{to_vec, RawBytes};
use fvm_shared::address::Address;
use fvm_shared::error::{ErrorNumber, ExitCode};
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

lazy_static! {
    static ref TIMING_LOG: Option<Mutex<BufWriter<File>>> = env::var_os("FVM_TIMING_LOG")
        .and_then(|path| OpenOptions::new().create(true).append(true).open(path).ok())
        .map(BufWriter::new)
        .map(Mutex::new);
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
    tracing: bool,
    blockstore_id: u64,
    externs_id: u64,
) -> repr_c::Box<Result<FvmMachine>> {
    use fvm::machine::NetworkConfig;
    unsafe {
        catch_panic_response_no_default("create_fvm_machine", || {
            match fvm_version {
                FvmRegisteredVersion::V1 => info!("using FVM V1"),
                //_ => panic!("unsupported FVM Registered Version")
            }

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

            let mut network_config = NetworkConfig::new(network_version);
            match import_actors(&blockstore, manifest_cid, network_version) {
                Ok(Some(manifest)) => {
                    network_config.override_actors(manifest);
                }
                Ok(None) => {}
                Err(err) => bail!("couldn't load builtin actors: {}", err),
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
                fvm::machine::DefaultMachine::new(&ENGINE, &machine_context, blockstore, externs)
                    .map_err(|err| anyhow!("failed to create machine: {}", err))?;

            Ok(Some(repr_c::Box::new(InnerFvmMachine {
                machine: Some(Mutex::new(CgoExecutor::new(machine))),
            })))
        })
    }
}

#[ffi_export]
fn fvm_machine_execute_message(
    executor: &'_ InnerFvmMachine,
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

        let start = Instant::now();
        let message: Message = fvm_ipld_encoding::from_slice(&message)?;

        let recipient = message.to;
        let method_num = message.method_num;

        let mut executor = executor
            .machine
            .as_ref()
            .expect("missing executor")
            .lock()
            .unwrap();
        let apply_ret = executor.execute_message(message, apply_kind, chain_len as usize)?;

        // Dump execution stats if supplied.
        let duration = start.elapsed();
        if let (ApplyKind::Explicit, Some(mut log), Some(stats)) = (
            apply_kind,
            TIMING_LOG.as_ref().and_then(|l| l.lock().ok()),
            &apply_ret.exec_stats,
        ) {
            let code = executor
                .state_tree()
                .get_actor(&recipient)
                .ok()
                .flatten()
                .map(|a| a.code);
            let _ = writeln!(
                log,
                r#"{{"type":"apply","epoch":{},"fuel":{},"wasm_time":{},"call_overhead":{},"gas":{},"compute_gas":{},"num_actor_calls":{},"num_syscalls":{},"num_externs":{},"block_bytes_read":{},"block_bytes_written":{},"time":{},"code":{},"method":{}}}"#,
                executor.context().epoch,
                stats.fuel_used,
                stats.wasm_duration.as_nanos(),
                if stats.call_count > 0 {
                    format!(
                        "{}",
                        stats.call_overhead.as_nanos() / stats.call_count as u128
                    )
                } else {
                    "null".to_owned()
                },
                apply_ret.msg_receipt.gas_used,
                stats.compute_gas,
                stats.call_count,
                stats.num_syscalls,
                stats.num_externs,
                stats.block_bytes_read,
                stats.block_bytes_written,
                duration.as_nanos(),
                code.map(|c| format!(r#""{}""#, c))
                    .unwrap_or_else(|| String::from("null")),
                method_num,
            );
        }

        let exec_trace = if !apply_ret.exec_trace.is_empty() {
            let mut trace_iter = apply_ret.exec_trace.into_iter();
            build_lotus_trace(
                &trace_iter
                    .next()
                    .expect("already checked trace for emptiness"),
                &mut trace_iter,
            )
            .ok()
            .and_then(|t| to_vec(&t).ok())
            .map(|trace| trace.into_boxed_slice().into())
        } else {
            None
        };

        let failure_info = apply_ret
            .failure_info
            .map(|info| info.to_string().into_boxed_str().into());

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
            exit_code: exit_code.value() as u64,
            return_val,
            gas_used: gas_used as u64,
            penalty_hi: (penalty >> u64::BITS) as u64,
            penalty_lo: penalty as u64,
            miner_tip_hi: (miner_tip >> u64::BITS) as u64,
            miner_tip_lo: miner_tip as u64,
            exec_trace,
            failure_info,
        })
    })
}

#[ffi_export]
fn fvm_machine_flush(executor: &'_ InnerFvmMachine) -> repr_c::Box<Result<c_slice::Box<u8>>> {
    catch_panic_response("fvm_machine_flush", || {
        let mut executor = executor
            .machine
            .as_ref()
            .expect("missing executor")
            .lock()
            .unwrap();

        let start = Instant::now();

        let cid = executor.flush()?;

        let duration = start.elapsed();
        if let Some(mut log) = TIMING_LOG.as_ref().and_then(|l| l.lock().ok()) {
            let _ = writeln!(
                log,
                r#"{{"type":"flush","epoch":{},"time":{}}}"#,
                executor.context().epoch,
                duration.as_nanos()
            );
            let _ = log.flush();
        }

        Ok(cid.to_bytes().into_boxed_slice().into())
    })
}

destructor!(drop_fvm_machine, InnerFvmMachine);
destructor!(destroy_create_fvm_machine_response, Result<FvmMachine>);

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
