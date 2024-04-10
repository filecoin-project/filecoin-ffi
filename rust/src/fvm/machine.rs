use std::borrow::Cow;
use std::convert::{TryFrom, TryInto};
use std::ops::RangeInclusive;

use anyhow::{anyhow, Context};
use cid::Cid;
use fvm4::executor::ApplyKind;
use fvm4::gas::GasCharge;
use fvm4::trace::ExecutionEvent;
use fvm4_shared::address::Address;
use fvm4_shared::state::ActorState;
use fvm4_shared::{ActorID, MethodNum};
use fvm_ipld_encoding::ipld_block::IpldBlock;
use fvm_ipld_encoding::tuple::{Deserialize_tuple, Serialize_tuple};
use fvm_ipld_encoding::{strict_bytes, to_vec, CborStore};

use fvm4_shared::error::{ErrorNumber, ExitCode};
use fvm4_shared::receipt::Receipt;
use fvm4_shared::{econ::TokenAmount, message::Message};
use lazy_static::lazy_static;
use log::info;
use safer_ffi::prelude::*;

use super::blockstore::CgoBlockstore;
use super::engine::*;
use super::externs::CgoExterns;
use super::types::*;
use crate::destructor;
use crate::util::types::{catch_panic_response, catch_panic_response_no_default, Result};

const STACK_SIZE: usize = 64 << 20; // 64MiB

lazy_static! {
    static ref CONCURRENCY: u32 = get_concurrency();
    static ref ENGINES: MultiEngineContainer = MultiEngineContainer::with_concurrency(*CONCURRENCY);
    static ref THREAD_POOL: yastl::Pool = yastl::Pool::with_config(
        *CONCURRENCY as usize,
        yastl::ThreadConfig::new()
            .prefix("fvm")
            .stack_size(STACK_SIZE)
    );
}

const LOTUS_FVM_CONCURRENCY_ENV_NAME: &str = "LOTUS_FVM_CONCURRENCY";
const VALID_CONCURRENCY_RANGE: RangeInclusive<u32> = 1..=256;

fn available_parallelism() -> u32 {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(8) as u32
}

fn get_concurrency() -> u32 {
    let valosstr = match std::env::var_os(LOTUS_FVM_CONCURRENCY_ENV_NAME) {
        Some(v) => v,
        None => return available_parallelism(),
    };
    let valstr = match valosstr.to_str() {
        Some(s) => s,
        None => {
            log::error!("{LOTUS_FVM_CONCURRENCY_ENV_NAME} has invalid value");
            return available_parallelism();
        }
    };
    let concurrency: u32 = match valstr.parse() {
        Ok(v) => v,
        Err(e) => {
            log::error!("{LOTUS_FVM_CONCURRENCY_ENV_NAME} has invalid value: {e}");
            return available_parallelism();
        }
    };
    if !VALID_CONCURRENCY_RANGE.contains(&concurrency) {
        log::error!(
            "{LOTUS_FVM_CONCURRENCY_ENV_NAME} must be in the range {VALID_CONCURRENCY_RANGE:?}, not {concurrency}"
        );
        return available_parallelism();
    }
    concurrency
}

#[allow(clippy::too_many_arguments)]
fn create_fvm_machine_generic(
    fvm_version: FvmRegisteredVersion,
    chain_epoch: u64,
    chain_timestamp: u64,
    chain_id: u64,
    base_fee_hi: u64,
    base_fee_lo: u64,
    circulating_supply_hi: u64,
    circulating_supply_lo: u64,
    network_version: u32,
    state_root: c_slice::Ref<u8>,
    actor_redirect: Option<c_slice::Ref<u8>>,
    actor_debugging: bool,
    tracing: bool,
    blockstore_id: u64,
    externs_id: u64,
) -> repr_c::Box<Result<FvmMachine>> {
    unsafe {
        catch_panic_response_no_default("create_fvm_machine", || {
            match fvm_version {
                FvmRegisteredVersion::V1 => info!("using FVM V1"),
                //_ => panic!("unsupported FVM Registered Version")
            }

            let circulating_supply = TokenAmount::from_atto(
                ((circulating_supply_hi as u128) << u64::BITS) | circulating_supply_lo as u128,
            );
            let base_fee =
                TokenAmount::from_atto(((base_fee_hi as u128) << u64::BITS) | base_fee_lo as u128);

            let state_root = Cid::try_from(&state_root[..])
                .map_err(|err| anyhow!("invalid state root: {}", err))?;

            let blockstore = CgoBlockstore::new(blockstore_id);

            let actor_redirect = actor_redirect
                .map(|ar| Cid::try_from(&ar[..]).context("invalid redirect CID"))
                .transpose()?
                .map(|k| {
                    blockstore
                        .get_cbor(&k)
                        .context("blockstore error when looking up actor redirects")?
                        .context("failed to create engine: missing redirect vector")
                })
                .transpose()?
                .unwrap_or_default();

            let config = Config {
                network_version,
                chain_id,
                chain_epoch,
                chain_timestamp,
                state_root,
                base_fee,
                circulating_supply,
                tracing,
                actor_debugging,
                actor_redirect,
            };

            let externs = CgoExterns::new(externs_id);

            let engine = ENGINES.get(network_version)?;
            Ok(Some(repr_c::Box::new(
                engine.new_executor(config, blockstore, externs)?,
            )))
        })
    }
}

/// Note: the incoming args as u64 and odd conversions to i32/i64
/// for some types is due to the generated bindings not liking the
/// 32bit types as incoming args
///
#[ffi_export]
fn create_fvm_machine(
    fvm_version: FvmRegisteredVersion,
    chain_epoch: u64,
    chain_timestamp: u64,
    chain_id: u64,
    base_fee_hi: u64,
    base_fee_lo: u64,
    circulating_supply_hi: u64,
    circulating_supply_lo: u64,
    network_version: u32,
    state_root: c_slice::Ref<u8>,
    tracing: bool,
    blockstore_id: u64,
    externs_id: u64,
) -> repr_c::Box<Result<FvmMachine>> {
    create_fvm_machine_generic(
        fvm_version,
        chain_epoch,
        chain_timestamp,
        chain_id,
        base_fee_hi,
        base_fee_lo,
        circulating_supply_hi,
        circulating_supply_lo,
        network_version,
        state_root,
        None,
        false,
        tracing,
        blockstore_id,
        externs_id,
    )
}

#[ffi_export]
fn create_fvm_debug_machine(
    fvm_version: FvmRegisteredVersion,
    chain_epoch: u64,
    chain_timestamp: u64,
    chain_id: u64,
    base_fee_hi: u64,
    base_fee_lo: u64,
    circulating_supply_hi: u64,
    circulating_supply_lo: u64,
    network_version: u32,
    state_root: c_slice::Ref<u8>,
    actor_redirect: c_slice::Ref<u8>,
    tracing: bool,
    blockstore_id: u64,
    externs_id: u64,
) -> repr_c::Box<Result<FvmMachine>> {
    create_fvm_machine_generic(
        fvm_version,
        chain_epoch,
        chain_timestamp,
        chain_id,
        base_fee_hi,
        base_fee_lo,
        circulating_supply_hi,
        circulating_supply_lo,
        network_version,
        state_root,
        if actor_redirect.is_empty() {
            None
        } else {
            Some(actor_redirect)
        },
        true,
        tracing,
        blockstore_id,
        externs_id,
    )
}

fn with_new_stack<F, T>(name: &str, pool: &yastl::Pool, callback: F) -> repr_c::Box<Result<T>>
where
    T: Sized + Default + Send,
    F: FnOnce() -> anyhow::Result<T> + std::panic::UnwindSafe + Send,
{
    let mut res = None;
    pool.scoped(|scope| scope.execute(|| res = Some(catch_panic_response(name, callback))));

    res.unwrap_or_else(|| {
        repr_c::Box::new(Result::err(
            format!("failed to schedule {name}")
                .into_bytes()
                .into_boxed_slice(),
        ))
    })
}

#[ffi_export]
fn fvm_machine_execute_message(
    executor: &'_ InnerFvmMachine,
    message: c_slice::Ref<u8>,
    chain_len: u64,
    apply_kind: u64, /* 0: Explicit, _: Implicit */
) -> repr_c::Box<Result<FvmMachineExecuteResponse>> {
    // Execute in the thread-pool because we need a 64MiB stack.
    with_new_stack("fvm_machine_execute_message", &THREAD_POOL, || {
        let apply_kind = if apply_kind == 0 {
            ApplyKind::Explicit
        } else {
            ApplyKind::Implicit
        };

        let message: Message = fvm_ipld_encoding::from_slice(&message)?;

        let mut executor = executor
            .machine
            .as_ref()
            .context("missing executor")?
            .lock()
            .map_err(|e| anyhow!("executor lock poisoned: {e}"))?;
        let apply_ret = executor.execute_message(message, apply_kind, chain_len as usize)?;

        let exec_trace = if !apply_ret.exec_trace.is_empty() {
            let mut trace_iter = apply_ret.exec_trace.into_iter();
            let mut initial_gas_charges = Vec::new();
            loop {
                match trace_iter.next() {
                    Some(gc @ ExecutionEvent::GasCharge(_)) => initial_gas_charges.push(gc),
                    Some(ExecutionEvent::Call {
                        from,
                        to,
                        method,
                        params,
                        value,
                        gas_limit,
                        read_only,
                    }) => {
                        break build_lotus_trace(
                            from,
                            to,
                            method,
                            params,
                            value,
                            gas_limit,
                            read_only,
                            &mut initial_gas_charges.into_iter().chain(&mut trace_iter),
                        )
                        .ok()
                    }
                    // Skip anything unexpected.
                    Some(_) => {}
                    // Return none if we don't even have a call.
                    None => break None,
                }
            }
        } else {
            None
        }
        .and_then(|t| to_vec(&t).ok())
        .map(|trace| trace.into_boxed_slice().into());

        let failure_info = apply_ret
            .failure_info
            .map(|info| info.to_string().into_boxed_str().into());

        // TODO: use the non-bigint token amount everywhere in the FVM
        let penalty: u128 = apply_ret
            .penalty
            .atto()
            .try_into()
            .context("penalty exceeds u128 attoFIL")?;
        let miner_tip: u128 = apply_ret
            .miner_tip
            .atto()
            .try_into()
            .context("miner tip exceeds u128 attoFIL")?;
        let base_fee_burn: u128 = apply_ret
            .base_fee_burn
            .atto()
            .try_into()
            .context("base fee burn exceeds u128 attoFIL")?;
        let over_estimation_burn: u128 = apply_ret
            .over_estimation_burn
            .atto()
            .try_into()
            .context("overestimation burn exceeds u128 attoFIL")?;
        let refund: u128 = apply_ret
            .refund
            .atto()
            .try_into()
            .context("refund exceeds u128 attoFIL")?;
        let gas_refund = apply_ret.gas_refund;
        let gas_burned = apply_ret.gas_burned;

        let Receipt {
            exit_code,
            return_data,
            gas_used,
            events_root,
        } = apply_ret.msg_receipt;

        let return_val = if return_data.is_empty() {
            None
        } else {
            let bytes: Vec<u8> = return_data.into();
            Some(bytes.into_boxed_slice().into())
        };

        let events = if apply_ret.events.is_empty() {
            None
        } else {
            // This field is informational, if for whatever reason we fail to serialize
            // return a None and move on. What's important for consensus is the
            // events_root in the receipt.
            to_vec(&apply_ret.events)
                .map_err(|err| {
                    log::warn!("[UNEXPECTED] failed to serialize events: {}", err);
                    err
                })
                .ok()
                .map(|evts| evts.into_boxed_slice().into())
        };

        let events_root = events_root.map(|cid| cid.to_bytes().into_boxed_slice().into());

        Ok(FvmMachineExecuteResponse {
            exit_code: exit_code.value() as u64,
            return_val,
            gas_used,
            penalty_hi: (penalty >> u64::BITS) as u64,
            penalty_lo: penalty as u64,
            miner_tip_hi: (miner_tip >> u64::BITS) as u64,
            miner_tip_lo: miner_tip as u64,
            base_fee_burn_hi: (base_fee_burn >> u64::BITS) as u64,
            base_fee_burn_lo: base_fee_burn as u64,
            over_estimation_burn_hi: (over_estimation_burn >> u64::BITS) as u64,
            over_estimation_burn_lo: over_estimation_burn as u64,
            refund_hi: (refund >> u64::BITS) as u64,
            refund_lo: refund as u64,
            gas_refund,
            gas_burned,
            exec_trace,
            failure_info,
            events,
            events_root,
        })
    })
}

#[ffi_export]
fn fvm_machine_flush(executor: &'_ InnerFvmMachine) -> repr_c::Box<Result<c_slice::Box<u8>>> {
    catch_panic_response("fvm_machine_flush", || {
        let mut executor = executor
            .machine
            .as_ref()
            .context("missing executor")?
            .lock()
            .map_err(|e| anyhow!("executor lock poisoned: {e}"))?;
        let cid = executor.flush()?;

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

#[derive(Clone, Debug, PartialEq, Eq, Serialize_tuple, Deserialize_tuple)]
struct LotusGasCharge {
    pub name: Cow<'static, str>,
    pub total_gas: u64,
    pub compute_gas: u64,
    pub other_gas: u64,
    pub duration_nanos: u64,
}

#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple)]
struct Trace {
    pub msg: TraceMessage,
    pub msg_ret: TraceReturn,
    pub msg_invoked: Option<TraceActor>,
    pub gas_charges: Vec<LotusGasCharge>,
    pub subcalls: Vec<Trace>,
}

#[derive(Serialize_tuple, Deserialize_tuple, Debug, PartialEq, Eq, Clone)]
pub struct TraceMessage {
    pub from: Address,
    pub to: Address,
    pub value: TokenAmount,
    pub method_num: MethodNum,
    #[serde(with = "strict_bytes")]
    pub params: Vec<u8>,
    pub codec: u64,
    pub gas_limit: u64,
    pub read_only: bool,
}

#[derive(Serialize_tuple, Deserialize_tuple, Debug, PartialEq, Eq, Clone)]
pub struct TraceActor {
    pub actor_id: ActorID,
    pub actor_state: ActorState,
}

#[derive(Serialize_tuple, Deserialize_tuple, Debug, PartialEq, Eq, Clone)]
pub struct TraceReturn {
    pub exit_code: ExitCode,
    #[serde(with = "strict_bytes")]
    pub return_data: Vec<u8>,
    pub codec: u64,
}

#[allow(clippy::too_many_arguments)]
fn build_lotus_trace(
    from: u64,
    to: Address,
    method: u64,
    params: Option<IpldBlock>,
    value: TokenAmount,
    gas_limit: u64,
    read_only: bool,
    trace_iter: &mut impl Iterator<Item = ExecutionEvent>,
) -> anyhow::Result<Trace> {
    let params = params.unwrap_or_default();
    let mut new_trace = Trace {
        msg: TraceMessage {
            from: Address::new_id(from),
            to,
            value,
            method_num: method,
            params: params.data,
            codec: params.codec,
            gas_limit,
            read_only,
        },
        msg_invoked: None,
        msg_ret: TraceReturn {
            exit_code: ExitCode::OK,
            return_data: Vec::new(),
            codec: 0,
        },
        gas_charges: vec![],
        subcalls: vec![],
    };

    while let Some(trace) = trace_iter.next() {
        match trace {
            ExecutionEvent::Call {
                from,
                to,
                method,
                params,
                value,
                gas_limit,
                read_only,
            } => {
                new_trace.subcalls.push(build_lotus_trace(
                    from, to, method, params, value, gas_limit, read_only, trace_iter,
                )?);
            }
            ExecutionEvent::InvokeActor { id, state } => {
                new_trace.msg_invoked = Some(TraceActor {
                    actor_id: id,
                    actor_state: state,
                })
            }
            ExecutionEvent::CallReturn(exit_code, return_data) => {
                let return_data = return_data.unwrap_or_default();
                new_trace.msg_ret = TraceReturn {
                    exit_code,
                    return_data: return_data.data,
                    codec: return_data.codec,
                };
                return Ok(new_trace);
            }
            ExecutionEvent::CallError(syscall_err) => {
                // Errors indicate the message couldn't be dispatched at all
                // (as opposed to failing during execution of the receiving actor).
                // These errors are mapped to exit codes that persist on chain.
                let exit_code = match syscall_err.1 {
                    ErrorNumber::InsufficientFunds => ExitCode::SYS_INSUFFICIENT_FUNDS,
                    ErrorNumber::NotFound => ExitCode::SYS_INVALID_RECEIVER,
                    _ => ExitCode::SYS_ASSERTION_FAILED,
                };

                new_trace.msg_ret = TraceReturn {
                    exit_code,
                    return_data: Default::default(),
                    codec: 0,
                };
                return Ok(new_trace);
            }
            ExecutionEvent::GasCharge(GasCharge {
                name,
                compute_gas,
                other_gas,
                elapsed,
            }) => {
                new_trace.gas_charges.push(LotusGasCharge {
                    name,
                    total_gas: (compute_gas + other_gas).round_up(),
                    compute_gas: compute_gas.round_up(),
                    other_gas: other_gas.round_up(),
                    duration_nanos: elapsed
                        .get()
                        .copied()
                        .unwrap_or_default()
                        .as_nanos()
                        .try_into()
                        .unwrap_or(u64::MAX),
                });
            }
            _ => (), // ignore unknown events.
        };
    }

    Err(anyhow!("should have returned on an ExecutionEvent:Return"))
}

#[cfg(test)]
mod test {
    use crate::fvm::machine::{build_lotus_trace, LotusGasCharge};
    use fvm4::gas::Gas;
    use fvm4::gas::GasCharge;
    use fvm4::kernel::SyscallError;
    use fvm4::trace::ExecutionEvent;
    use fvm4_shared::address::Address;
    use fvm4_shared::econ::TokenAmount;
    use fvm4_shared::error::ErrorNumber::IllegalArgument;
    use fvm4_shared::ActorID;

    #[test]
    fn test_lotus_trace() {
        let call_event = ExecutionEvent::Call {
            from: ActorID::default(),
            method: 0,
            params: None,
            to: Address::new_id(0),
            value: TokenAmount::default(),
            gas_limit: u64::MAX,
            read_only: false,
        };
        let return_result =
            ExecutionEvent::CallError(SyscallError::new(IllegalArgument, "illegal"));
        let initial_gas_charge = GasCharge::new("gas_test", Gas::new(1), Gas::new(2));
        let trace = vec![
            ExecutionEvent::GasCharge(initial_gas_charge.clone()),
            call_event.clone(),
            return_result.clone(),
            call_event.clone(),
            call_event,
            return_result.clone(),
            return_result.clone(),
            return_result,
        ];

        let mut trace_iter = trace.into_iter();

        let lotus_trace = build_lotus_trace(
            0,
            Address::new_id(0),
            0,
            None,
            TokenAmount::default(),
            u64::MAX,
            false,
            &mut trace_iter,
        )
        .unwrap();

        assert!(trace_iter.next().is_none());

        assert_eq!(lotus_trace.gas_charges.len(), 1);
        assert_eq!(
            *lotus_trace.gas_charges.get(0).unwrap(),
            LotusGasCharge {
                name: initial_gas_charge.clone().name,
                total_gas: initial_gas_charge.total().round_up(),
                compute_gas: initial_gas_charge.compute_gas.round_up(),
                other_gas: initial_gas_charge.other_gas.round_up(),
                duration_nanos: initial_gas_charge
                    .elapsed
                    .get()
                    .copied()
                    .unwrap_or_default()
                    .as_nanos() as u64,
            }
        );
        assert_eq!(lotus_trace.subcalls.len(), 2);
        assert_eq!(lotus_trace.subcalls[0].subcalls.len(), 0);
        assert_eq!(lotus_trace.subcalls[1].subcalls.len(), 1);
        assert_eq!(lotus_trace.subcalls[1].subcalls[0].subcalls.len(), 0);
    }
}
