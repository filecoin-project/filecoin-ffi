use std::borrow::Cow;
use std::convert::{TryFrom, TryInto};
use std::sync::Mutex;

use anyhow::{anyhow, bail, Context};
use cid::Cid;
use fvm::call_manager::DefaultCallManager;
use fvm::executor::{ApplyKind, DefaultExecutor, Executor, ThreadedExecutor};
use fvm::gas::GasCharge;
use fvm::machine::{DefaultMachine, MultiEngine};
use fvm::trace::ExecutionEvent;
use fvm::DefaultKernel;
use fvm_ipld_encoding::tuple::{Deserialize_tuple, Serialize_tuple};
use fvm_ipld_encoding::{to_vec, CborStore, RawBytes};
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

type CgoMachine = DefaultMachine<OverlayBlockstore<CgoBlockstore>, CgoExterns>;
type BaseExecutor = DefaultExecutor<DefaultKernel<DefaultCallManager<CgoMachine>>>;

pub type CgoExecutor = ThreadedExecutor<BaseExecutor>;

fn new_executor(machine: CgoMachine) -> CgoExecutor {
    ThreadedExecutor(BaseExecutor::new(machine))
}

lazy_static! {
    static ref ENGINES: MultiEngine = MultiEngine::new();
}

#[allow(clippy::too_many_arguments)]
fn create_fvm_machine_generic(
    fvm_version: FvmRegisteredVersion,
    chain_epoch: u64,
    base_fee_hi: u64,
    base_fee_lo: u64,
    base_circ_supply_hi: u64,
    base_circ_supply_lo: u64,
    network_version: u64,
    state_root: c_slice::Ref<u8>,
    manifest_cid: Option<c_slice::Ref<u8>>,
    actor_redirect: Option<c_slice::Ref<u8>>,
    actor_debug: bool,
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

            let base_circ_supply = TokenAmount::from_atto(
                ((base_circ_supply_hi as u128) << u64::BITS) | base_circ_supply_lo as u128,
            );
            let base_fee =
                TokenAmount::from_atto(((base_fee_hi as u128) << u64::BITS) | base_fee_lo as u128);

            let network_version = NetworkVersion::try_from(network_version as u32)
                .map_err(|_| anyhow!("unsupported network version: {}", network_version))?;
            let state_root = Cid::try_from(&state_root[..])
                .map_err(|err| anyhow!("invalid state root: {}", err))?;

            // There may be no manifest CID:
            // - for pre nv16, use the builtin bundles
            // - for nv16 or higher, it means we have already migrated state for system
            //   actor and we can pass None to the machine constructor to fish it from state.
            // The presence of the manifest cid argument allows us to test with new bundles
            // with minimum friction.
            let manifest_cid = manifest_cid
                .as_deref() // into a slice
                .map(Cid::try_from) // into a cid
                .transpose() // Option<Result<Cid>> -> Result<Option<Cid>>
                .context("invalid manifest")?;

            let blockstore = FakeBlockstore::new(CgoBlockstore::new(blockstore_id));

            let mut network_config = NetworkConfig::new(network_version);
            if let Some(manifest) = manifest_cid {
                network_config.override_actors(manifest);
            }

            if actor_debug {
                network_config.enable_actor_debugging();
            }

            let blockstore = blockstore.finish();
            if let Some(ar) = actor_redirect {
                let actor_redirect_cid = Cid::try_from(&ar[..])
                    .map_err(|err| anyhow!("invalid redirect CID: {}", err))?;
                let redirect: Vec<(Cid, Cid)> = match blockstore
                    .get_cbor(&actor_redirect_cid)
                    .map_err(|err| anyhow!("invalid redirect cid: {}", err))?
                {
                    Some(v) => v,
                    None => bail!("failed to create engine: missing redirect vector"),
                };
                network_config.redirect_actors(redirect);
            }

            let mut machine_context = network_config.for_epoch(chain_epoch, state_root);

            machine_context
                .set_base_fee(base_fee)
                .set_circulating_supply(base_circ_supply);

            if tracing {
                machine_context.enable_tracing();
            }

            let externs = CgoExterns::new(externs_id);

            let engine = match ENGINES.get(&network_config) {
                Ok(e) => e,
                Err(err) => bail!("failed to create engine: {}", err),
            };

            let machine = CgoMachine::new(&engine, &machine_context, blockstore, externs)?;

            Ok(Some(repr_c::Box::new(InnerFvmMachine {
                machine: Some(Mutex::new(new_executor(machine))),
            })))
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
    create_fvm_machine_generic(
        fvm_version,
        chain_epoch,
        base_fee_hi,
        base_fee_lo,
        base_circ_supply_hi,
        base_circ_supply_lo,
        network_version,
        state_root,
        if manifest_cid.is_empty() {
            None
        } else {
            Some(manifest_cid)
        },
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
    base_fee_hi: u64,
    base_fee_lo: u64,
    base_circ_supply_hi: u64,
    base_circ_supply_lo: u64,
    network_version: u64,
    state_root: c_slice::Ref<u8>,
    actor_redirect: c_slice::Ref<u8>,
    tracing: bool,
    blockstore_id: u64,
    externs_id: u64,
) -> repr_c::Box<Result<FvmMachine>> {
    create_fvm_machine_generic(
        fvm_version,
        chain_epoch,
        base_fee_hi,
        base_fee_lo,
        base_circ_supply_hi,
        base_circ_supply_lo,
        network_version,
        state_root,
        None,
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

        let message: Message = fvm_ipld_encoding::from_slice(&message)?;

        let mut executor = executor
            .machine
            .as_ref()
            .expect("missing executor")
            .lock()
            .unwrap();
        let apply_ret = executor.execute_message(message, apply_kind, chain_len as usize)?;

        let exec_trace = if !apply_ret.exec_trace.is_empty() {
            let mut trace_iter = apply_ret.exec_trace.into_iter();
            build_lotus_trace(
                &(&mut trace_iter)
                    // Skip gas charges before the first call, if any. Lotus can't handle them.
                    .find(|item| !matches!(item, &ExecutionEvent::GasCharge(_)))
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
        let penalty: u128 = apply_ret.penalty.atto().try_into().unwrap();
        let miner_tip: u128 = apply_ret.miner_tip.atto().try_into().unwrap();
        let base_fee_burn: u128 = apply_ret.base_fee_burn.atto().try_into().unwrap();
        let over_estimation_burn: u128 = apply_ret.over_estimation_burn.atto().try_into().unwrap();
        let refund: u128 = apply_ret.refund.atto().try_into().unwrap();
        let gas_refund = apply_ret.gas_refund;
        let gas_burned = apply_ret.gas_burned;

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
        let cid = executor.0.flush()?;

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

#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple)]
struct LotusGasCharge {
    pub name: Cow<'static, str>,
    pub total_gas: i64,
    pub compute_gas: i64,
    pub storage_gas: i64,
}

#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple)]
struct LotusTrace {
    pub msg: Message,
    pub msg_receipt: Receipt,
    pub error: String,
    pub gas_charges: Vec<LotusGasCharge>,
    pub subcalls: Vec<LotusTrace>,
}

fn build_lotus_trace(
    new_call: &ExecutionEvent,
    trace_iter: &mut impl Iterator<Item = ExecutionEvent>,
) -> anyhow::Result<LotusTrace> {
    let mut new_trace = LotusTrace {
        msg: match new_call {
            ExecutionEvent::Call {
                from,
                to,
                method,
                params,
                value,
            } => Message {
                version: 0,
                from: Address::new_id(*from),
                to: *to,
                sequence: 0,
                value: value.clone(),
                method_num: *method,
                params: params.clone(),
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
        gas_charges: vec![],
        subcalls: vec![],
    };

    while let Some(trace) = trace_iter.next() {
        match trace {
            ExecutionEvent::Call { .. } => {
                new_trace
                    .subcalls
                    .push(build_lotus_trace(&trace, trace_iter)?);
            }
            ExecutionEvent::CallReturn(return_data) => {
                new_trace.msg_receipt = Receipt {
                    exit_code: ExitCode::OK,
                    return_data,
                    gas_used: 0,
                };
                return Ok(new_trace);
            }
            ExecutionEvent::CallAbort(exit_code) => {
                if exit_code.is_success() {
                    return Err(anyhow!("actor failed with status OK"));
                }
                new_trace.msg_receipt = Receipt {
                    exit_code,
                    return_data: Default::default(),
                    gas_used: 0,
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

                new_trace.msg_receipt = Receipt {
                    exit_code,
                    return_data: Default::default(),
                    gas_used: 0,
                };
                return Ok(new_trace);
            }
            ExecutionEvent::GasCharge(GasCharge {
                name,
                compute_gas,
                storage_gas,
            }) => {
                new_trace.gas_charges.push(LotusGasCharge {
                    name,
                    total_gas: (compute_gas + storage_gas).round_up(),
                    compute_gas: compute_gas.round_up(),
                    storage_gas: storage_gas.round_up(),
                });
            }
            _ => (), // ignore unknown events.
        };
    }

    Err(anyhow!("should have returned on an ExecutionEvent:Return"))
}

#[cfg(test)]
mod test {
    use crate::fvm::machine::build_lotus_trace;
    use fvm::kernel::SyscallError;
    use fvm::trace::ExecutionEvent;
    use fvm_ipld_encoding::RawBytes;
    use fvm_shared::address::Address;
    use fvm_shared::econ::TokenAmount;
    use fvm_shared::error::ErrorNumber::IllegalArgument;
    use fvm_shared::ActorID;

    #[test]
    fn test_lotus_trace() {
        let call_event = ExecutionEvent::Call {
            from: ActorID::default(),
            method: 0,
            params: RawBytes::default(),
            to: Address::new_id(0),
            value: TokenAmount::default(),
        };
        let return_result =
            ExecutionEvent::CallError(SyscallError::new(IllegalArgument, "illegal"));
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
