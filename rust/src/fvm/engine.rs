use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::anyhow;
use cid::Cid;
use num_traits::FromPrimitive;

use fvm2::call_manager::{backtrace::Cause as Cause2, DefaultCallManager as DefaultCallManager2};
use fvm3::call_manager::{
    backtrace::Backtrace, backtrace::Cause, backtrace::Frame,
    DefaultCallManager as DefaultCallManager3,
};

use fvm2::trace::ExecutionEvent as ExecutionEvent2;
use fvm3::trace::ExecutionEvent;

use fvm3::gas::{Gas, GasCharge};

use fvm3::kernel::SyscallError;

use fvm2::executor::{
    ApplyFailure as ApplyFailure2, ApplyKind as ApplyKind2, DefaultExecutor as DefaultExecutor2,
    ThreadedExecutor as ThreadedExecutor2,
};
use fvm3::executor::{
    ApplyFailure, ApplyKind, ApplyRet, DefaultExecutor as DefaultExecutor3,
    ThreadedExecutor as ThreadedExecutor3,
};

use fvm2::machine::{
    DefaultMachine as DefaultMachine2, MachineContext as MachineContext2,
    MultiEngine as MultiEngine2, NetworkConfig as NetworkConfig2,
};
use fvm3::machine::{
    DefaultMachine as DefaultMachine3, MachineContext, MultiEngine as MultiEngine3, NetworkConfig,
};

use fvm2::DefaultKernel as DefaultKernel2;
use fvm3::DefaultKernel as DefaultKernel3;

use fvm2::gas::PriceList as PriceList2;
use fvm3::gas::PriceList as PriceList3;

use fvm3_shared::{
    address::Address, econ::TokenAmount, error::ErrorNumber, error::ExitCode, message::Message,
    receipt::Receipt, version::NetworkVersion,
};

use fvm2_shared::{
    address::Address as Address2, econ::TokenAmount as TokenAmount2, message::Message as Message2,
    version::NetworkVersion as NetworkVersion2,
};

use fvm2_ipld_encoding::RawBytes as RawBytes2;
use fvm3_ipld_encoding::RawBytes;

use super::blockstore::{CgoBlockstore, OverlayBlockstore};
use super::externs::CgoExterns;
use super::types::*;

pub type CgoMachine3 = DefaultMachine3<OverlayBlockstore<CgoBlockstore>, CgoExterns>;
pub type BaseExecutor3 = DefaultExecutor3<DefaultKernel3<DefaultCallManager3<CgoMachine3>>>;
pub type CgoExecutor3 = ThreadedExecutor3<BaseExecutor3>;

pub type CgoMachine2 = DefaultMachine2<OverlayBlockstore<CgoBlockstore>, CgoExterns>;
pub type BaseExecutor2 = DefaultExecutor2<DefaultKernel2<DefaultCallManager2<CgoMachine2>>>;
pub type CgoExecutor2 = ThreadedExecutor2<BaseExecutor2>;

fn new_executor3(machine: CgoMachine3) -> CgoExecutor3 {
    ThreadedExecutor3(BaseExecutor3::new(machine))
}

fn new_executor2(machine: CgoMachine2) -> CgoExecutor2 {
    ThreadedExecutor2(BaseExecutor2::new(machine))
}

pub trait CgoExecutor {
    fn execute_message(
        &mut self,
        msg: Message,
        apply_kind: ApplyKind,
        raw_length: usize,
    ) -> anyhow::Result<ApplyRet>;

    fn flush(&mut self) -> anyhow::Result<Cid>;
}

impl CgoExecutor for CgoExecutor3 {
    fn execute_message(
        &mut self,
        msg: Message,
        apply_kind: ApplyKind,
        raw_length: usize,
    ) -> anyhow::Result<ApplyRet> {
        use fvm3::executor::Executor;
        self.0.execute_message(msg, apply_kind, raw_length)
    }

    fn flush(&mut self) -> anyhow::Result<Cid> {
        use fvm3::executor::Executor;
        self.0.flush()
    }
}

impl CgoExecutor for CgoExecutor2 {
    fn execute_message(
        &mut self,
        msg: Message,
        apply_kind: ApplyKind,
        raw_length: usize,
    ) -> anyhow::Result<ApplyRet> {
        use fvm2::executor::Executor;
        let res = self.0.execute_message(
            Message2 {
                version: msg.version,
                from: Address2::from_bytes(&msg.from.to_bytes()).unwrap(),
                to: Address2::from_bytes(&msg.to.to_bytes()).unwrap(),
                sequence: msg.sequence,
                value: TokenAmount2::from_atto(msg.value.atto().clone()),
                method_num: msg.method_num,
                params: RawBytes2::from(msg.params.to_vec()),
                gas_limit: msg.gas_limit,
                gas_fee_cap: TokenAmount2::from_atto(msg.gas_fee_cap.atto().clone()),
                gas_premium: TokenAmount2::from_atto(msg.gas_premium.atto().clone()),
            },
            match apply_kind {
                ApplyKind::Explicit => ApplyKind2::Explicit,
                ApplyKind::Implicit => ApplyKind2::Implicit,
            },
            raw_length,
        );
        match res {
            Ok(ret) => Ok(ApplyRet {
                msg_receipt: Receipt {
                    exit_code: ExitCode::new(ret.msg_receipt.exit_code.value()),
                    return_data: RawBytes::from(ret.msg_receipt.return_data.to_vec()),
                    gas_used: ret.msg_receipt.gas_used,
                },
                penalty: TokenAmount::from_atto(ret.penalty.atto().clone()),
                miner_tip: TokenAmount::from_atto(ret.miner_tip.atto().clone()),
                base_fee_burn: TokenAmount::from_atto(ret.base_fee_burn.atto().clone()),
                over_estimation_burn: TokenAmount::from_atto(
                    ret.over_estimation_burn.atto().clone(),
                ),
                refund: TokenAmount::from_atto(ret.refund.atto().clone()),
                gas_refund: ret.gas_refund,
                gas_burned: ret.gas_burned,
                failure_info: ret.failure_info.map(|failure| match failure {
                    ApplyFailure2::MessageBacktrace(bt) => {
                        ApplyFailure::MessageBacktrace(Backtrace {
                            frames: bt
                                .frames
                                .iter()
                                .map(|f| Frame {
                                    source: f.source,
                                    method: f.method,
                                    code: ExitCode::new(f.code.value()),
                                    message: f.message.clone(),
                                })
                                .collect(),
                            cause: bt.cause.map(|cause| match cause {
                                Cause2::Syscall {
                                    module,
                                    function,
                                    error,
                                    message,
                                } => Cause::Syscall {
                                    module,
                                    function,
                                    error: ErrorNumber::from_u32(error as u32).unwrap(),
                                    message,
                                },
                                Cause2::Fatal {
                                    error_msg,
                                    backtrace,
                                } => Cause::Fatal {
                                    error_msg,
                                    backtrace,
                                },
                            }),
                        })
                    }
                    ApplyFailure2::PreValidation(s) => ApplyFailure::PreValidation(s),
                }),
                exec_trace: ret
                    .exec_trace
                    .iter()
                    .filter_map(|tr| match tr {
                        ExecutionEvent2::GasCharge(charge) => {
                            Some(ExecutionEvent::GasCharge(GasCharge {
                                name: charge.name.clone(),
                                compute_gas: Gas::from_milligas(charge.compute_gas.as_milligas()),
                                storage_gas: Gas::from_milligas(charge.storage_gas.as_milligas()),
                            }))
                        }
                        ExecutionEvent2::Call {
                            from,
                            to,
                            method,
                            params,
                            value,
                        } => Some(ExecutionEvent::Call {
                            from: *from,
                            to: Address::from_bytes(&to.to_bytes()).unwrap(),
                            method: *method,
                            params: RawBytes::from(params.to_vec()),
                            value: TokenAmount::from_atto(value.atto().clone()),
                        }),
                        ExecutionEvent2::CallReturn(ret) => {
                            Some(ExecutionEvent::CallReturn(RawBytes::from(ret.to_vec())))
                        }
                        ExecutionEvent2::CallAbort(ec) => {
                            Some(ExecutionEvent::CallAbort(ExitCode::new(ec.value())))
                        }
                        ExecutionEvent2::CallError(err) => {
                            Some(ExecutionEvent::CallError(SyscallError(
                                err.0.clone(),
                                ErrorNumber::from_u32(err.1 as u32).unwrap(),
                            )))
                        }
                        _ => None,
                    })
                    .collect(),
            }),
            Err(x) => Err(x),
        }
    }

    fn flush(&mut self) -> anyhow::Result<Cid> {
        use fvm2::executor::Executor;
        self.0.flush()
    }
}

pub trait AbstractMultiEngine: Send + Sync {
    fn new_executor(
        &self,
        ncfg: NetworkConfig,
        mctx: MachineContext,
        blockstore: OverlayBlockstore<CgoBlockstore>,
        externs: CgoExterns,
    ) -> InnerFvmMachine;
}

impl AbstractMultiEngine for MultiEngine3 {
    fn new_executor(
        &self,
        cfg: NetworkConfig,
        ctx: MachineContext,
        blockstore: OverlayBlockstore<CgoBlockstore>,
        externs: CgoExterns,
    ) -> InnerFvmMachine {
        let engine = match self.get(&cfg) {
            Ok(e) => e,
            Err(err) => panic!("failed to create engine: {}", err),
        };

        let machine = CgoMachine3::new(&engine, &ctx, blockstore, externs).unwrap();
        InnerFvmMachine {
            machine: Some(Mutex::new(Box::new(new_executor3(machine)))),
        }
    }
}

impl AbstractMultiEngine for MultiEngine2 {
    fn new_executor(
        &self,
        cfg: NetworkConfig,
        ctx: MachineContext,
        blockstore: OverlayBlockstore<CgoBlockstore>,
        externs: CgoExterns,
    ) -> InnerFvmMachine {
        let cfg = NetworkConfig2 {
            network_version: unsafe {
                std::mem::transmute::<NetworkVersion, NetworkVersion2>(cfg.network_version)
            },
            max_call_depth: cfg.max_call_depth,
            max_wasm_stack: cfg.max_wasm_stack,
            builtin_actors_override: cfg.builtin_actors_override,
            actor_debugging: cfg.actor_debugging,
            price_list: unsafe { std::mem::transmute::<&PriceList3, &PriceList2>(cfg.price_list) },
            actor_redirect: cfg.actor_redirect,
        };

        let engine = match self.get(&cfg) {
            Ok(e) => e,
            Err(err) => panic!("failed to create engine: {}", err),
        };

        let ctx = MachineContext2 {
            network: cfg,
            epoch: ctx.network_context.epoch,
            initial_state_root: ctx.initial_state_root,
            base_fee: TokenAmount2::from_atto(ctx.network_context.base_fee.atto().clone()),
            circ_supply: TokenAmount2::from_atto(ctx.circ_supply.atto().clone()),
            tracing: ctx.tracing,
        };

        let machine = CgoMachine2::new(&engine, &ctx, blockstore, externs).unwrap();
        InnerFvmMachine {
            machine: Some(Mutex::new(Box::new(new_executor2(machine)))),
        }
    }
}

pub struct MultiEngineContainer {
    engines: Mutex<HashMap<u32, Arc<dyn AbstractMultiEngine + 'static>>>,
}

impl MultiEngineContainer {
    pub fn new() -> MultiEngineContainer {
        MultiEngineContainer {
            engines: Mutex::new(HashMap::new()),
        }
    }

    pub fn get(
        &self,
        nv: NetworkVersion,
    ) -> anyhow::Result<Arc<dyn AbstractMultiEngine + 'static>> {
        let mut locked = self.engines.lock().unwrap();
        Ok(match locked.entry(nv as u32) {
            Entry::Occupied(v) => v.get().clone(),
            Entry::Vacant(v) => v
                .insert(match nv {
                    NetworkVersion::V16 | NetworkVersion::V17 => {
                        Arc::new(MultiEngine2::new()) as Arc<dyn AbstractMultiEngine + 'static>
                    }
                    NetworkVersion::V18 => {
                        Arc::new(MultiEngine3::new()) as Arc<dyn AbstractMultiEngine + 'static>
                    }
                    _ => return Err(anyhow!("network version not supported")),
                })
                .clone(),
        })
    }
}
