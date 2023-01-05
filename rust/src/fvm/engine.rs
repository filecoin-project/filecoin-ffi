use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::anyhow;
use fvm3_cid::Cid as Cid3;
use fvm2_cid::Cid as Cid2;
use fvm3_cid::Version as Version3;
use fvm2_cid::Version as Version2;
use fvm3_multihash::Multihash as Multihash3;
use fvm2_multihash::Multihash as Multihash2;
use fvm2::machine::MultiEngine as MultiEngine2;
use fvm3::executor::{ApplyKind, ApplyRet};
use fvm3::machine::{MachineContext, MultiEngine as MultiEngine3, NetworkConfig};
use fvm_shared::{message::Message, version::NetworkVersion};

use super::blockstore::{CgoBlockstore, OverlayBlockstore};
use super::externs::CgoExterns;
use super::types::*;


// SHAWN: move and reffactor to return anyhow::result
fn cid2_to_cid3(cid2: &Cid2) -> Cid3 {
    let v = cid2.version() as u64;
    let multihash2_bytes = cid2.hash().to_bytes();
    let multihash3 = Multihash3::from_bytes(&multihash2_bytes).unwrap();
    // SHAWN TODO: instead of unwraping here propagate so we have error handling
    Cid3::new(Version3::try_from(v).unwrap(), cid2.codec(), multihash3).unwrap()
}

fn cid3_to_cid2(cid3: &Cid3) -> Cid2 {
    let v = cid3.version() as u64;
    let multihash3_bytes = cid3.hash().to_bytes();
    let multihash2 = Multihash2::from_bytes(&multihash3_bytes).unwrap();
    // SHAWN TODO: instead of unwraping here propagate so we have error handling
    Cid2::new(Version2::try_from(v).unwrap(), cid3.codec(), multihash2).unwrap()
}

// Generic executor; uses the current (v3) engine types
pub trait CgoExecutor {
    fn execute_message(
        &mut self,
        msg: Message,
        apply_kind: ApplyKind,
        raw_length: usize,
    ) -> anyhow::Result<ApplyRet>;

    fn flush(&mut self) -> anyhow::Result<Cid3>;
}

// The generic engine interface
pub trait AbstractMultiEngine: Send + Sync {
    fn new_executor(
        &self,
        ncfg: NetworkConfig,
        mctx: MachineContext,
        blockstore: OverlayBlockstore<CgoBlockstore>,
        externs: CgoExterns,
    ) -> anyhow::Result<InnerFvmMachine>;
}

// The generic engine container
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

impl Default for MultiEngineContainer {
    fn default() -> MultiEngineContainer {
        MultiEngineContainer::new()
    }
}

// fvm v3 implementation
mod v3 {
    use fvm3_cid::Cid;
    use std::sync::Mutex;

    use fvm3::call_manager::DefaultCallManager as DefaultCallManager3;
    use fvm3::executor::{
        ApplyKind, ApplyRet, DefaultExecutor as DefaultExecutor3,
        ThreadedExecutor as ThreadedExecutor3,
    };
    use fvm3::machine::{
        DefaultMachine as DefaultMachine3, MachineContext, MultiEngine as MultiEngine3,
        NetworkConfig,
    };
    use fvm3::DefaultKernel as DefaultKernel3;
    use fvm_shared::message::Message;

    use crate::fvm::engine::{
        AbstractMultiEngine, CgoBlockstore, CgoExecutor, CgoExterns, InnerFvmMachine,
        OverlayBlockstore,
    };

    type CgoMachine3 = DefaultMachine3<OverlayBlockstore<CgoBlockstore>, CgoExterns>;
    type BaseExecutor3 = DefaultExecutor3<DefaultKernel3<DefaultCallManager3<CgoMachine3>>>;
    type CgoExecutor3 = ThreadedExecutor3<BaseExecutor3>;

    fn new_executor(machine: CgoMachine3) -> CgoExecutor3 {
        ThreadedExecutor3(BaseExecutor3::new(machine))
    }

    impl CgoExecutor for CgoExecutor3 {
        fn execute_message(
            &mut self,
            msg: Message,
            apply_kind: ApplyKind,
            raw_length: usize,
        ) -> anyhow::Result<ApplyRet> {
            fvm3::executor::Executor::execute_message(self, msg, apply_kind, raw_length)
        }

        fn flush(&mut self) -> anyhow::Result<Cid> {
            fvm3::executor::Executor::flush(self)
        }
    }

    impl AbstractMultiEngine for MultiEngine3 {
        fn new_executor(
            &self,
            cfg: NetworkConfig,
            ctx: MachineContext,
            blockstore: OverlayBlockstore<CgoBlockstore>,
            externs: CgoExterns,
        ) -> anyhow::Result<InnerFvmMachine> {
            let engine = self.get(&cfg)?;
            let machine = CgoMachine3::new(&engine, &ctx, blockstore, externs)?;
            Ok(InnerFvmMachine {
                machine: Some(Mutex::new(Box::new(new_executor(machine)))),
            })
        }
    }
}

// fvm v2 implementation
mod v2 {
    use super::cid3_to_cid2;
    use super::cid2_to_cid3;
    use anyhow::anyhow;
    //use fvm2_cid::Cid as Cid2;
    use num_traits::FromPrimitive;
    use std::sync::Mutex;

    use fvm2::call_manager::{
        backtrace::Cause as Cause2, DefaultCallManager as DefaultCallManager2,
    };
    use fvm2::executor::{
        ApplyFailure as ApplyFailure2, ApplyKind as ApplyKind2,
        DefaultExecutor as DefaultExecutor2, ThreadedExecutor as ThreadedExecutor2,
    };
    use fvm2::machine::{
        DefaultMachine as DefaultMachine2, MachineContext as MachineContext2,
        MultiEngine as MultiEngine2, NetworkConfig as NetworkConfig2,
    };
    use fvm2::trace::ExecutionEvent as ExecutionEvent2;
    use fvm2::DefaultKernel as DefaultKernel2;
    use fvm2_ipld_encoding::RawBytes as RawBytes2;
    use fvm2_shared::{
        address::Address as Address2, econ::TokenAmount as TokenAmount2,
        message::Message as Message2, version::NetworkVersion as NetworkVersion2,
    };
    use fvm3::call_manager::{backtrace::Backtrace, backtrace::Cause, backtrace::Frame};
    use fvm3::executor::{ApplyFailure, ApplyKind, ApplyRet};
    use fvm3::gas::{Gas, GasCharge};
    use fvm3::kernel::SyscallError;
    use fvm3::machine::{MachineContext, NetworkConfig};
    use fvm3::trace::ExecutionEvent;
    use fvm3_ipld_encoding::RawBytes;
    use fvm_shared::{
        address::Address, econ::TokenAmount, error::ErrorNumber, error::ExitCode, message::Message,
        receipt::Receipt,
    };
    use fvm3_cid::Cid as Cid3;
    use crate::fvm::engine::{
        AbstractMultiEngine, CgoBlockstore, CgoExecutor, CgoExterns, InnerFvmMachine,
        OverlayBlockstore,
    };

    type CgoMachine2 = DefaultMachine2<OverlayBlockstore<CgoBlockstore>, CgoExterns>;
    type BaseExecutor2 = DefaultExecutor2<DefaultKernel2<DefaultCallManager2<CgoMachine2>>>;
    type CgoExecutor2 = ThreadedExecutor2<BaseExecutor2>;

    fn new_executor(machine: CgoMachine2) -> CgoExecutor2 {
        ThreadedExecutor2(BaseExecutor2::new(machine))
    }

    impl CgoExecutor for CgoExecutor2 {
        fn execute_message(
            &mut self,
            msg: Message,
            apply_kind: ApplyKind,
            raw_length: usize,
        ) -> anyhow::Result<ApplyRet> {
            let res = fvm2::executor::Executor::execute_message(
                self,
                Message2 {
                    version: msg.version,
                    from: Address2::from_bytes(&msg.from.to_bytes()).unwrap(),
                    to: Address2::from_bytes(&msg.to.to_bytes()).unwrap(),
                    sequence: msg.sequence,
                    value: TokenAmount2::from_atto(msg.value.atto().clone()),
                    method_num: msg.method_num,
                    params: RawBytes2::new(msg.params.into()),
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
                        return_data: RawBytes::new(ret.msg_receipt.return_data.into()),
                        gas_used: ret.msg_receipt.gas_used,
                        events_root: None,
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
                                    .into_iter()
                                    .map(|f| Frame {
                                        source: f.source,
                                        method: f.method,
                                        code: ExitCode::new(f.code.value()),
                                        message: f.message,
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
                                        error: ErrorNumber::from_u32(error as u32)
                                            .unwrap_or(ErrorNumber::AssertionFailed),
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
                        .into_iter()
                        .filter_map(|tr| match tr {
                            ExecutionEvent2::GasCharge(charge) => {
                                Some(ExecutionEvent::GasCharge(GasCharge {
                                    name: charge.name,
                                    compute_gas: Gas::from_milligas(
                                        charge.compute_gas.as_milligas(),
                                    ),
                                    storage_gas: Gas::from_milligas(
                                        charge.storage_gas.as_milligas(),
                                    ),
                                }))
                            }
                            ExecutionEvent2::Call {
                                from,
                                to,
                                method,
                                params,
                                value,
                            } => Some(ExecutionEvent::Call {
                                from,
                                to: Address::from_bytes(&to.to_bytes()).unwrap(),
                                method,
                                params: RawBytes::new(params.into()),
                                value: TokenAmount::from_atto(value.atto().clone()),
                            }),
                            ExecutionEvent2::CallReturn(ret) => Some(ExecutionEvent::CallReturn(
                                ExitCode::OK,
                                RawBytes::new(ret.into()),
                            )),
                            ExecutionEvent2::CallAbort(ec) => Some(ExecutionEvent::CallReturn(
                                ExitCode::new(ec.value()),
                                RawBytes::default(),
                            )),
                            ExecutionEvent2::CallError(err) => {
                                Some(ExecutionEvent::CallError(SyscallError(
                                    err.0,
                                    ErrorNumber::from_u32(err.1 as u32)
                                        .unwrap_or(ErrorNumber::AssertionFailed),
                                )))
                            }
                            _ => None,
                        })
                        .collect(),
                    events: vec![],
                }),
                Err(x) => Err(x),
            }
        }

        fn flush(&mut self) -> anyhow::Result<Cid3> {
            let cid2 = fvm2::executor::Executor::flush(self)?;
            Ok(cid2_to_cid3(&cid2))
        }
    }

    impl AbstractMultiEngine for MultiEngine2 {
        fn new_executor(
            &self,
            cfg: NetworkConfig,
            ctx: MachineContext,
            blockstore: OverlayBlockstore<CgoBlockstore>,
            externs: CgoExterns,
        ) -> anyhow::Result<InnerFvmMachine> {
            let ver = NetworkVersion2::try_from(cfg.network_version as u32)
                .map_err(|nv| anyhow!("unsupported network version {nv}"))?;

            let builtin_actors_override = match cfg.builtin_actors_override {
                Some(c) => Some(cid3_to_cid2(&c)),
                None => None,
            };
            let actor_redirect = cfg.actor_redirect.iter().map(
                |c| (cid3_to_cid2(&c.0), cid3_to_cid2(&c.1))
            ).collect::<Vec<_>>();
            let cfg = NetworkConfig2 {
                network_version: ver,
                max_call_depth: cfg.max_call_depth,
                max_wasm_stack: cfg.max_wasm_stack,
                builtin_actors_override,
                actor_debugging: cfg.actor_debugging,
                price_list: fvm2::gas::price_list_by_network_version(ver),
                actor_redirect,
            };

            let engine = self.get(&cfg)?;

            let initial_state_root = cid3_to_cid2(&ctx.initial_state_root);

            let ctx = MachineContext2 {
                network: cfg,
                epoch: ctx.epoch,
                initial_state_root,
                base_fee: TokenAmount2::from_atto(ctx.base_fee.atto().clone()),
                circ_supply: TokenAmount2::from_atto(ctx.circ_supply.atto().clone()),
                tracing: ctx.tracing,
            };

            let machine = CgoMachine2::new(&engine, &ctx, blockstore, externs)?;
            Ok(InnerFvmMachine {
                machine: Some(Mutex::new(Box::new(new_executor(machine)))),
            })
        }
    }
}
