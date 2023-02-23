use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::anyhow;
use cid::Cid;

use fvm2::machine::MultiEngine as MultiEngine2;
use fvm3::engine::MultiEngine as MultiEngine3;
use fvm3::executor::{ApplyKind, ApplyRet};

use fvm3_shared::econ::TokenAmount;
use fvm3_shared::message::Message;

use super::blockstore::CgoBlockstore;
use super::externs::CgoExterns;
use super::types::*;

// Generic executor; uses the current (v3) engine types
pub trait CgoExecutor {
    fn execute_message(
        &mut self,
        msg: Message,
        apply_kind: ApplyKind,
        raw_length: usize,
    ) -> anyhow::Result<ApplyRet>;

    fn flush(&mut self) -> anyhow::Result<Cid>;
}

pub struct Config {
    pub network_version: u32,
    pub chain_id: u64,
    pub chain_epoch: u64,
    pub chain_timestamp: u64,
    pub state_root: Cid,
    pub base_fee: TokenAmount,
    pub circulating_supply: TokenAmount,
    pub tracing: bool,
    pub actor_debugging: bool,
    pub actor_redirect: Vec<(Cid, Cid)>,
}

// The generic engine interface
pub trait AbstractMultiEngine: Send + Sync {
    fn new_executor(
        &self,
        config: Config,
        blockstore: CgoBlockstore,
        externs: CgoExterns,
    ) -> anyhow::Result<InnerFvmMachine>;
}

// The generic engine container
pub struct MultiEngineContainer {
    concurrency: u32,
    engines: Mutex<HashMap<u32, Arc<dyn AbstractMultiEngine + 'static>>>,
}

impl MultiEngineContainer {
    pub fn new() -> MultiEngineContainer {
        MultiEngineContainer {
            engines: Mutex::new(HashMap::new()),
            // The number of messages that can be executed simultaniously on any given engine (i.e.,
            // on any given network version/config).
            concurrency: 1,
        }
    }

    pub fn get(&self, nv: u32) -> anyhow::Result<Arc<dyn AbstractMultiEngine + 'static>> {
        let mut locked = self
            .engines
            .lock()
            .map_err(|e| anyhow!("engine lock poisoned: {e}"))?;
        Ok(match locked.entry(nv) {
            Entry::Occupied(v) => v.get().clone(),
            Entry::Vacant(v) => v
                .insert(match nv {
                    16 | 17 => {
                        Arc::new(MultiEngine2::new()) as Arc<dyn AbstractMultiEngine + 'static>
                    }
                    18 | 19 => Arc::new(MultiEngine3::new(self.concurrency))
                        as Arc<dyn AbstractMultiEngine + 'static>,
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
    use anyhow::anyhow;
    use cid::Cid;
    use std::sync::Mutex;

    use fvm3::call_manager::DefaultCallManager as DefaultCallManager3;
    use fvm3::engine::{EnginePool as EnginePool3, MultiEngine as MultiEngine3};
    use fvm3::executor::{
        ApplyKind, ApplyRet, DefaultExecutor as DefaultExecutor3,
        ThreadedExecutor as ThreadedExecutor3,
    };
    use fvm3::machine::{DefaultMachine as DefaultMachine3, NetworkConfig};
    use fvm3::DefaultKernel as DefaultKernel3;
    use fvm3_shared::{chainid::ChainID, clock::ChainEpoch, message::Message};

    use crate::fvm::engine::{
        AbstractMultiEngine, CgoBlockstore, CgoExecutor, CgoExterns, InnerFvmMachine,
    };

    use super::Config;

    type CgoMachine3 = DefaultMachine3<CgoBlockstore, CgoExterns>;
    type BaseExecutor3 = DefaultExecutor3<DefaultKernel3<DefaultCallManager3<CgoMachine3>>>;
    type CgoExecutor3 = ThreadedExecutor3<BaseExecutor3>;

    fn new_executor(
        engine_pool: EnginePool3,
        machine: CgoMachine3,
    ) -> anyhow::Result<CgoExecutor3> {
        Ok(ThreadedExecutor3(BaseExecutor3::new(engine_pool, machine)?))
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
            cfg: Config,
            blockstore: CgoBlockstore,
            externs: CgoExterns,
        ) -> anyhow::Result<InnerFvmMachine> {
            let mut network_config = NetworkConfig::new(
                cfg.network_version
                    .try_into()
                    .map_err(|nv| anyhow!("network version {nv} not supported"))?,
            );
            network_config.chain_id(ChainID::from(cfg.chain_id));

            if cfg.actor_debugging {
                network_config.enable_actor_debugging();
            }

            network_config.redirect_actors(cfg.actor_redirect);

            let mut machine_context = network_config.for_epoch(
                cfg.chain_epoch as ChainEpoch,
                cfg.chain_timestamp,
                cfg.state_root,
            );

            machine_context.set_base_fee(cfg.base_fee);
            machine_context.set_circulating_supply(cfg.circulating_supply);

            if cfg.tracing {
                machine_context.enable_tracing();
            }
            let engine = self.get(&network_config)?;
            let machine = CgoMachine3::new(&machine_context, blockstore, externs)?;
            Ok(InnerFvmMachine {
                machine: Some(Mutex::new(Box::new(new_executor(engine, machine)?))),
            })
        }
    }
}

// fvm v2 implementation
mod v2 {
    use anyhow::{anyhow, Context};
    use cid::Cid;
    use fvm3_ipld_encoding::ipld_block::IpldBlock;
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
        DefaultMachine as DefaultMachine2, MultiEngine as MultiEngine2,
        NetworkConfig as NetworkConfig2,
    };
    use fvm2::trace::ExecutionEvent as ExecutionEvent2;
    use fvm2::DefaultKernel as DefaultKernel2;
    use fvm2_ipld_encoding::RawBytes as RawBytes2;
    use fvm2_shared::{
        address::Address as Address2, clock::ChainEpoch as ChainEpoch2,
        econ::TokenAmount as TokenAmount2, message::Message as Message2,
    };
    use fvm3::call_manager::{backtrace::Backtrace, backtrace::Cause, backtrace::Frame};
    use fvm3::executor::{ApplyFailure, ApplyKind, ApplyRet};
    use fvm3::gas::{Gas, GasCharge};
    use fvm3::kernel::SyscallError;

    use fvm3::trace::ExecutionEvent;
    use fvm3_ipld_encoding::{RawBytes, DAG_CBOR};
    use fvm3_shared::{
        address::Address, econ::TokenAmount, error::ErrorNumber, error::ExitCode, message::Message,
        receipt::Receipt,
    };

    use crate::fvm::engine::{
        AbstractMultiEngine, CgoBlockstore, CgoExecutor, CgoExterns, InnerFvmMachine,
    };

    use super::Config;

    type CgoMachine2 = DefaultMachine2<CgoBlockstore, CgoExterns>;
    type BaseExecutor2 = DefaultExecutor2<DefaultKernel2<DefaultCallManager2<CgoMachine2>>>;
    type CgoExecutor2 = ThreadedExecutor2<BaseExecutor2>;

    fn new_executor(machine: CgoMachine2) -> CgoExecutor2 {
        ThreadedExecutor2(BaseExecutor2::new(machine))
    }

    fn bytes_to_block(bytes: RawBytes2) -> Option<IpldBlock> {
        if bytes.is_empty() {
            None
        } else {
            Some(IpldBlock {
                data: bytes.into(),
                codec: DAG_CBOR,
            })
        }
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
                    version: msg.version.try_into().context("invalid message version")?,
                    from: Address2::from_bytes(&msg.from.to_bytes())
                        .context("unsupported from address")?,
                    to: Address2::from_bytes(&msg.to.to_bytes())
                        .context("unsupported to address")?,
                    sequence: msg.sequence,
                    value: TokenAmount2::from_atto(msg.value.atto().clone()),
                    method_num: msg.method_num,
                    params: RawBytes2::new(msg.params.into()),
                    gas_limit: msg.gas_limit.try_into().context("invalid gas limit")?,
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
                        gas_used: ret
                            .msg_receipt
                            .gas_used
                            .try_into()
                            .context("negative gas used")?,
                        events_root: None,
                    },
                    penalty: TokenAmount::from_atto(ret.penalty.atto().clone()),
                    miner_tip: TokenAmount::from_atto(ret.miner_tip.atto().clone()),
                    base_fee_burn: TokenAmount::from_atto(ret.base_fee_burn.atto().clone()),
                    over_estimation_burn: TokenAmount::from_atto(
                        ret.over_estimation_burn.atto().clone(),
                    ),
                    refund: TokenAmount::from_atto(ret.refund.atto().clone()),
                    gas_refund: ret.gas_refund.try_into().context("negative gas refund")?,
                    gas_burned: ret.gas_burned.try_into().context("negative gas burned")?,
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
                                // We set the gas for "negative" charges to 0. This isn't correct,
                                // but it won't matter in practice (the sum of the gas charges in
                                // the trace aren't guaranteed to equal the total gas charge
                                // anyways).
                                Some(ExecutionEvent::GasCharge(GasCharge {
                                    name: charge.name,
                                    compute_gas: Gas::from_milligas(
                                        charge
                                            .compute_gas
                                            .as_milligas()
                                            .try_into()
                                            .unwrap_or_default(),
                                    ),
                                    other_gas: Gas::from_milligas(
                                        charge
                                            .storage_gas
                                            .as_milligas()
                                            .try_into()
                                            .unwrap_or_default(),
                                    ),
                                    elapsed: Default::default(), // no timing information for v2.
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
                                to: Address::from_bytes(&to.to_bytes())
                                    // There's nothing we can do here, so we use the "chaos" actor
                                    // ID.
                                    .unwrap_or_else(|_| Address::new_id(98)),
                                method,
                                params: bytes_to_block(params),
                                value: TokenAmount::from_atto(value.atto().clone()),
                            }),
                            ExecutionEvent2::CallReturn(ret) => Some(ExecutionEvent::CallReturn(
                                ExitCode::OK,
                                bytes_to_block(ret),
                            )),
                            ExecutionEvent2::CallAbort(ec) => {
                                Some(ExecutionEvent::CallReturn(ExitCode::new(ec.value()), None))
                            }
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

        fn flush(&mut self) -> anyhow::Result<Cid> {
            fvm2::executor::Executor::flush(self)
        }
    }

    impl AbstractMultiEngine for MultiEngine2 {
        fn new_executor(
            &self,
            cfg: Config,
            blockstore: CgoBlockstore,
            externs: CgoExterns,
        ) -> anyhow::Result<InnerFvmMachine> {
            let mut network_config = NetworkConfig2::new(
                cfg.network_version
                    .try_into()
                    .map_err(|nv| anyhow!("network version {nv} not supported"))?,
            );

            if cfg.actor_debugging {
                network_config.enable_actor_debugging();
            }

            network_config.redirect_actors(cfg.actor_redirect);

            let mut machine_context =
                network_config.for_epoch(cfg.chain_epoch as ChainEpoch2, cfg.state_root);

            machine_context.set_base_fee(TokenAmount2::from_atto(cfg.base_fee.atto().clone()));
            machine_context.set_circulating_supply(TokenAmount2::from_atto(
                cfg.circulating_supply.atto().clone(),
            ));

            if cfg.tracing {
                machine_context.enable_tracing();
            }
            let engine = self.get(&network_config)?;
            let machine = CgoMachine2::new(&engine, &machine_context, blockstore, externs)?;
            Ok(InnerFvmMachine {
                machine: Some(Mutex::new(Box::new(new_executor(machine)))),
            })
        }
    }
}
