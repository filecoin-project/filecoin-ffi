use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::anyhow;
use cid::Cid;
use fvm3::call_manager::DefaultCallManager as DefaultCallManager3;
use fvm3::executor::{
    ApplyKind as ApplyKind3, ApplyRet as ApplyRet3, DefaultExecutor as DefaultExecutor3,
    ThreadedExecutor as ThreadedExecutor3,
};
use fvm3::machine::{
    DefaultMachine as DefaultMachine3, MachineContext as MachineContext3,
    MultiEngine as MultiEngine3, NetworkConfig as NetworkConfig3,
};
use fvm3::DefaultKernel as DefaultKernel3;
use fvm3_shared::{
    message::Message, version::NetworkVersion,
};

use super::blockstore::{CgoBlockstore, OverlayBlockstore};
use super::externs::CgoExterns;
use super::types::*;

pub type CgoMachine3 = DefaultMachine3<OverlayBlockstore<CgoBlockstore>, CgoExterns>;
pub type BaseExecutor3 = DefaultExecutor3<DefaultKernel3<DefaultCallManager3<CgoMachine3>>>;

pub type CgoExecutor3 = ThreadedExecutor3<BaseExecutor3>;

fn new_executor3(machine: CgoMachine3) -> CgoExecutor3 {
    ThreadedExecutor3(BaseExecutor3::new(machine))
}

pub trait CgoExecutor {
    fn execute_message(
        &mut self,
        msg: Message,
        apply_kind: ApplyKind3,
        raw_length: usize,
    ) -> anyhow::Result<ApplyRet3>;

    fn flush(&mut self) -> anyhow::Result<Cid>;
}

impl CgoExecutor for CgoExecutor3 {
    fn execute_message(
        &mut self,
        msg: Message,
        apply_kind: ApplyKind3,
        raw_length: usize,
    ) -> anyhow::Result<ApplyRet3> {
        use fvm3::executor::Executor;
        self.0.execute_message(msg, apply_kind, raw_length)
    }

    fn flush(&mut self) -> anyhow::Result<Cid> {
        use fvm3::executor::Executor;
        self.0.flush()
    }
}

pub trait AbstractMultiEngine: Send + Sync {
    fn new_executor(
        &self,
        ncfg: NetworkConfig3,
        mctx: MachineContext3,
        blockstore: OverlayBlockstore<CgoBlockstore>,
        externs: CgoExterns,
    ) -> InnerFvmMachine;
}

impl AbstractMultiEngine for MultiEngine3 {
    fn new_executor(
        &self,
        cfg: NetworkConfig3,
        ctx: MachineContext3,
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

pub struct MultiEngineContainer {
    engines: Mutex<HashMap<u32, Arc<dyn AbstractMultiEngine + 'static>>>,
}

impl MultiEngineContainer {
    pub fn new() -> MultiEngineContainer {
        MultiEngineContainer {
            engines: Mutex::new(HashMap::new()),
        }
    }

    pub fn get(&self, nv: NetworkVersion) -> anyhow::Result<Arc<dyn AbstractMultiEngine + 'static>> {
        let mut locked = self.engines.lock().unwrap();
        Ok(match locked.entry(nv as u32) {
            Entry::Occupied(v) => v.get().clone(),
            Entry::Vacant(v) => v
                .insert(match nv {
                    //NetworkVersion::V16 | NetworkVersion::V17 => {
                    //    Arc::new(MultiEngine2::new()) as Arc<dyn AbstractMultiEngine + 'static>
                    //}
                    NetworkVersion::V18 => {
                        Arc::new(MultiEngine3::new()) as Arc<dyn AbstractMultiEngine + 'static>
                    }
                    _ => return Err(anyhow!("network version not supported")),
                })
                .clone(),
        })
    }
}
