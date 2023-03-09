use std::sync::Mutex;

use safer_ffi::prelude::*;

use super::engine::CgoExecutor;

#[derive_ReprC]
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FvmRegisteredVersion {
    V1,
}

#[derive_ReprC]
#[ReprC::opaque]
#[derive(Default)]
pub struct InnerFvmMachine {
    pub(crate) machine: Option<Mutex<Box<dyn CgoExecutor>>>,
}

pub type FvmMachine = Option<repr_c::Box<InnerFvmMachine>>;

#[derive_ReprC]
#[repr(C)]
#[derive(Default)]
pub struct FvmMachineExecuteResponse {
    pub exit_code: u64,
    pub return_val: Option<c_slice::Box<u8>>,
    pub gas_used: u64,
    pub penalty_hi: u64,
    pub penalty_lo: u64,
    pub miner_tip_hi: u64,
    pub miner_tip_lo: u64,
    pub base_fee_burn_hi: u64,
    pub base_fee_burn_lo: u64,
    pub over_estimation_burn_hi: u64,
    pub over_estimation_burn_lo: u64,
    pub refund_hi: u64,
    pub refund_lo: u64,
    pub gas_refund: u64,
    pub gas_burned: u64,
    pub exec_trace: Option<c_slice::Box<u8>>,
    pub failure_info: Option<str::Box>,
    pub events: Option<c_slice::Box<u8>>,
    pub events_root: Option<c_slice::Box<u8>>,
}
