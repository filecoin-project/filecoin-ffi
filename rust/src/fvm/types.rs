use std::sync::Mutex;

use safer_ffi::prelude::*;

use super::machine::CgoExecutor;
use fvm::executor::ValidateRet;

#[derive_ReprC]
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FvmRegisteredVersion {
    V1,
}

#[derive_ReprC]
#[ReprC::opaque]
#[derive(Default)]
pub struct InnerFvmMachine {
    pub(crate) machine: Option<Mutex<CgoExecutor>>,
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
    pub gas_refund: i64,
    pub gas_burned: i64,
    pub exec_trace: Option<c_slice::Box<u8>>,
    pub failure_info: Option<str::Box>,
}

#[derive_ReprC]
#[repr(C)]
#[derive(Default)]
pub struct FvmMachineValidateResponse {
    pub exit_code: u64,
    pub gas_used: i64,
}

impl From<ValidateRet> for FvmMachineValidateResponse {
    fn from(src: ValidateRet) -> Self {
        Self {
            exit_code: src.exit_code.value() as u64,
            gas_used: src.gas_used,
        }
    }
}
