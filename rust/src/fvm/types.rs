use std::convert::TryInto;
use std::io::{Error, SeekFrom};
use std::ptr;

use drop_struct_macro_derive::DropStructMacro;
use ffi_toolkit::{code_and_message_impl, free_c_str, CodeAndMessage, FCPResponseStatus};

use fvm_shared::address::Address;
use fvm_shared::clock::ChainEpoch;
use fvm_shared::econ::TokenAmount;
use fvm_shared::encoding::RawBytes;
use fvm_shared::error::ExitCode;
use fvm_shared::message::Message;
use fvm_shared::version::NetworkVersion;
use fvm_shared::MethodNum;
use num_bigint::BigInt;

use num_traits::FromPrimitive;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum fil_FvmRegisteredVersion {
    V1,
}

#[repr(C)]
#[derive(DropStructMacro)]
pub struct fil_CreateFvmMachineResponse {
    pub error_msg: *const libc::c_char,
    pub status_code: FCPResponseStatus,
    pub machine_id: u64,
}

impl Default for fil_CreateFvmMachineResponse {
    fn default() -> fil_CreateFvmMachineResponse {
        fil_CreateFvmMachineResponse {
            error_msg: ptr::null(),
            status_code: FCPResponseStatus::FCPNoError,
            machine_id: 0,
        }
    }
}

code_and_message_impl!(fil_CreateFvmMachineResponse);

#[repr(C)]
#[derive(DropStructMacro)]
pub struct fil_DropFvmMachineResponse {
    pub error_msg: *const libc::c_char,
    pub status_code: FCPResponseStatus,
}

impl Default for fil_DropFvmMachineResponse {
    fn default() -> fil_DropFvmMachineResponse {
        fil_DropFvmMachineResponse {
            error_msg: ptr::null(),
            status_code: FCPResponseStatus::FCPNoError,
        }
    }
}

code_and_message_impl!(fil_DropFvmMachineResponse);

#[repr(C)]
#[derive(DropStructMacro)]
pub struct fil_FvmMachineExecuteResponse {
    pub error_msg: *const libc::c_char,
    pub status_code: FCPResponseStatus,
    pub exit_code: u64,
    pub return_ptr: *const u8,
    pub return_len: libc::size_t,
    pub gas_used: u64,
    pub penalty_hi: u64,
    pub penalty_lo: u64,
    pub miner_tip_hi: u64,
    pub miner_tip_lo: u64,
}

impl Default for fil_FvmMachineExecuteResponse {
    fn default() -> fil_FvmMachineExecuteResponse {
        fil_FvmMachineExecuteResponse {
            error_msg: ptr::null(),
            status_code: FCPResponseStatus::FCPNoError,
            exit_code: ExitCode::Ok as u64,
            return_ptr: ptr::null(),
            return_len: 0,
            gas_used: 0,
            penalty_hi: 0,
            penalty_lo: 0,
            miner_tip_hi: 0,
            miner_tip_lo: 0,
        }
    }
}

code_and_message_impl!(fil_FvmMachineExecuteResponse);
