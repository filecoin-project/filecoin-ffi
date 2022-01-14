use std::io::{Error, SeekFrom};
use std::ptr;
use std::slice::from_raw_parts;

use anyhow::Result;
use drop_struct_macro_derive::DropStructMacro;
use ffi_toolkit::{code_and_message_impl, free_c_str, CodeAndMessage, FCPResponseStatus};

use fvm_shared::address::Address;
use fvm_shared::clock::ChainEpoch;
use fvm_shared::econ::TokenAmount;
use fvm_shared::encoding::RawBytes;
use fvm_shared::message::Message;
use fvm_shared::version::NetworkVersion;
use fvm_shared::MethodNum;

use num_traits::FromPrimitive;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum fil_FvmRegisteredVersion {
    V1,
}

// Not sure which form is needed
fn get_address_from_id(id: u64) -> Address {
    Address::new_id(id)
}

// Not sure which form is needed
fn get_address_from_bytes(
    address_ptr: *const u8,
    address_len: libc::size_t,
) -> Result<Address, fvm_shared::address::Error> {
    let address_bytes: Vec<u8> =
        unsafe { std::slice::from_raw_parts(address_ptr, address_len).to_vec() };

    Address::from_bytes(&address_bytes)
}

fn get_params_from_bytes(params_ptr: *const u8, params_len: libc::size_t) -> RawBytes {
    let params_bytes: Vec<u8> =
        unsafe { std::slice::from_raw_parts(params_ptr, params_len).to_vec() };

    RawBytes::new(params_bytes)
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
}

impl Default for fil_FvmMachineExecuteResponse {
    fn default() -> fil_FvmMachineExecuteResponse {
        fil_FvmMachineExecuteResponse {
            error_msg: ptr::null(),
            status_code: FCPResponseStatus::FCPNoError,
        }
    }
}

code_and_message_impl!(fil_FvmMachineExecuteResponse);
