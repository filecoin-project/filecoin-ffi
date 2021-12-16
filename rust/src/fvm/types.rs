use std::io::{Error, SeekFrom};
use std::ptr;
use std::slice::from_raw_parts;

use anyhow::Result;
use drop_struct_macro_derive::DropStructMacro;
use ffi_toolkit::{code_and_message_impl, free_c_str, CodeAndMessage, FCPResponseStatus};
use fvm::machine::Machine;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
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
