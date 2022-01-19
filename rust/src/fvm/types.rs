use std::ptr;

use drop_struct_macro_derive::DropStructMacro;
use ffi_toolkit::{code_and_message_impl, free_c_str, CodeAndMessage, FCPResponseStatus};

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
