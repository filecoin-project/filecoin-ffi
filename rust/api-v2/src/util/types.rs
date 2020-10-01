use std::ptr;

use drop_struct_macro_derive::DropStructMacro;
// `CodeAndMessage` is the trait implemented by `code_and_message_impl
use ffi_toolkit::{code_and_message_impl, free_c_str, CodeAndMessage, FCPResponseStatus};

#[repr(C)]
#[derive(DropStructMacro)]
pub struct fil_GpuDeviceResponseV2 {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
    pub devices_len: libc::size_t,
    pub devices_ptr: *const *const libc::c_char,
}

impl Default for fil_GpuDeviceResponseV2 {
    fn default() -> Self {
        Self {
            error_msg: ptr::null(),
            status_code: FCPResponseStatus::FCPNoError,
            devices_len: 0,
            devices_ptr: ptr::null(),
        }
    }
}

code_and_message_impl!(fil_GpuDeviceResponseV2);

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_gpu_device_response_v2(ptr: *mut fil_GpuDeviceResponseV2) {
    let _ = Box::from_raw(ptr);
}

#[repr(C)]
#[derive(DropStructMacro)]
pub struct fil_InitLogFdResponseV2 {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
}

impl Default for fil_InitLogFdResponseV2 {
    fn default() -> Self {
        Self {
            error_msg: ptr::null(),
            status_code: FCPResponseStatus::FCPNoError,
        }
    }
}

code_and_message_impl!(fil_InitLogFdResponseV2);

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_init_log_fd_response_v2(ptr: *mut fil_InitLogFdResponseV2) {
    let _ = Box::from_raw(ptr);
}
