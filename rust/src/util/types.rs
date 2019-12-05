use std::ptr;

use drop_struct_macro_derive::DropStructMacro;
// `CodeAndMessage` is the trait implemented by `code_and_message_impl
use ffi_toolkit::{code_and_message_impl, free_c_str, CodeAndMessage, FCPResponseStatus};

#[repr(C)]
#[derive(DropStructMacro)]
pub struct GpuDeviceResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
    pub devices_len: libc::size_t,
    pub devices_ptr: *const *const libc::c_char,
}

impl Default for GpuDeviceResponse {
    fn default() -> Self {
        Self {
            error_msg: ptr::null(),
            status_code: FCPResponseStatus::FCPNoError,
            devices_len: 0,
            devices_ptr: ptr::null(),
        }
    }
}

code_and_message_impl!(GpuDeviceResponse);

#[no_mangle]
pub unsafe extern "C" fn destroy_gpu_device_response(ptr: *mut GpuDeviceResponse) {
    let _ = Box::from_raw(ptr);
}
