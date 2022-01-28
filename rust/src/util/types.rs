use std::{ops::Deref, ptr};

use drop_struct_macro_derive::DropStructMacro;
// `CodeAndMessage` is the trait implemented by `code_and_message_impl
use ffi_toolkit::{code_and_message_impl, free_c_str, CodeAndMessage, FCPResponseStatus};

#[repr(C)]
pub struct fil_Array<T: Sized> {
    ptr: *mut T,
    len: usize,
}

impl<T> Default for fil_Array<T> {
    fn default() -> Self {
        Self {
            ptr: ptr::null_mut(),
            len: 0,
        }
    }
}

pub type fil_Bytes = fil_Array<u8>;

impl<T> From<Vec<T>> for fil_Array<T> {
    fn from(buf: Vec<T>) -> Self {
        if buf.is_empty() {
            return Default::default();
        }
        buf.into_boxed_slice().into()
    }
}

impl<T> From<Box<[T]>> for fil_Array<T> {
    fn from(buf: Box<[T]>) -> Self {
        if buf.is_empty() {
            return Default::default();
        }
        let len = buf.len();
        let ptr = buf.as_mut_ptr();
        Box::leak(buf);

        Self { ptr, len }
    }
}

impl<T> Drop for fil_Array<T> {
    fn drop(&mut self) {
        unsafe {
            if !self.ptr.is_null() && self.len != 0 {
                let _ = Vec::from_raw_parts(self.ptr, self.len, self.len);
            }
        }
    }
}

impl<T> Deref for fil_Array<T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        unsafe {
            if self.ptr.is_null() {
                std::slice::from_raw_parts(ptr::NonNull::dangling().as_ptr(), 0)
            } else {
                std::slice::from_raw_parts(self.ptr, self.len)
            }
        }
    }
}

impl From<&str> for fil_Bytes {
    fn from(s: &str) -> Self {
        if s.is_empty() {
            return Default::default();
        }
        Box::<str>::from(s).into()
    }
}

impl From<String> for fil_Bytes {
    fn from(s: String) -> Self {
        if s.is_empty() {
            return Default::default();
        }
        s.into_boxed_str().into()
    }
}

impl From<Box<str>> for fil_Bytes {
    fn from(s: Box<str>) -> Self {
        if s.is_empty() {
            return Default::default();
        }
        let len = s.len();
        let ptr = s.as_mut_ptr();
        Box::leak(s);

        Self { ptr, len }
    }
}

#[repr(C)]
pub struct fil_GpuDeviceResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: fil_Bytes,
    pub devices: fil_Array<fil_Bytes>,
}

impl Default for fil_GpuDeviceResponse {
    fn default() -> Self {
        Self {
            error_msg: Default::default(),
            status_code: FCPResponseStatus::FCPNoError,
            devices: Default::default(),
        }
    }
}

code_and_message_impl!(fil_GpuDeviceResponse);

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_gpu_device_response(ptr: *mut fil_GpuDeviceResponse) {
    let _ = Box::from_raw(ptr);
}

#[repr(C)]
#[derive(DropStructMacro)]
pub struct fil_InitLogFdResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
}

impl Default for fil_InitLogFdResponse {
    fn default() -> Self {
        Self {
            error_msg: ptr::null(),
            status_code: FCPResponseStatus::FCPNoError,
        }
    }
}

code_and_message_impl!(fil_InitLogFdResponse);

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_init_log_fd_response(ptr: *mut fil_InitLogFdResponse) {
    let _ = Box::from_raw(ptr);
}
