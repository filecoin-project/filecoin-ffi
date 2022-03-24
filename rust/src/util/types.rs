use std::{fmt::Display, ops::Deref, panic, path::PathBuf, ptr::NonNull, str::Utf8Error};

use safer_ffi::prelude::*;

use super::api::init_log;

#[derive_ReprC]
#[repr(i32)]
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum FCPResponseStatus {
    // Don't use FCPSuccess, since that complicates description of 'successful' verification.
    FCPNoError = 0,
    FCPUnclassifiedError = 1,
    FCPCallerError = 2,
    FCPReceiverError = 3,
}

/// Owned, fixed size array, allocated on the heap.
#[derive_ReprC]
#[repr(C)]
pub struct Array<T: Sized> {
    ptr: Option<NonNull<*mut T>>,
    len: usize,
}

impl<T: Clone> Clone for Array<T> {
    fn clone(&self) -> Self {
        let ptr = self.ptr.and_then(|ptr| {
            let bytes = unsafe { std::slice::from_raw_parts(ptr.as_ptr(), self.len) }
                .to_owned()
                .into_boxed_slice();

            NonNull::new(Box::into_raw(bytes).cast())
        });

        Array { ptr, len: self.len }
    }
}

impl<T> Default for Array<T> {
    fn default() -> Self {
        Self { ptr: None, len: 0 }
    }
}

impl<T: Sized> Array<T> {
    pub fn is_null(&self) -> bool {
        self.ptr.is_none() || self.len == 0
    }

    /// Converts this array into a boxed slice, transferring ownership of the memory.
    pub fn into_boxed_slice(self) -> Box<[T]> {
        match self.ptr {
            None => Box::new([]),
            Some(ptr) => {
                let res = unsafe {
                    Box::from_raw(std::slice::from_raw_parts_mut(
                        ptr.as_ptr().cast(),
                        self.len,
                    ))
                };
                // no drop for us
                std::mem::forget(self);
                res
            }
        }
    }
}

// This is needed because of https://github.com/rust-lang/rust/issues/59878
impl<T: Sized> IntoIterator for Array<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        Vec::from(self.into_boxed_slice()).into_iter()
    }
}

impl<T> From<Vec<T>> for Array<T> {
    fn from(buf: Vec<T>) -> Self {
        if buf.is_empty() {
            return Default::default();
        }
        buf.into_boxed_slice().into()
    }
}

impl<T: Clone> From<&[T]> for Array<T> {
    fn from(buf: &[T]) -> Self {
        if buf.is_empty() {
            return Default::default();
        }
        buf.to_vec().into_boxed_slice().into()
    }
}

impl<T> From<Box<[T]>> for Array<T> {
    fn from(buf: Box<[T]>) -> Self {
        if buf.is_empty() {
            return Default::default();
        }
        let len = buf.len();
        let ptr = NonNull::new(Box::into_raw(buf).cast());

        Self { ptr, len }
    }
}

impl<T> Drop for Array<T> {
    fn drop(&mut self) {
        if let Some(ptr) = self.ptr {
            let _ = unsafe { Box::from_raw(ptr.as_ptr()) };
        }
    }
}

impl<T> Deref for Array<T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        self.as_ref()
    }
}

impl<T> AsRef<[T]> for Array<T> {
    #[inline]
    fn as_ref(&self) -> &[T] {
        match self.ptr {
            None => &[],
            Some(ptr) => unsafe { std::slice::from_raw_parts(ptr.as_ptr().cast(), self.len) },
        }
    }
}

#[cfg(target_os = "linux")]
pub fn as_path_buf(bytes: &[u8]) -> std::result::Result<PathBuf, Utf8Error> {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    Ok(OsStr::from_bytes(bytes).into())
}

#[cfg(not(target_os = "linux"))]
pub fn as_path_buf(bytes: &[u8]) -> std::result::Result<PathBuf, Utf8Error> {
    std::str::from_utf8(bytes).map(Into::into)
}

#[cfg(test)]
#[cfg(target_os = "linux")]
pub fn as_bytes(path: &std::path::Path) -> &[u8] {
    use std::os::unix::ffi::OsStrExt;

    path.as_os_str().as_bytes()
}

#[cfg(all(test, not(target_os = "linux")))]
pub fn as_bytes(path: &std::path::Path) -> &[u8] {
    path.to_str().unwrap().as_bytes()
}

#[derive_ReprC]
#[repr(C)]
#[derive(Clone)]
pub struct Result<T: Sized> {
    pub status_code: FCPResponseStatus,
    pub error_msg: c_slice::Box<u8>,
    pub value: T,
}

impl<T: Sized> Deref for Result<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<T: Sized + Default> Default for Result<T> {
    fn default() -> Self {
        Result {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: Default::default(),
            value: Default::default(),
        }
    }
}

impl<T, E> From<std::result::Result<T, E>> for Result<T>
where
    T: Sized + Default,
    E: Display,
{
    fn from(r: std::result::Result<T, E>) -> Self {
        match r {
            Ok(value) => Self::ok(value),
            Err(e) => Self::err(e.to_string().into_bytes().into_boxed_slice()),
        }
    }
}

impl<T> From<T> for Result<T>
where
    T: Sized,
{
    fn from(value: T) -> Self {
        Self {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: Default::default(),
            value,
        }
    }
}

impl<T: Sized> Result<T> {
    pub fn ok(value: T) -> Self {
        Result {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: Default::default(),
            value,
        }
    }

    pub unsafe fn into_boxed_raw(self) -> *mut Result<T> {
        Box::into_raw(Box::new(self))
    }

    pub fn err_with_default(err: impl Into<c_slice::Box<u8>>, value: T) -> Self {
        Result {
            status_code: FCPResponseStatus::FCPUnclassifiedError,
            error_msg: err.into(),
            value,
        }
    }
}

impl<T: Sized + Default> Result<T> {
    pub fn err(err: impl Into<c_slice::Box<u8>>) -> Self {
        Result {
            status_code: FCPResponseStatus::FCPUnclassifiedError,
            error_msg: err.into(),
            value: Default::default(),
        }
    }
}

pub type GpuDeviceResponse = Result<Array<c_slice::Box<u8>>>;

#[ffi_export]
pub fn destroy_gpu_device_response(ptr: repr_c::Box<GpuDeviceResponse>) {
    drop(ptr)
}

pub type InitLogFdResponse = Result<()>;

#[ffi_export]
pub fn destroy_init_log_fd_response(ptr: repr_c::Box<InitLogFdResponse>) {
    drop(ptr)
}

/// Catch panics and return an error response
pub fn catch_panic_response<F, T>(name: &str, callback: F) -> repr_c::Box<Result<T>>
where
    T: Sized + Default,
    F: FnOnce() -> anyhow::Result<T> + std::panic::UnwindSafe,
{
    catch_panic_response_raw(name, || {
        Result::from(callback().map_err(|err| err.to_string()))
    })
}

pub fn catch_panic_response_raw<F, T>(name: &str, callback: F) -> repr_c::Box<Result<T>>
where
    T: Sized + Default,
    F: FnOnce() -> Result<T> + std::panic::UnwindSafe,
{
    match panic::catch_unwind(|| {
        init_log();
        log::info!("{}: start", name);
        let res = callback();
        log::info!("{}: end", name);
        res
    }) {
        Ok(t) => repr_c::Box::new(t),
        Err(panic) => {
            let error_msg = match panic.downcast_ref::<&'static str>() {
                Some(message) => message,
                _ => "no unwind information",
            };

            repr_c::Box::new(Result::from(Err(format!("Rust panic: {}", error_msg))))
        }
    }
}
