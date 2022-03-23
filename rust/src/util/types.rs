use std::{
    fmt::Display,
    ops::Deref,
    panic,
    path::{Path, PathBuf},
    ptr::NonNull,
    str::Utf8Error,
};

use super::api::init_log;

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

/// Owned, fixed size and heap allocated array of bytes.
pub type Bytes = Array<u8>;

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
        match self.ptr {
            None => &[],
            Some(ptr) => unsafe { std::slice::from_raw_parts(ptr.as_ptr().cast(), self.len) },
        }
    }
}

impl From<&str> for Bytes {
    fn from(s: &str) -> Self {
        if s.is_empty() {
            return Default::default();
        }
        Box::<str>::from(s).into()
    }
}

impl From<String> for Bytes {
    fn from(s: String) -> Self {
        if s.is_empty() {
            return Default::default();
        }
        s.into_boxed_str().into()
    }
}

impl From<PathBuf> for Bytes {
    fn from(s: PathBuf) -> Self {
        s.to_string_lossy().as_ref().into()
    }
}

impl From<&Path> for Bytes {
    fn from(s: &Path) -> Self {
        s.to_string_lossy().as_ref().into()
    }
}

impl From<Box<str>> for Bytes {
    fn from(s: Box<str>) -> Self {
        if s.is_empty() {
            return Default::default();
        }
        let len = s.len();
        let ptr = NonNull::new(Box::into_raw(s).cast());

        Self { ptr, len }
    }
}

impl Bytes {
    pub fn as_str(&self) -> std::result::Result<&str, Utf8Error> {
        std::str::from_utf8(self)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn as_path(&self) -> std::result::Result<PathBuf, Utf8Error> {
        self.as_str().map(Into::into)
    }

    #[cfg(target_os = "linux")]
    pub fn as_path(&self) -> std::result::Result<PathBuf, Utf8Error> {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        Ok(OsStr::from_bytes(self).into())
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct Result<T: Sized> {
    pub status_code: FCPResponseStatus,
    pub error_msg: Bytes,
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
            Err(e) => Self::err(e.to_string()),
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

    pub fn err_with_default(err: impl Into<Bytes>, value: T) -> Self {
        Result {
            status_code: FCPResponseStatus::FCPUnclassifiedError,
            error_msg: err.into(),
            value,
        }
    }
}

impl<T: Sized + Default> Result<T> {
    pub fn err(err: impl Into<Bytes>) -> Self {
        Result {
            status_code: FCPResponseStatus::FCPUnclassifiedError,
            error_msg: err.into(),
            value: Default::default(),
        }
    }
}

pub type GpuDeviceResponse = Result<Array<Bytes>>;

#[no_mangle]
pub unsafe extern "C" fn destroy_gpu_device_response(ptr: *mut GpuDeviceResponse) {
    let _ = Box::from_raw(ptr);
}

pub type InitLogFdResponse = Result<()>;

#[no_mangle]
pub unsafe extern "C" fn destroy_init_log_fd_response(ptr: *mut InitLogFdResponse) {
    let _ = Box::from_raw(ptr);
}

/// Catch panics and return an error response
pub fn catch_panic_response<F, T>(name: &str, callback: F) -> *mut Result<T>
where
    T: Sized + Default,
    F: FnOnce() -> anyhow::Result<T> + std::panic::UnwindSafe,
{
    catch_panic_response_raw(name, || {
        Result::from(callback().map_err(|err| err.to_string()))
    })
}

pub fn catch_panic_response_raw<F, T>(name: &str, callback: F) -> *mut Result<T>
where
    T: Sized + Default,
    F: FnOnce() -> Result<T> + std::panic::UnwindSafe,
{
    let result = match panic::catch_unwind(|| {
        init_log();
        log::info!("{}: start", name);
        let res = callback();
        log::info!("{}: end", name);
        res
    }) {
        Ok(t) => t,
        Err(panic) => {
            let error_msg = match panic.downcast_ref::<&'static str>() {
                Some(message) => message,
                _ => "no unwind information",
            };

            Result::from(Err(format!("Rust panic: {}", error_msg)))
        }
    };

    unsafe { result.into_boxed_raw() }
}
