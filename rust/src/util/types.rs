use std::{fmt::Display, mem::MaybeUninit, ops::Deref, panic, path::PathBuf, str::Utf8Error};

use safer_ffi::prelude::*;

use super::api::init_log;

#[derive_ReprC]
#[repr(i32)]
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub enum FCPResponseStatus {
    // Don't use FCPSuccess, since that complicates description of 'successful' verification.
    NoError = 0,
    UnclassifiedError = 1,
    CallerError = 2,
    ReceiverError = 3,
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
            status_code: FCPResponseStatus::NoError,
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
            status_code: FCPResponseStatus::NoError,
            error_msg: Default::default(),
            value,
        }
    }
}

impl<T: Sized> Result<T> {
    pub fn ok(value: T) -> Self {
        Result {
            status_code: FCPResponseStatus::NoError,
            error_msg: Default::default(),
            value,
        }
    }

    pub unsafe fn into_boxed_raw(self) -> *mut Result<T> {
        Box::into_raw(Box::new(self))
    }

    pub fn err_with_default(err: impl Into<c_slice::Box<u8>>, value: T) -> Self {
        Result {
            status_code: FCPResponseStatus::UnclassifiedError,
            error_msg: err.into(),
            value,
        }
    }

    /// Safety: value must not be accessed.
    pub unsafe fn err_no_default(err: impl Into<c_slice::Box<u8>>) -> Self {
        Result {
            status_code: FCPResponseStatus::UnclassifiedError,
            error_msg: err.into(),
            value: MaybeUninit::zeroed().assume_init(),
        }
    }
}

impl<T: Sized + Default> Result<T> {
    pub fn err(err: impl Into<c_slice::Box<u8>>) -> Self {
        Result {
            status_code: FCPResponseStatus::UnclassifiedError,
            error_msg: err.into(),
            value: Default::default(),
        }
    }
}

pub type GpuDeviceResponse = Result<c_slice::Box<c_slice::Box<u8>>>;

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
        Result::from(callback().map_err(|err| format!("{err:?}")))
    })
}

pub fn catch_panic_response_no_log<F, T>(callback: F) -> repr_c::Box<Result<T>>
where
    T: Sized + Default,
    F: FnOnce() -> anyhow::Result<T> + std::panic::UnwindSafe,
{
    catch_panic_response_raw_no_log(|| Result::from(callback().map_err(|err| format!("{err:?}"))))
}

pub fn catch_panic_response_raw_no_log<F, T>(callback: F) -> repr_c::Box<Result<T>>
where
    T: Sized + Default,
    F: FnOnce() -> Result<T> + std::panic::UnwindSafe,
{
    let result = match panic::catch_unwind(callback) {
        Ok(t) => t,
        Err(panic) => {
            let error_msg = match panic.downcast_ref::<&'static str>() {
                Some(message) => message,
                _ => "no unwind information",
            };

            Result::from(Err(format!("Rust panic: {}", error_msg)))
        }
    };

    repr_c::Box::new(result)
}

pub fn catch_panic_response_raw<F, T>(name: &str, callback: F) -> repr_c::Box<Result<T>>
where
    T: Sized + Default,
    F: FnOnce() -> Result<T> + std::panic::UnwindSafe,
{
    catch_panic_response_raw_no_log(|| {
        init_log();
        log::debug!("{}: start", name);
        let res = callback();
        log::debug!("{}: end", name);
        res
    })
}

pub unsafe fn catch_panic_response_no_default<F, T>(
    name: &str,
    callback: F,
) -> repr_c::Box<Result<T>>
where
    T: Sized,
    F: FnOnce() -> anyhow::Result<T> + std::panic::UnwindSafe,
{
    let result = match panic::catch_unwind(|| {
        init_log();
        log::debug!("{}: start", name);
        let res = callback();
        log::debug!("{}: end", name);
        res
    }) {
        Ok(t) => match t {
            Ok(t) => Result::ok(t),
            Err(err) => Result::err_no_default(format!("{err:?}").into_bytes().into_boxed_slice()),
        },
        Err(panic) => {
            let error_msg = match panic.downcast_ref::<&'static str>() {
                Some(message) => message,
                _ => "no unwind information",
            };

            Result::err_no_default(
                format!("Rust panic: {}", error_msg)
                    .into_bytes()
                    .into_boxed_slice(),
            )
        }
    };

    repr_c::Box::new(result)
}

/// Generate a destructor for the given type wrapped in a `repr_c::Box`.
#[macro_export]
macro_rules! destructor {
    ($name:ident, $type:ty) => {
        /// Destroys the passed in `repr_c::Box<$type>`.
        #[ffi_export]
        fn $name(ptr: repr_c::Box<$type>) {
            drop(ptr);
        }
    };
}
