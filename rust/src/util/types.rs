use std::{
    ffi::CStr,
    fmt::Display,
    mem::ManuallyDrop,
    ops::Deref,
    path::{Path, PathBuf},
    ptr,
    str::Utf8Error,
};

// `CodeAndMessage` is the trait implemented by `code_and_message_impl
use ffi_toolkit::{CodeAndMessage, FCPResponseStatus};

#[repr(C)]
pub struct fil_Array<T: Sized> {
    ptr: *mut T,
    len: usize,
}

impl<T: Clone> Clone for fil_Array<T> {
    fn clone(&self) -> Self {
        let ptr = unsafe { clone_box_parts(self.ptr, self.len).cast() };

        fil_Array { len: self.len, ptr }
    }
}

impl<T> Default for fil_Array<T> {
    fn default() -> Self {
        Self {
            ptr: ptr::null_mut(),
            len: 0,
        }
    }
}

impl<T: Sized> fil_Array<T> {
    pub fn as_parts(&self) -> (*const T, usize) {
        (self.ptr.cast(), self.len)
    }

    pub fn is_null(&self) -> bool {
        self.ptr.is_null()
    }
}

#[allow(non_camel_case_types)]
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
        let ptr = Box::into_raw(buf).cast();

        Self { ptr, len }
    }
}

impl<T> Drop for fil_Array<T> {
    fn drop(&mut self) {
        unsafe { drop_box_from_parts(self.ptr) }
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

impl From<PathBuf> for fil_Bytes {
    fn from(s: PathBuf) -> Self {
        s.to_string_lossy().as_ref().into()
    }
}

impl From<&Path> for fil_Bytes {
    fn from(s: &Path) -> Self {
        s.to_string_lossy().as_ref().into()
    }
}

impl From<Box<str>> for fil_Bytes {
    fn from(s: Box<str>) -> Self {
        if s.is_empty() {
            return Default::default();
        }
        let len = s.len();
        let ptr = Box::into_raw(s).cast();

        Self { ptr, len }
    }
}

impl fil_Bytes {
    pub fn as_str(&self) -> Result<&str, Utf8Error> {
        std::str::from_utf8(self)
    }

    pub fn as_path(&self) -> Result<PathBuf, Utf8Error> {
        self.as_str().map(PathBuf::from)
    }
}

#[repr(C)]
pub struct fil_Result<T: Sized> {
    pub status_code: FCPResponseStatus,
    pub error_msg: fil_Bytes,
    pub value: T,
}

impl<T: Sized + Default> Default for fil_Result<T> {
    fn default() -> Self {
        fil_Result {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: Default::default(),
            value: Default::default(),
        }
    }
}

impl<T: Sized> CodeAndMessage for fil_Result<T> {
    fn set_error(&mut self, code_and_message: (FCPResponseStatus, *mut libc::c_char)) {
        let s = unsafe { CStr::from_ptr(code_and_message.1.cast()) }
            .to_string_lossy()
            .to_string();
        self.status_code = code_and_message.0;
        self.error_msg = s.into();
    }
}

impl<T, E> From<Result<T, E>> for fil_Result<T>
where
    T: Sized + Default,
    E: Display,
{
    fn from(r: Result<T, E>) -> Self {
        match r {
            Ok(value) => Self::ok(value),
            Err(e) => Self::err(e.to_string()),
        }
    }
}

impl<T> From<T> for fil_Result<T>
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

impl<T: Sized> fil_Result<T> {
    pub fn ok(value: T) -> Self {
        fil_Result {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: Default::default(),
            value,
        }
    }

    pub unsafe fn into_boxed_raw(self) -> *mut fil_Result<T> {
        Box::into_raw(Box::new(self))
    }
}

impl<T: Sized + Default> fil_Result<T> {
    pub fn err(err: impl Into<fil_Bytes>) -> Self {
        fil_Result {
            status_code: FCPResponseStatus::FCPUnclassifiedError,
            error_msg: err.into(),
            value: Default::default(),
        }
    }
}

#[allow(non_camel_case_types)]
pub type fil_GpuDeviceResponse = fil_Result<fil_Array<fil_Bytes>>;

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_gpu_device_response(ptr: *mut fil_GpuDeviceResponse) {
    let _ = Box::from_raw(ptr);
}

#[allow(non_camel_case_types)]
pub type fil_InitLogFdResponse = fil_Result<()>;

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_init_log_fd_response(ptr: *mut fil_InitLogFdResponse) {
    let _ = Box::from_raw(ptr);
}

pub fn vec_into_raw<T>(v: Vec<T>) -> (*mut T, usize) {
    let bytes = v.into_boxed_slice();
    let len = bytes.len();
    (Box::into_raw(bytes).cast(), len)
}

/// `ptr` must be allocated using `Box::into_raw` or be null.
pub unsafe fn drop_box_from_parts<T>(ptr: *mut T) {
    if !ptr.is_null() {
        let _ = Box::from_raw(ptr);
    }
}

/// `ptr` must be allocated using `Box::into_raw` or be null.
pub unsafe fn clone_box_parts<T: Clone>(ptr: *const T, len: usize) -> *mut T {
    if ptr.is_null() {
        return ptr::null_mut();
    }

    // restore, but without triggering a drop on the original
    // safe to cast as *mut as we don't mutate
    let bytes: ManuallyDrop<Box<[T]>> = ManuallyDrop::new(Box::from_raw(
        std::slice::from_raw_parts_mut(ptr as *mut _, len),
    ));

    // duplicate the bytes
    let bytes2 = ManuallyDrop::into_inner(bytes.clone());
    Box::into_raw(bytes2).cast()
}

/// `ptr` must be allocated using `Box::into_raw` or be null.
pub unsafe fn clone_as_vec_from_parts<T: Clone>(ptr: *const T, len: usize) -> Vec<T> {
    if ptr.is_null() {
        return Vec::new();
    }

    // restore, but without triggering a drop on the original
    // safe to cast as *mut as we don't mutate
    let bytes: ManuallyDrop<Box<[T]>> = ManuallyDrop::new(Box::from_raw(
        std::slice::from_raw_parts_mut(ptr as *mut _, len),
    ));

    // duplicate the bytes
    bytes.to_vec()
}
