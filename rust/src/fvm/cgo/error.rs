//! Error codes used by the cgo bridge (blockstore/externs). These are used by both rust and go, so
//! don't remove them even if they seem dead.

use safer_ffi::prelude::*;

#[derive_ReprC]
#[repr(i32)]
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub enum FvmError {
    /// The error code returned by cgo if the blockstore handle isn't valid.
    InvalidHandle = -1,
    /// The error code returned by cgo when the block isn't found.
    NotFound = -2,
    /// The error code returned by cgo when there's some underlying system error.
    Io = -3,
    /// The error code returned by cgo when an argument is invalid.
    InvalidArgument = -4,
    /// The error code returned by cgo when the application panics.
    Panic = -5,
}

// Dummy to make safer-ffi export the error enum
#[ffi_export]
fn dummy(_error: FvmError) {
    panic!("Don't call me");
}
