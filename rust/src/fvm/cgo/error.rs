//! Error codes used by the cgo bridge (blockstore/externs). These are used by both rust and go, so
//! don't remove them even if they seem dead.

#![allow(dead_code)]

/// The error code returned by cgo if the blockstore handle isn't valid.
pub const ERR_INVALID_HANDLE: i32 = -1;

/// The error code returned by cgo when the block isn't found.
pub const ERR_NOT_FOUND: i32 = -2;

/// The error code returned by cgo when there's some underlying system error.
pub const ERR_IO: i32 = -3;

/// The error code returned by cgo when an argument is invalid.
pub const ERR_INVALID_ARGUMENT: i32 = -4;

/// The error code returned by cgo when the application panics.
pub const ERR_PANIC: i32 = -5;
