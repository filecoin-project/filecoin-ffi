/// The error code returned by cgo if the blockstore handle isn't valid.
#[allow(dead_code)]
pub const ERR_INVALID_HANDLE: i32 = -1;
/// The error code returned by cgo when the block isn't found.
#[allow(dead_code)]
pub const ERR_NOT_FOUND: i32 = -2;
/// The error code returned by cgo when there's some underlying system error.
#[allow(dead_code)]
pub const ERR_IO: i32 = -3;
/// The error code returned by cgo when an argument is invalid.
#[allow(dead_code)]
pub const ERR_INVALID_ARGUMENT: i32 = -4;
