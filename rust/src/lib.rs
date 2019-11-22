use std::os::raw::c_int;

extern crate filecoin_proofs_ffi;

pub use filecoin_proofs_ffi::api::write_without_alignment;

#[no_mangle]
pub unsafe extern fn sum_2(
    x: c_int,
    y: c_int,
    z: c_int,
) -> c_int {
    x + y + z
}
