/// cbindgen:ignore
#[cfg(not(feature = "bindgen"))]
mod cgo;
#[cfg(not(feature = "bindgen"))]
pub use cgo::*;

// We need these so that cbindgen doesn't try to generate "externs" for them. If it does, c-for-go
// can't parse the header.

#[cfg(feature = "bindgen")]
mod mock;
#[cfg(feature = "bindgen")]
pub use mock::*;

mod error;
pub use error::*;
