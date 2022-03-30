/// cbindgen:ignore
#[cfg(not(feature = "bindgen"))]
mod cgo;
#[cfg(not(feature = "bindgen"))]
pub use cgo::*;

#[cfg(feature = "bindgen")]
mod mock;
#[cfg(feature = "bindgen")]
pub use mock::*;

mod error;
pub use error::*;
