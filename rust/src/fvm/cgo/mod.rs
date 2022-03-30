/// cbindgen:ignore
#[cfg(not(feature = "bindgen"))]
mod externs;
#[cfg(not(feature = "bindgen"))]
pub use externs::*;

#[cfg(feature = "bindgen")]
mod mock;
#[cfg(feature = "bindgen")]
pub use mock::*;

mod error;
pub use error::*;
