#![deny(clippy::all, clippy::perf, clippy::correctness)]

#[macro_use]
extern crate failure;
#[macro_use]
extern crate lazy_static;

mod error;
mod helpers;
mod singletons;

pub mod api;
pub mod responses;
