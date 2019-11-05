#![deny(clippy::all, clippy::perf, clippy::correctness)]
#![allow(clippy::missing_safety_doc)]

#[macro_use]
extern crate failure;
#[macro_use]
extern crate log;

mod error;
mod helpers;

pub mod api;
pub mod types;
