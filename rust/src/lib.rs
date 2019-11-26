#![deny(clippy::all, clippy::perf, clippy::correctness)]
#![allow(clippy::missing_safety_doc)]

#[macro_use]
extern crate failure;
#[macro_use]
extern crate log;

pub mod bls;
pub mod proofs;
