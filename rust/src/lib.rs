#![deny(clippy::all, clippy::perf, clippy::correctness)]
#![allow(clippy::missing_safety_doc)]

#[macro_use]
extern crate anyhow;
#[macro_use]
extern crate log;
extern crate serde_json;

pub mod bls;
pub mod proofs;
pub mod util;
