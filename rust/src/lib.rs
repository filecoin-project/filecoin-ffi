#![deny(clippy::all)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::upper_case_acronyms)]

pub mod bls;
pub mod fvm;
pub mod proofs;
pub mod util;

// Generates the headers.
// Run `HEADER_DIR=<dir> cargo test --locked build_headers --features c-headers` to build
#[safer_ffi::cfg_headers]
#[test]
fn build_headers() -> std::io::Result<()> {
    use std::env;
    use std::path::Path;

    let header_dir = env::var("HEADER_DIR").expect("Missing \"HEADER_DIR\"");
    let out_dir = Path::new(&header_dir);
    let hdr_out = out_dir.join("filcrypto.h");

    safer_ffi::headers::builder()
        .to_file(&hdr_out)?
        .generate()?;

    Ok(())
}
