fn main() {
    println!("cargo:rerun-if-changed=src/");

    cbindgen::generate(std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .expect("Could not generate header")
        .write_to_file("include/filecoin_proofs_ffi.h");
}
