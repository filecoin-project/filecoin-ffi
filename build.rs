extern crate cbindgen;

use cbindgen::{Config, RenameRule};

const VERSION: &'static str = env!("CARGO_PKG_VERSION");

fn main() {
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();

    println!("cargo:rerun-if-changed=Cargo.lock");
    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-changed=src/");

    let config = {
        let mut c: Config = Default::default();

        c.header = Some(
            format!(
                r##"
/* libfilecoin_proofs Header Version {} */

#ifdef __cplusplus
extern "C" {{
#endif
"##,
                VERSION
            )
            .trim()
            .into(),
        );

        c.trailer = Some(
            r##"
#ifdef __cplusplus
} /* extern "C" */
#endif
"##
            .trim()
            .into(),
        );

        c.include_guard = Some("LIBFILECOIN_PROOFS_CAPI_H".to_owned());
        c.language = cbindgen::Language::C;
        c.enumeration.rename_variants = Some(RenameRule::QualifiedScreamingSnakeCase);
        c
    };

    // Generate libfilecoin_proofs.h.
    cbindgen::generate_with_config(&crate_dir, config)
        .expect("Could not generate header")
        .write_to_file("include/libfilecoin_proofs.h");
}
