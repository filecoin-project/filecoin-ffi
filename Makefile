STATIC_NAME=libfilecoin_proofs_ffi.a
BUILD_MODE=release
VERSION=$$(git rev-parse HEAD)
DUMMY_CRATE_OUTPUT=$$(mktemp)
RUST_TOOLCHAIN_VERSION=$$(cat rust-toolchain)

all: target/$(BUILD_MODE)/$(STATIC_NAME) filecoin_proofs_ffi.pc include/filecoin_proofs_ffi.h

clean:
	cargo clean
	-rm -f filecoin_proofs_ffi.pc
	-rm -f include/filecoin_proofs_ffi.h

include/filecoin_proofs_ffi.h: target/$(BUILD_MODE)/$(STATIC_NAME)

target/$(BUILD_MODE)/$(STATIC_NAME): Cargo.toml src/lib.rs
	cargo +$(RUST_TOOLCHAIN_VERSION) build --$(BUILD_MODE) $(CARGO_FLAGS)

filecoin_proofs_ffi.pc: filecoin_proofs_ffi.pc.template Makefile Cargo.toml
	sed -e "s;@VERSION@;$(VERSION);" \
		-e "s;@PRIVATE_LIBS@;$$(rustc --print native-static-libs --crate-type staticlib /dev/null -o $(DUMMY_CRATE_OUTPUT) 2>&1 | grep native-static-libs | cut -d ':' -f 3);" filecoin_proofs_ffi.pc.template > $@

.PHONY: all

.SILENT: filecoin_proofs_ffi.pc
