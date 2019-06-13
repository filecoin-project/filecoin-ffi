STATIC_NAME=libfilecoin_proofs_ffi.a
BUILD_MODE=release
VERSION=$$(git rev-parse HEAD)
RUST_TOOLCHAIN_VERSION=$$(cat rust-toolchain)

all: filecoin_proofs_ffi.pc include/filecoin_proofs_ffi.h

clean:
	cargo clean
	-rm -f filecoin_proofs_ffi.pc
	-rm -f include/filecoin_proofs_ffi.h

include/filecoin_proofs_ffi.h: filecoin_proofs_ffi.pc

filecoin_proofs_ffi.pc: filecoin_proofs_ffi.pc.template Makefile Cargo.toml ./src/lib.rs
	sed -e "s;@VERSION@;$(VERSION);" \
		-e "s;@PRIVATE_LIBS@;$(shell RUSTFLAGS='--print native-static-libs' cargo +$(RUST_TOOLCHAIN_VERSION) build --$(BUILD_MODE) $(CARGO_FLAGS) 2>&1 | grep native-static-libs | cut -d ':' -f 3);" filecoin_proofs_ffi.pc.template > $@

.PHONY: all

.SILENT: filecoin_proofs.pc
