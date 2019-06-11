STATIC_NAME=libfilecoin_proofs.a
BUILD_MODE=release
VERSION=$$(git rev-parse HEAD))
DUMMY_CRATE_OUTPUT=$$(mktemp)

all: target/$(BUILD_MODE)/$(STATIC_NAME) filecoin_proofs.pc include/filecoin_proofs.h

clean:
	cargo clean
	-rm -f filecoin_proofs.pc
	-rm -f include/filecoin_proofs.h

include/filecoin_proofs.h: target/$(BUILD_MODE)/$(STATIC_NAME)

target/$(BUILD_MODE)/$(STATIC_NAME): Cargo.toml src/lib.rs
	cargo build --$(BUILD_MODE) --all

filecoin_proofs.pc: filecoin_proofs.pc.template Makefile Cargo.toml
	sed -e "s;@VERSION@;$(VERSION);" \
		-e "s;@PRIVATE_LIBS@;$$(rustc --print native-static-libs --crate-type staticlib /dev/null -o $(DUMMY_CRATE_OUTPUT) 2>&1 | grep native-static-libs | cut -d ':' -f 3);" filecoin_proofs.pc.template > $@

.PHONY: all
