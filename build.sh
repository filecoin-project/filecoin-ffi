#!/bin/bash

set -e

make clean
cd rust
rm -f Cargo.lock
cargo update -p "filecoin-proofs-api"
cargo install cbindgen
cbindgen --clean --config cbindgen.toml --crate filcrypto --output ../include/filcrypto.h
cd ..
FFI_BUILD_FROM_SOURCE=1 FFI_USE_BLST=1 FFI_USE_GPU2=1 make
make cgo-gen
go mod tidy
