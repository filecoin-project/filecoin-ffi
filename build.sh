#!/bin/bash

set -e

make clean
cd rust
rm Cargo.lock
cargo update -p "filecoin-proofs-api"
cargo install cbindgen

# Generate API v1 bindings
pushd api-v1
cbindgen --clean --config cbindgen.toml --crate filcrypto-v1 --output ../../include/filcrypto-v1.h
popd

# Generate API v2 bindings
pushd api-v2
cbindgen --clean --config cbindgen.toml --crate filcrypto-v2 --output ../../include/filcrypto-v2.h
popd

cd ..
FFI_BUILD_FROM_SOURCE=1 make
go mod tidy
