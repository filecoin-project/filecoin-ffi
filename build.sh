#!/bin/bash

set -e

make clean
cd rust
rm -f Cargo.lock
rustup target add aarch64-apple-darwin
cargo update -p "filecoin-proofs-api"
cd ..
FFI_BUILD_FROM_SOURCE=1 make
go mod tidy
