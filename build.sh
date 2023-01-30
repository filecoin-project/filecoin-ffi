#!/bin/bash

set -e

make clean
cd rust
rm -f Cargo.lock
rustup target add x86_64-apple-darwin --toolchain $(cat rust-toolchain)
rustup target add aarch64-apple-darwin --toolchain $(cat rust-toolchain)
rustup target add x86_64-pc-windows-gnu --toolchain $(cat rust-toolchain)
cargo update -p "filecoin-proofs-api"
cargo install cargo-lipo
cd ..
FFI_BUILD_FROM_SOURCE=1 make
go mod tidy
