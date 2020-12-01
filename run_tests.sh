#!/bin/bash

RUST_LOG=info go test -count=1 ./... && cd rust && RUSTFLAGS="-C target-cpu=native" cargo test --release --all && cd ..
