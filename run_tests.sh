#!/bin/bash

RUST_LOG=info go test -count=1 ./... && cd rust/api-v1 && cargo test --release --all && cd ../rust/api-v2 && cargo test --release --all && cd ..
