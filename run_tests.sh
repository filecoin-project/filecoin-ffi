#!/bin/bash

RUST_LOG=info go test -mod=mod -count=1 ./... && cd rust && cargo test --release --all && cd ..
