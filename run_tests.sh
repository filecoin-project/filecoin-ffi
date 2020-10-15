#!/bin/bash

RUST_LOG=info go test --ldflags '-extldflags "-L/tmp/__fil-hwloc/lib -lhwloc"' -count=1 ./... && cd rust && cargo test --release --all && cd ..
