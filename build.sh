#!/bin/bash

set -e

make clean

pushd rust > /dev/null
rm Cargo.lock
cargo update -p "filecoin-proofs-api"
cargo install cbindgen
cbindgen --clean --config cbindgen.toml --crate filcrypto --output ../include/filcrypto.h
popd > /dev/null

FFI_BUILD_FROM_SOURCE=1 make

# This is hacky
cat include/filcrypto.h | grep -v "#include <stdarg.h>" > include/filcrypto.h.1
sed -i 's/<stdint.h>/"stdint.h"/g' include/filcrypto.h.1

cp include/filcrypto.h.1 filcrypto.h

make cgo-gen

go mod tidy
