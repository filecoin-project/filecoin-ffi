# Filecoin Proofs FFI

> C and CGO bindings for Filecoin's Rust libraries

## Building

To build and install libfilcrypto, its header file and pkg-config manifest, run:

```shell
make
```

If no precompiled static library is available for your operating system, the
build tooling will attempt to compile a static library from local Rust sources.

### Forcing Local Build

To opt out of downloading precompiled assets, set `FFI_BUILD_FROM_SOURCE=1`:

```shell
rm .install-filcrypto \
    ; make clean \
    ; FFI_BUILD_FROM_SOURCE=1 make
```

## Updating CGO Bindings

The CGO bindings are generated using [c-for-go](https://github.com/xlab/c-for-go)
and committed to Git. To generate bindings yourself, install the c-for-go
binary, ensure that it's on your path, and then run `make cgo-gen`. CI builds
will fail if generated CGO diverges from what's checked into Git.

## License

MIT or Apache 2.0
