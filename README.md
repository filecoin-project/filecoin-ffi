# Filecoin Proofs FFI

> C and CGO bindings for Filecoin's Rust libraries

## Building

To build and install libfilcrypto, its header file and pkg-config manifest, run:

```shell
make
```

To optionally authenticate with GitHub for assets download (to increase API limits)
set `GITHUB_TOKEN` to personal access token.

If no precompiled static library is available for your operating system, the
build tooling will attempt to compile a static library from local Rust sources.

### Installation notes

By default, building this will download a pre-built binary of the ffi.  The advantages for downloading it are faster build times, and not requiring a rust toolchain and build environment.

The disadvantage to downloading the pre-built binary is that it will not be optimized for your specific hardware.  This means that if raw performance is of utmost importance to you, it's highly recommended that you build from source.

### Building from Source

To opt out of downloading precompiled assets, set `FFI_BUILD_FROM_SOURCE=1`:

```shell
rm .install-filcrypto \
    ; make clean \
    ; FFI_BUILD_FROM_SOURCE=1 make
```

To allow portable building of the `blst` dependency, set `FFI_USE_BLST_PORTABLE=1`:

```shell
rm .install-filcrypto \
    ; make clean \
    ; FFI_BUILD_FROM_SOURCE=1 FFI_USE_BLST_PORTABLE=1 make
```

By default, a 'gpu' option is used in the proofs library.  There is now an experimental 'gpu2' feature which has improved performance.  To allow building with the 'gpu2' dependency, set `FFI_USE_GPU2=1`:

```shell
rm .install-filcrypto \
    ; make clean \
    ; FFI_BUILD_FROM_SOURCE=1 FFI_USE_BLST=1 FFI_USE_GPU2=1 make
```

## Updating rust-fil-proofs (via rust-filecoin-proofs-api)

If rust-fil-proofs has changed from commit X to Y and you wish to get Y into
the filecoin-ffi project, you need to do a few things:

1. Update the rust-filecoin-proofs-api [Cargo.toml][1] file to point to Y
2. Run `cd rust && cargo update -p "filecoin-proofs-api"` from the root of the filecoin-ffi project
3. After the previous step alters your Cargo.lock file, commit and push

## go get

`go get` needs some additional steps in order to work as expected.

Get the source, add this repo as a submodule to your repo, build it and point to it:

```shell
$ go get github.com/filecoin-project/filecoin-ffi
$ git submodule add https://github.com/filecoin-project/filecoin-ffi.git extern/filecoin-ffi
$ make -C extern/filecoin-ffi
$ go mod edit -replace=github.com/filecoin-project/filecoin-ffi=./extern/filecoin-ffi
```

## Updating CGO Bindings

The CGO bindings are generated using [c-for-go](https://github.com/xlab/c-for-go)
and committed to Git. To generate bindings yourself, install the c-for-go
binary, ensure that it's on your path, and then run `make cgo-gen`. CI builds
will fail if generated CGO diverges from what's checked into Git.

## Updating the Changelog

The `mkreleaselog` script (in the project root) can be used to generate a good
portion of the filecoin-ffi changelog. For historical reasons, the script must
be run from the root of a filecoin-ffi checkout which is in your `$GOPATH`.

Run it like so:

```shell
./mkreleaselog v0.25.0 v0.26.0 > /tmp/v0.26.0.notes.txt
```

## License

MIT or Apache 2.0

[1]: https://github.com/filecoin-project/rust-filecoin-proofs-api/commit/61fde0e581cc38abc4e13dbe96145c9ad2f1f0f5
