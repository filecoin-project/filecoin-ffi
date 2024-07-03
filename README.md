[![Build Status][circleci-image]][circleci-link]

# Filecoin FFI

> C and CGO bindings for Filecoin's Rust libraries, i.e: [proofs](https://github.com/filecoin-project/rust-fil-proofs) and [ref-fvm](https://github.com/filecoin-project/ref-fvm). This repository is built to enable the reference implementation of Filecoin, [Lotus](https://github.com/filecoin-project/lotus), to consume the Rust libraries that are needed.

## Building

To build and install libfilcrypto, its header file and pkg-config manifest, run:

```shell
make
```

To optionally authenticate with GitHub for assets download (to increase API limits) set `GITHUB_TOKEN` to personal access token.

If no precompiled static library is available for your operating system, the build tooling will attempt to compile a static library from local Rust sources.

### Installation notes

By default, building this will download a pre-built binary of the ffi. The advantages for downloading it are faster build times, and not requiring a rust toolchain and build environment.

The disadvantage to downloading the pre-built binary is that it will not be optimized for your specific hardware. This means that if raw performance is of utmost importance to you, it's highly recommended that you build from source.

### Building from Source

To opt out of downloading precompiled assets, set `FFI_BUILD_FROM_SOURCE=1`:

To allow portable building of the `blst` dependency, set `FFI_USE_BLST_PORTABLE=1`:

```shell
rm .install-filcrypto \
    ; make clean \
    ; FFI_BUILD_FROM_SOURCE=1 FFI_USE_BLST_PORTABLE=1 make
```

By default, a 'gpu' option is used in the proofs library. This feature is also used in FFI unless explicitly disabled. To disable building with the 'gpu' dependency, set `FFI_USE_GPU=0`:

```shell
rm .install-filcrypto \
    ; make clean \
    ; FFI_BUILD_FROM_SOURCE=1 FFI_USE_GPU=0 make
```

#### GPU support

CUDA for GPU support is now enabled by default in the proofs library. This feature can optionally be replaced by OpenCL by using `FFI_USE_OPENCL=1` set in the environment when building from source. Alternatively, if the CUDA toolkit (such as `nvcc`) cannot be located in the environment, OpenCL support is used instead. To disable GPU support entirely, set `FFI_USE_GPU=0` in the environment when building from source.

There is experimental support for faster C2 named "SupraSeal". To enable it, set `FFI_USE_CUDA_SUPRASEAL=1`. It's specific to CUDA and won't work with OpenCL.

```shell
rm .install-filcrypto \
    ; make clean \
    ; FFI_BUILD_FROM_SOURCE=1 make
```

By default, a 'multicore-sdr' option is used in the proofs library. This feature is also used in FFI unless explicitly disabled. To disable building with the 'multicore-sdr' dependency, set `FFI_USE_MULTICORE_SDR=0`:

```shell
rm .install-filcrypto \
    ; make clean \
    ; FFI_BUILD_FROM_SOURCE=1 FFI_USE_MULTICORE_SDR=0 make
```

## Updating rust-fil-proofs (via rust-filecoin-proofs-api)

If rust-fil-proofs has changed from commit X to Y and you wish to get Y into the filecoin-ffi project, you need to do a few things:

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

## Updating the Changelog

The `mkreleaselog` script (in the project root) can be used to generate a good
portion of the filecoin-ffi changelog. For historical reasons, the script must
be run from the root of a filecoin-ffi checkout which is in your `$GOPATH`.

Run it like so:

```shell
./mkreleaselog v0.25.0 v0.26.0 > /tmp/v0.26.0.notes.txt
```

## Contribution 

### Maintainers

The core maintainers of this repository are:
- @Filoz
- [Elliptic Research](https://www.ellipticresearch.com/)

Maintainers are not only the contributors of this repository, but also exercise a range of editorial responsibilities to keep the repository organized for the OSS contributors, that includes triage the issues, review and merge/close PRs, publish releases and so on.

### Development Guidelines (WIP)

#### CI Builds

To start a CI job to build binaries off of a commit push a tag starting with the character `v`, i.e. `v1.22.0-rc2`.

#### Branches

`master` is considered as the development branch of this repository. Changes being introduced to master must be tested (programmable and/or manual). The head of the master will be tagged and released upon the merge of each PR automatically.

We will cooperates with the [lotus' releases and it's testing flows](https://github.com/filecoin-project/lotus/blob/0c91b0dc1012c3e54b305a76bb25fb68390adf9d/LOTUS_RELEASE_FLOW.md?plain=1#L50) to confirm whether a tagged release is production ready:

*Non-consensus breaking changes*
- All PRs introducing non-consensus breaking changes can be merged to master as long they have maintainers' approvals.
- Roughly on a monthly basis, lotus will integrate ffi's head in `master` branch, for it's new feature release, and carry it through the testing flows.
  - `release/lotus-vX` will be created to determine the commit that lotus integrates in the corresponding release.
- If any bug is found during the testing, the fix should land in master then get backported to `release/lotus-vX`. The updated commit should be integrated into lotus and getting tested. Repeat the steps until it can be considered as stable.

*Consensus breaking changes*
- Consensus breaking changes should be developed in it's own branch, (branch name is suggested to be: feature branches `feat/` or bug fix branches `bug/`). 
- Consensus breaking changes that are scoped into the next immediate network upgrade shall land in `next` branch first. The maintainers are responsible to coordinate on when to land `next` to `master` according to lotus mandatory(network upgrade) release schedules.
- A new dev branch should be created and contributors are responsible to rebase the branch onto `master`/`next` as needed.

#### Versioning

The versioning in Filecoin-FFI currently follows the Lotus versioning.  For example, if you are cutting a release for Lotus v1.28.0-rc1, the Filecoin-FFI release will be named v1.28.0-rc1 as well.  (Note: Lotus versioning will be refactored in the near future as part of [lotus #12072](https://github.com/filecoin-project/lotus/issues/12072).)

#### Release Process

##### Cutting a development or release candidate release

<details>
  <summary>Steps to cut a development or release candidate release:</summary>

1. Go to [Filecoin-FFI Releases](https://github.com/filecoin-project/filecoin-ffi/releases).
2. Click the "Draft a new release" button in the right corner.
3. In the "Choose a tag" dropdown, enter the desired version and click "Create new tag: vX.XX.X-rcX/dev on publish".
4. Target the master branch.
5. Set the previous tag to compare against, which should be the last stable release.
6. Click the "Generate release notes" button.
6. Check the "Set as a pre-release" checkbox.
7. Click "Publish release" to create the release.

</details>

##### Cutting a definitive release

<details>
  <summary>Steps to cut a definitive release:</summary>

1. Go to [Filecoin-FFI Releases](https://github.com/filecoin-project/filecoin-ffi/releases).
2. Click the "Draft a new release" button in the right corner.
3. In the "Choose a tag" dropdown, enter the desired version and click "Create new tag: vX.XX.X on publish".
4. Target the release candidate you want to create a stable.
5. Set the previous tag to compare against, which should be the last stable release (e.g., non-RC)
6. click the "Generate release notes" button.
6. Ensure the "Set as a latest release" checkbox **is checked**.
7. Click "Publish release" to create the release.

</details>

## License

This repository is dual-licensed under Apache 2.0 and MIT terms.

[1]: https://github.com/filecoin-project/rust-filecoin-proofs-api/commit/61fde0e581cc38abc4e13dbe96145c9ad2f1f0f5

[circleci-image]: https://circleci.com/gh/filecoin-project/filecoin-ffi.svg?branch=master&style=shield
[circleci-link]: https://app.circleci.com/pipelines/github/filecoin-project/filecoin-ffi?branch=master
