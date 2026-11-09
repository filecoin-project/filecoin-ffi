#!/usr/bin/env bash

set -Exeo pipefail

main() {
    if [[ -z "${1}" ]]
    then
        (>&2 echo '[build-release/main] Error: script requires a build action, e.g. ./build-release.sh build')
        exit 1
    fi

    if [[ "${1}" != "build" ]]
    then
        (>&2 echo "[build-release/main] Error: unsupported build action '${1}' (only 'build' is supported; universal 'lipo' builds were removed with darwin/amd64 support)")
        exit 1
    fi

    # temporary place for storing build output (cannot use 'local', because
    # 'trap' is not going to have access to variables scoped to this function)
    #
    __build_output_log_tmp=$(mktemp)

    # clean up temp file on exit
    #
    trap '{ rm -f $__build_output_log_tmp; }' EXIT

    # build with RUSTFLAGS configured to output linker flags for native libs
    #
    local __rust_flags="--print native-static-libs ${RUSTFLAGS}"

    local __extra_features=""
    if [[ -z "${FFI_DISABLE_FVM}" ]]; then
        __extra_features="--features fvm"
    fi

    # shellcheck disable=SC2068 # the rest of the parameters should be split
    RUSTFLAGS="${__rust_flags}" \
        cargo build \
        --release --locked ${@:2} ${__extra_features} 2>&1 | tee ${__build_output_log_tmp}

    # parse build output for linker flags
    #
    local __linker_flags=$(cat ${__build_output_log_tmp} \
        | grep native-static-libs\: \
        | head -n 1 \
        | cut -d ':' -f 3)

    echo "Linker Flags: ${__linker_flags}"
    # On macOS, OpenCL is a framework rather than a plain library. This does
    # nothing if rustc already emitted `-framework OpenCL`.
    if [ "$(uname -s)" = "Darwin" ]; then
        __linker_flags=$(echo ${__linker_flags} | sed 's/-lOpenCL/-framework OpenCL/g')
        echo "Using Linker Flags: ${__linker_flags}"
    fi

    # generate filcrypto.h
    # Check if FVM is in the build features - if so, include it in header generation
    local __header_features="c-headers"
    if [[ -z "${FFI_DISABLE_FVM}" ]]; then  
        __header_features="c-headers,fvm"
    fi
    RUSTFLAGS="${__rust_flags}" HEADER_DIR="." \
        cargo test --no-default-features --locked build_headers --features ${__header_features}

    # generate pkg-config
    #
    sed -e "s;@VERSION@;$(git rev-parse HEAD);" \
        -e "s;@PRIVATE_LIBS@;${__linker_flags};" "filcrypto.pc.template" > "filcrypto.pc"

    # ensure header file was built
    #
    find -L . -type f -name "filcrypto.h" | read

    # ensure the archive file was built
    #
    find -L . -type f -name "libfilcrypto.a" | read
}

main "$@"; exit
