#!/usr/bin/env bash

set -Exeo pipefail

main() {
    if [[ -z "${1}" ]]
    then
        (>&2 echo '[build-release/main] Error: script requires a build action, e.g. ./build-release.sh [build|lipo]')
        exit 1
    fi

    local __action="${1}"

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

    # shellcheck disable=SC2068 # the rest of the parameters should be split
    RUSTFLAGS="${__rust_flags}" \
        cargo build \
        --release --locked ${@:2} 2>&1 | tee ${__build_output_log_tmp}

    # parse build output for linker flags
    #
    local __linker_flags=$(cat ${__build_output_log_tmp} \
        | grep native-static-libs\: \
        | head -n 1 \
        | cut -d ':' -f 3)

    echo "Linker Flags: ${__linker_flags}"
    # Build a universal binary when `lipo` is enabled, independent of which
    # architecture we are on.
    if [ "${__action}" = "lipo" ]; then
        # With lipo enabled, this replacement may not be necessary,
        # but leaving it in doesn't hurt as it does nothing if not
        # needed
        __linker_flags=$(echo ${__linker_flags} | sed 's/-lOpenCL/-framework OpenCL/g')
        echo "Using Linker Flags: ${__linker_flags}"

        # Build again for the other architecture.
        if [ "$(uname -m)" = "x86_64" ]; then
            __target="aarch64-apple-darwin"
        else
            __target="x86_64-apple-darwin"
        fi

        # shellcheck disable=SC2068 # the rest of the parameters should be split
        RUSTFLAGS="${__rust_flags}" \
            cargo build \
            --release --locked --target ${__target} ${@:2} 2>&1 \
            | tee ${__build_output_log_tmp}

        # Create the universal binary/
        lipo -create -output libfilcrypto.a \
            target/release/libfilcrypto.a \
            target/${__target}/release/libfilcrypto.a

        find . -type f -name "libfilcrypto.a"
        rm -f ./target/aarch64-apple-darwin/release/libfilcrypto.a
        rm -f ./target/x86_64-apple-darwin/release/libfilcrypto.a
        rm -f ./target/release/libfilcrypto.a
        echo "Eliminated non-universal binary libraries"
        find . -type f -name "libfilcrypto.a"
    fi

    local __has_no_default_features=0
    local __has_fvm_feature=0
    local __features_list=""
    
    # Iterate through arguments to find --no-default-features and --features
    local i=2
    while [[ $i -le $# ]]; do
        local arg="${!i}"
        if [[ "$arg" == "--no-default-features" ]]; then
            __has_no_default_features=1
        elif [[ "$arg" == --features=* ]]; then
            # Handle --features=value format
            __features_list="${arg#--features=}"
        elif [[ "$arg" == "--features" ]]; then
            # Handle --features value format (next argument is the value)
            ((i++))
            if [[ $i -le $# ]]; then
                __features_list="${!i}"
            fi
        fi
        ((i++))
    done
    
    # Check if fvm is in the features list
    if [[ -n "${__features_list}" ]]; then
        IFS=',' read -ra __features_array <<< "${__features_list}"
        for feature in "${__features_array[@]}"; do
            if [[ "$feature" == "fvm" ]]; then
                __has_fvm_feature=1
                break
            fi
        done
    fi

    # generate filcrypto.h
    # Check if FVM is in the build features - if so, include it in header generation
    local __header_features="c-headers"
    if [[ "${__has_fvm_feature}" -eq 1 ]]; then
        # FVM was explicitly included in --features
        __header_features="c-headers,fvm"
    elif [[ "${__has_no_default_features}" -eq 1 ]] || [[ -z "${FFI_DISABLE_FVM}" ]]; then
        # --no-default-features is set and FFI_DISABLE_FVM is not set to 1, add fvm
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
