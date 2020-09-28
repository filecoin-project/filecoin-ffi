#!/usr/bin/env bash

set -Exeo pipefail

main() {
    if [[ -z "$1" ]]
    then
        (>&2 echo '[build-release/main] Error: script requires an api version, e.g. "v1"')
        exit 1
    fi
    if [[ -z "$2" ]]
    then
        (>&2 echo '[build-release/main] Error: script requires a library name, e.g. "filecoin" or "snark"')
        exit 1
    fi

    if [[ -z "$3" ]]
    then
        (>&2 echo '[build-release/main] Error: script requires a toolchain, e.g. ./build-release.sh +nightly-2019-04-19')
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

    RUSTFLAGS="${__rust_flags}" \
        cargo +$3 build \
        --release ${@:4} 2>&1 | tee ${__build_output_log_tmp}

    # parse build output for linker flags
    #
    local __linker_flags=$(cat ${__build_output_log_tmp} \
        | grep native-static-libs\: \
        | head -n 1 \
        | cut -d ':' -f 3)

    # generate pkg-config
    #
    sed -e "s;@VERSION@;$(git rev-parse HEAD);" \
        -e "s;@PRIVATE_LIBS@;${__linker_flags};" "../$2.pc.template" > "../$2.pc"

    # ensure header file was built
    #
    find -L ../../ -type f -name "$2.h" | read

    # ensure the archive file was built
    #
    library_name="lib$(echo $2 | sed 's/-/_/g').a"
    find -L ../../ -type f -name "${library_name}" | read
}

main "$@"
