#!/usr/bin/env bash

set -Exeuo pipefail

main() {
    if [[ -z "$1" ]]
    then
        (>&2 echo '[package-release/main] Error: script requires an api version, e.g. "v1"')
        exit 1
    fi
    if [[ -z "$2" ]]
    then
        (>&2 echo '[package-release/main] Error: script requires path to which it will write release (gzipped) tarball, e.g. "/tmp/filecoin-ffi-Darwin-standard.tar.tz"')
        exit 1
    fi

    local version=$1
    local __tarball_output_path=$2

    # create temporary directory to hold build artifacts (must not be declared
    # with 'local' because we will use 'trap' to clean it up)
    #
    __tmp_dir=$(mktemp -d)

    (>&2 echo "[package-release/main] preparing release files")

    # clean up temp directory on exit
    #
    trap '{ rm -rf $__tmp_dir; }' EXIT

    # copy assets into temporary directory
    #
    find -L . -type f -name filcrypto-${version}.h -exec cp -- "{}" $__tmp_dir/ \;
    find -L . -type f -name libfilcrypto_${version}.a -exec cp -- "{}" $__tmp_dir/ \;
    find -L . -type f -name filcrypto-${version}.pc -exec cp -- "{}" $__tmp_dir/ \;

    # create gzipped tarball from contents of temporary directory
    #
    tar -czf $__tarball_output_path $__tmp_dir/*

    (>&2 echo "[package-release/main] release file created: $__tarball_output_path")
}

main "$@"; exit
