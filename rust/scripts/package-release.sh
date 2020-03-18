#!/usr/bin/env bash

set -x

if [[ -z "$1" ]]
then
    (>&2 echo 'Error: script requires path to which it will write release (gzipped) tarball, e.g. "/tmp/filecoin-ffi-Darwin-standard.tar.tz"')
    exit 1
fi
TARBALL_OUTPUT_PATH=$1

echo "preparing release file"

# create temporary directory to hold build artifacts
#
TMP_DIR=$(mktemp -d)

# clean up temp directory on exit
#
trap '{ rm -f $TMP_DIR; }' EXIT

# copy assets into temporary directory
#
find -L . -type f -name filecoin.h -exec cp -- "{}" $TMP_DIR/ \;
find -L . -type f -name libfilecoin.a -exec cp -- "{}" $TMP_DIR/ \;
find -L . -type f -name filecoin.pc -exec cp -- "{}" $TMP_DIR/ \;

# create gzipped tarball from contents of temporary directory
#
tar -czf $TARBALL_OUTPUT_PATH $TMP_DIR/*

echo "release file created: $TARBALL_OUTPUT_PATH"
