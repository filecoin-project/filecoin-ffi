#!/usr/bin/env bash

set -Exeuo pipefail

if [[ -z "$1" ]]
then
    (>&2 echo 'Error: script requires path to which it will write release (gzipped) tarball, e.g. "/tmp/filecoin-ffi-Darwin-standard.tar.tz"')
    exit 1
fi
tarball_output_path=$1

(>&2 echo "preparing release files")

# create temporary directory to hold build artifacts
#
tmp_dir=$(mktemp -d)

# clean up temp directory on exit
#
trap '{ rm -f $tmp_dir; }' EXIT

# copy assets into temporary directory
#
find -L . -type f -name filecoin.h -exec cp -- "{}" $tmp_dir/ \;
find -L . -type f -name libfilecoin.a -exec cp -- "{}" $tmp_dir/ \;
find -L . -type f -name filecoin.pc -exec cp -- "{}" $tmp_dir/ \;

# create gzipped tarball from contents of temporary directory
#
tar -czf $tarball_output_path $tmp_dir/*

(>&2 echo "release file created: $tarball_output_path")
