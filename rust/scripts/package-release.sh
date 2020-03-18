#!/usr/bin/env bash

set -x

if [ -z "$1" ]; then
  TARBALL_OUTPUT_PATH=`mktemp`.tar.gz
else
  TARBALL_OUTPUT_PATH=$1
fi

echo "preparing release file"

TMP_DIR=`mktemp -d`

mkdir -p $TMP_DIR

find -L . -type f -name filecoin.h -exec cp -- "{}" $TMP_DIR/ \;
find -L . -type f -name libfilecoin.a -exec cp -- "{}" $TMP_DIR/ \;
find -L . -type f -name filecoin.pc -exec cp -- "{}" $TMP_DIR/ \;

pushd $TMP_DIR

tar -czf $TARBALL_OUTPUT_PATH ./*

echo "release file created: $TARBALL_OUTPUT_PATH"

popd

rm -rf $TMP_DIR
