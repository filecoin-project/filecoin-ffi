#!/usr/bin/env bash

if [ -z "$1" ]; then
  TAR_FILE=`mktemp`.tar.gz
else
  TAR_FILE=$1
fi

TAR_PATH=`mktemp -d`

mkdir -p $TAR_PATH
mkdir -p $TAR_PATH/include
mkdir -p $TAR_PATH/lib/pkgconfig

find . -L -type f -name filecoin.h -exec cp -- "{}" $TAR_PATH/include/ \;
find . -L -type f -name libfilecoin.a -exec cp -- "{}" $TAR_PATH/lib/ \;
find . -L -type f -name filecoin.pc -exec cp -- "{}" $TAR_PATH/lib/pkgconfig/ \;

pushd $TAR_PATH

tar -czf $TAR_FILE ./*

popd

rm -rf $TAR_PATH

echo $TAR_FILE
