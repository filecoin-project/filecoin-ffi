#!/bin/bash

timestamp=$(date +%s)
name=arm_build_only_$timestamp
docker build -t $name .

id=$(docker create $name)
docker cp $id:path/filecoin-ffi/ - > $name_filecoin_ffi.tar.gz
