#!/bin/bash

timestamp=$(date +%s)
name=arm_build_only_$timestamp
docker build -t $name .

id=$(docker create $name)
docker cp $id:/filecoin-ffi/ - > $name.tar.gz
docker cp $id:/filecoin-ffi/ - > $name.tar.gz

## extract 
tar -xvf $name.tar.gz
