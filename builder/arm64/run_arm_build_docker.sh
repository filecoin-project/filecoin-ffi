#!/bin/bash

timestamp=$(date +%s)
name=arm_build_only_$timestamp
docker build -t $name .

# get the container id
id=$(docker create $name)
docker cp $id:/filecoin-ffi/ - > $name.tar.gz

## extract 
tar -xvf $name.tar.gz

## Copy to wherever..