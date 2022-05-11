# filecoin-ffi build workaround

As of this writing, .circleci doens't support arm based images and as a workaround we need to try and build the filecoin-ffi in a containerized environment.This means that we need to create a docker image using an ARM64 based operating system and build the binaries there.

## Pre-requisites
- docker
- bash
- tar

There are 2 files in this repo:
- Dockerfile this is the main docker file that will run the steps to build the latest master branch of filecoin-ffi on ubuntu
- run_arm_build_docker.sh - this script runs the docker build and extract the content from the image to the host.

## Running
```
./run_arm_build_docker.sh
```


## Trial and error
We can use some of these images as builders. They are all arm64 based.
```
FROM --platform=arm64 golang@sha256:96e888160bd68f54a1165b23c66318aea4ff6a4726cb854276d6d776c14b8978 as builder
FROM ubuntu:latest as builder
FROM rust:slim-buster@sha256:5b0c5f6cd5aa84f6dd3f2188ac84aa0e0d602b514ccc14e9d1ebd5b865aa7849 as builder
FROM golang:1.17.9-stretch as builder
```