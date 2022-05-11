#FROM --platform=arm64 golang@sha256:96e888160bd68f54a1165b23c66318aea4ff6a4726cb854276d6d776c14b8978
FROM ubuntu:latest as builder
#FROM rust:slim-buster@sha256:5b0c5f6cd5aa84f6dd3f2188ac84aa0e0d602b514ccc14e9d1ebd5b865aa7849
#FROM golang:1.17.9-stretch

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y wget jq hwloc ocl-icd-opencl-dev git libhwloc-dev pkg-config make curl  && \
    apt-get install -y cargo golang-go
    
WORKDIR /filecoin-ffi/

#RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
RUN curl https://sh.rustup.rs -sSf | sh -s -- --default-toolchain nightly -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustup +nightly target add aarch64-unknown-linux-gnu
RUN cargo --help
RUN git clone https://github.com/filecoin-project/filecoin-ffi.git . && \
   RUSTFLAGS="-C target-cpu=native -g" FFI_BUILD_FROM_SOURCE=1 make