FROM rust:1.88-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        pkg-config \
        libssl-dev \
        libseccomp-dev \
        libdbus-1-dev \
        ca-certificates \
        bash \
        coreutils \
        procps \
        strace \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
ENV CARGO_TERM_COLOR=always
