#!/bin/sh
set -e

# Install dependencies
sudo apt-get install -y \
    --no-install-suggests --no-install-recommends \
    automake \
    bison \
    build-essential \
    flex \
    git \
    python3.7 \
    python3.7-dev \
    libtool \
    libtool-bin \
    libglib2.0-dev \
    python-setuptools \
    python2.7-dev \
    wget \
    ca-certificates \
    libpixman-1-dev \
    && sudo rm -rf /var/lib/apt/lists/*

# Install AFL
wget http://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz \
    && tar -xzvf afl-latest.tgz \
    && rm -rf afl-latest.tgz \
    && cd afl-2.52b \
    && make -j $1
