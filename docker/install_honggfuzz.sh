#!/bin/sh
set -e

# Install dependencies
sudo apt-get -y update && sudo apt-get install -y \
    gcc \
    git \
    make \
    pkg-config \
  	libunwind8-dev \
  	binutils-dev \
    && sudo rm -rf /var/lib/apt/lists/*

# Install Honggfuzz
git clone https://github.com/google/honggfuzz \
    && cd honggfuzz \
    && git checkout tags/2.1 -b 2.1 \
    && make -j $1
