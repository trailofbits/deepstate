#!/bin/sh
set -e

# Install dependencies
sudo apt-get update && sudo apt-get install -y binutils-dev \
    libunwind-dev \
    && sudo rm -rf /var/lib/apt/lists/*

# Install Honggfuzz
git clone https://github.com/google/honggfuzz \
    && cd honggfuzz \
    && make -j $1
