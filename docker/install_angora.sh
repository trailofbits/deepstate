#!/bin/sh
set -e

# Enable deb-sec
sudo sed -i -- 's/#deb-src/deb-src/g' /etc/apt/sources.list
sudo sed -i -- 's/# deb-src/deb-src/g' /etc/apt/sources.list

# Install dependencies
sudo apt-get update
sudo apt-get install -y rustc \
    cargo libstdc++-7-dev zlib1g-dev \
    && sudo rm -rf /var/lib/apt/lists/*

# set proper LLVM version
export LLVM_VER=7.0.0
export PATH="$(pwd)/clang+llvm/bin:$PATH"
export LD_LIBRARY_PATH="$(pwd)/clang+llvm/lib:$LD_LIBRARY_PATH"

# Install Angora
git clone https://github.com/AngoraFuzzer/Angora \
    && cd Angora \
    && ./build/build.sh
