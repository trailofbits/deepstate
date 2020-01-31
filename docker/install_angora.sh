#!/bin/sh
set -e

# Install Angora
git clone https://github.com/AngoraFuzzer/Angora \
    && cd Angora \
    && PREFIX="$1" ./build/build.sh