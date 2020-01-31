#!/bin/sh
set -e

# Install Honggfuzz
git clone https://github.com/google/honggfuzz \
    && cd honggfuzz \
    && make \
    && sudo make install