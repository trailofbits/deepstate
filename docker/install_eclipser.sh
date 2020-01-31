#!/bin/sh
set -e

# Install Eclipser
git clone https://github.com/SoftSec-KAIST/Eclipser \
    && cd Eclipser \
    && make