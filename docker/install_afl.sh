#!/bin/sh
set -e

# Install AFL
wget http://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz \
    && tar -xzvf afl-latest.tgz \
    && rm -rf afl-latest.tgz \
    && cd afl-2.52b/ \
    && make \
    && make install DESTDIR="$1"