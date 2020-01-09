#!/bin/sh
set -e

# add sources for Eclipser
echo 'deb-src http://archive.ubuntu.com/ubuntu/ bionic main restricted \n
deb-src http://archive.ubuntu.com/ubuntu/ bionic-updates main restricted \n
deb-src http://archive.ubuntu.com/ubuntu/ bionic universe \n
deb-src http://archive.ubuntu.com/ubuntu/ bionic-updates universe \n
deb-src http://archive.ubuntu.com/ubuntu/ bionic multiverse \n
deb-src http://archive.ubuntu.com/ubuntu/ bionic-updates multiverse \n
deb-src http://archive.ubuntu.com/ubuntu/ bionic-backports main restricted universe multiverse \n
deb-src http://archive.canonical.com/ubuntu bionic partner \n
deb-src http://security.ubuntu.com/ubuntu/ bionic-security main restricted \n
deb-src http://security.ubuntu.com/ubuntu/ bionic-security universe \n
deb-src http://security.ubuntu.com/ubuntu/ bionic-security multiverse' >> /etc/apt/sources.list

# update and install necessary dependencies
sudo apt-get update

# Install Eclipser dependencies
sudo apt-get -y build-dep qemu \
    && apt-get install -y libtool \
    libtool-bin wget automake autoconf \
    bison gdb git apt-transport-https \
    && wget -q https://packages.microsoft.com/config/ubuntu/18.04/packages-microsoft-prod.deb \
    && dpkg -i packages-microsoft-prod.deb \
    && apt-get update \
    && apt-get install -y dotnet-sdk-2.2

# Install Angora dependencies
sudo apt-get install -y rustc \
    cargo libstdc++-7-dev

# Install Honggfuzz dependencies
sudo apt-get install -y binutils-dev \
    libunwind-dev

# Install DeepState/AFL/libFuzzer dependencies
sudo apt-get install -y build-essential \
    && apt-get install -y clang \
    gcc-multilib g++-multilib cmake \
    python3-setuptools libffi-dev z3 python3-pip \
    && rm -rf /var/lib/apt/lists/*
