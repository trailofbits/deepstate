#!/bin/sh
set -e

# Enable deb-sec
sudo sed -i -- 's/#deb-src/deb-src/g' /etc/apt/sources.list
sudo sed -i -- 's/# deb-src/deb-src/g' /etc/apt/sources.list

# Install dependencies
sudo apt-get update
sudo apt-get -y build-dep qemu
sudo apt-get install -y libtool \
    libtool-bin wget automake autoconf \
    bison gdb git apt-transport-https

wget -q https://packages.microsoft.com/config/ubuntu/18.04/packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
sudo apt-get update
sudo apt-get install -y dotnet-sdk-2.2
sudo rm -rf /var/lib/apt/lists/*

# Install Eclipser
git clone https://github.com/SoftSec-KAIST/Eclipser \
    && cd Eclipser \
    && git checkout tags/v1.1 \
    && make -j $1
