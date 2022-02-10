FROM ubuntu:16.04

SHELL ["/bin/bash", "-lc"]

RUN apt-get update &&       \
    apt-get install -y      \
        curl                \
        gcc                 \
        g++                 \
        git                 \
        libgl1-mesa-dev     \
    &&                      \
    rm -rf /var/cache/apt/*

RUN curl -sLo /tmp/miniconda.sh https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh &&    \
    chmod +x /tmp/miniconda.sh &&                                                                           \
    /tmp/miniconda.sh -b -p /opt/conda &&                                                                   \
    rm /tmp/miniconda.sh &&                                                                                 \
    ln -s /opt/conda/etc/profile.d/conda.sh /etc/profile.d/conda.sh &&                                      \
    echo '. /opt/conda/etc/profile.d/conda.sh' >> /etc/bash.bashrc

RUN git config --system http.sslCAInfo /etc/ssl/certs/ca-certificates.crt &&        \
    echo 'ssl_verify: /etc/ssl/certs/ca-certificates.crt' > /opt/conda/.condarc &&  \
    echo 'always_yes: true' >> /opt/conda/.condarc &&                               \
    conda update conda

# Set up the non-root user
RUN apt-get update \
    && apt-get -y install sudo \
    && useradd -ms /bin/bash user && echo "user:user" | chpasswd && adduser user sudo
COPY /sudoers.txt /etc/sudoers

# Make RUN commands use `bash --login`:
SHELL ["/bin/bash", "--login", "-c"]

RUN conda create -c conda-forge -n deepstate_env python=3.7 pip setuptools

# Initialize conda in bash config fiiles:
RUN conda init bash

# Switch to permissioned user
WORKDIR /home/user
RUN chown -R user:user /home/user
USER user

# Make RUN commands use `bash --login`:
SHELL ["/bin/bash", "--login", "-c"]

# Initialize conda in bash config fiiles:
RUN conda init bash

RUN conda activate deepstate_env

# Install general dependencies
RUN sudo apt update \
    && sudo apt-get remove python3-apt \
    && sudo apt-get install -y build-essential python3-apt \
    gcc-multilib g++-multilib cargo libffi-dev z3 \
    git wget lsb-release software-properties-common \
    apt-transport-https ca-certificates cmake \
    && sudo rm -rf /var/lib/apt/lists/*
#
# RUN sudo ln -s /usr/lib/python3/dist-packages/apt_pkg.cpython-36m-x86_64-linux-gnu.so /usr/lib/python3/dist-packages/apt_pkg.so
#
ENV LLVM_VER=11

# Install LLVM
RUN wget https://apt.llvm.org/llvm.sh \
    && chmod +x llvm.sh \
    && sudo ./llvm.sh $LLVM_VER

RUN sudo apt-get update && sudo apt-get -y install libllvm-$LLVM_VER-ocaml-dev \
    libllvm$LLVM_VER llvm-$LLVM_VER llvm-$LLVM_VER-dev libz-dev \
    llvm-$LLVM_VER-doc llvm-$LLVM_VER-examples llvm-$LLVM_VER-runtime \
    clang-$LLVM_VER clang-tools-$LLVM_VER clang-$LLVM_VER-doc \
    libclang-common-$LLVM_VER-dev libclang-$LLVM_VER-dev libclang1-$LLVM_VER \
    clang-format-$LLVM_VER python3-clang-$LLVM_VER clangd-$LLVM_VER \
    libfuzzer-$LLVM_VER-dev libc++-$LLVM_VER-dev libc++abi-$LLVM_VER-dev \
    lld-$LLVM_VER lldb-$LLVM_VER

RUN sudo ln -s $(which clang-$LLVM_VER) /usr/bin/clang
RUN sudo ln -s $(which clang++-$LLVM_VER) /usr/bin/clang++
