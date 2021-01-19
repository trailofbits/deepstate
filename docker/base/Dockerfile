FROM ubuntu:18.04

# Set up the non-root user
RUN apt-get update \
    && apt-get -y install sudo \
    && useradd -ms /bin/bash user && echo "user:user" | chpasswd && adduser user sudo
COPY /sudoers.txt /etc/sudoers

# Switch to permissioned user
WORKDIR /home/user
RUN chown -R user:user /home/user
USER user

# Install general dependencies
RUN sudo apt update && sudo apt-get install -y build-essential \
    gcc-multilib g++-multilib cmake \
    python3-setuptools libffi-dev z3 python3-pip \
    git wget lsb-release software-properties-common \
    && sudo rm -rf /var/lib/apt/lists/*

ENV LLVM_VER=9

# Install LLVM
RUN wget https://apt.llvm.org/llvm.sh \
    && chmod +x llvm.sh \
    && sudo ./llvm.sh $LLVM_VER

RUN sudo apt-get update && sudo apt-get -y install libllvm-$LLVM_VER-ocaml-dev \
    libllvm$LLVM_VER llvm-$LLVM_VER llvm-$LLVM_VER-dev \
    llvm-$LLVM_VER-doc llvm-$LLVM_VER-examples llvm-$LLVM_VER-runtime \
    clang-$LLVM_VER clang-tools-$LLVM_VER clang-$LLVM_VER-doc \
    libclang-common-$LLVM_VER-dev libclang-$LLVM_VER-dev libclang1-$LLVM_VER \
    clang-format-$LLVM_VER python-clang-$LLVM_VER clangd-$LLVM_VER \
    libfuzzer-$LLVM_VER-dev libc++-$LLVM_VER-dev libc++abi-$LLVM_VER-dev \
    lld-$LLVM_VER lldb-$LLVM_VER

RUN sudo ln -s $(which clang-$LLVM_VER) /usr/bin/clang 
RUN sudo ln -s $(which clang++-$LLVM_VER) /usr/bin/clang++ 
