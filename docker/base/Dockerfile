FROM ubuntu:18.04

# Set up the non-root user
RUN apt-get update \
    && useradd -ms /bin/bash user && echo "user:user" | chpasswd

# COPY sudoers.txt /etc/sudoers.d/user
# RUN chmod 440 /etc/sudoers.d/user
# COPY /sudoers.txt /etc/sudoers
# removed because it breaks sudo

# Install general dependencies
RUN apt-get update && apt-get install -y build-essential \
    gcc-multilib g++-multilib cmake \
    python3-setuptools libffi-dev z3 python3-pip \
    git wget lsb-release software-properties-common \
    && rm -rf /var/lib/apt/lists/*

ENV LLVM_VER=9

# Install LLVM
RUN wget https://apt.llvm.org/llvm.sh \
    && chmod +x llvm.sh \
    && ./llvm.sh $LLVM_VER

RUN apt-get update && apt-get -y install libllvm-$LLVM_VER-ocaml-dev \
    libllvm$LLVM_VER llvm-$LLVM_VER llvm-$LLVM_VER-dev \
    llvm-$LLVM_VER-doc llvm-$LLVM_VER-examples llvm-$LLVM_VER-runtime \
    clang-$LLVM_VER clang-tools-$LLVM_VER clang-$LLVM_VER-doc \
    libclang-common-$LLVM_VER-dev libclang-$LLVM_VER-dev libclang1-$LLVM_VER \
    clang-format-$LLVM_VER python-clang-$LLVM_VER clangd-$LLVM_VER \
    libfuzzer-$LLVM_VER-dev libc++-$LLVM_VER-dev libc++abi-$LLVM_VER-dev \
    lld-$LLVM_VER lldb-$LLVM_VER

RUN ln -s $(which clang-$LLVM_VER) /usr/bin/clang 
RUN ln -s $(which clang++-$LLVM_VER) /usr/bin/clang++ 

# Switch to permissioned user last so no sudo calls are needed
WORKDIR /home/user
RUN chown -R user:user /home/user
USER user
