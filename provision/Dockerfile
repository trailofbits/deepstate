FROM ubuntu:18.04

# Set up the non-root user
RUN apt-get update \
    && apt-get -y install sudo \
    && useradd -ms /bin/bash user && echo "user:user" | chpasswd && adduser user sudo
ADD /provision/sudoers.txt /etc/sudoers

# Define envvars for fuzzer paths
ENV ECLIPSER_HOME /home/user/Eclipser
ENV ANGORA=/home/user/Angora

WORKDIR /home/user
COPY . /home/user/deepstate

# Eclipser requires deb-src entries
RUN echo 'deb-src http://archive.ubuntu.com/ubuntu/ bionic main restricted \n\
deb-src http://archive.ubuntu.com/ubuntu/ bionic-updates main restricted \n\
deb-src http://archive.ubuntu.com/ubuntu/ bionic universe \n\
deb-src http://archive.ubuntu.com/ubuntu/ bionic-updates universe \n\
deb-src http://archive.ubuntu.com/ubuntu/ bionic multiverse \n\
deb-src http://archive.ubuntu.com/ubuntu/ bionic-updates multiverse \n\
deb-src http://archive.ubuntu.com/ubuntu/ bionic-backports main restricted universe multiverse \n\
deb-src http://archive.canonical.com/ubuntu bionic partner \n\
deb-src http://security.ubuntu.com/ubuntu/ bionic-security main restricted \n\
deb-src http://security.ubuntu.com/ubuntu/ bionic-security universe \n\
deb-src http://security.ubuntu.com/ubuntu/ bionic-security multiverse' >> /etc/apt/sources.list

# Install Eclipser dependencies
RUN apt-get update \
    && apt-get -y build-dep qemu \
    && apt-get install -y libtool \
    libtool-bin wget automake autoconf \
    bison gdb git apt-transport-https \
    && wget -q https://packages.microsoft.com/config/ubuntu/18.04/packages-microsoft-prod.deb \
    && dpkg -i packages-microsoft-prod.deb \
    && apt-get update \
    && apt-get install -y dotnet-sdk-2.2

# Install Angora dependencies
RUN apt-get install -y rustc \
    cargo libstdc++-7-dev

# Install Honggfuzz dependencies
RUN apt-get install -y binutils-dev \
    libunwind-dev

# Install DeepState/AFL/libFuzzer dependencies
RUN apt-get install -y build-essential \
    && apt-get install -y clang \
    gcc-multilib g++-multilib cmake \
    python3-setuptools libffi-dev z3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Switch to permissioned user
RUN chown -R user:user /home/user
USER user

# Install fuzzers needed by DeepState, and build instances of DeepState with those fuzzers
CMD ["./install"]

# Reset compilers to clang
ENV CC=clang
ENV CXX=clang++

CMD ["/bin/bash"]
