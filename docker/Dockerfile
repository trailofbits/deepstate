FROM ubuntu:18.04

# Set up the non-root user
RUN apt-get update \
    &&  apt-get -y install sudo \
    && useradd -ms /bin/bash user && echo "user:user" | chpasswd && adduser user sudo

ADD /docker/sudoers.txt /etc/sudoers

ENV ECLIPSER_HOME /home/user/Eclipser

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
    bison gdb git \
    && wget -q https://packages.microsoft.com/config/ubuntu/18.04/packages-microsoft-prod.deb \
    && dpkg -i packages-microsoft-prod.deb \
    && apt-get install -y apt-transport-https \
    && apt-get update \
    && apt-get install -y dotnet-sdk-2.2

# Install DeepState/AFL/libFuzzer dependencies
RUN apt-get update \
    && apt-get install -y build-essential \
    && apt-get install -y clang \
    gcc-multilib g++-multilib cmake \
    python3-setuptools libffi-dev z3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

RUN chown -R user:user /home/user

USER user

# Install AFL
RUN wget http://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz \
    && tar -xzvf afl-latest.tgz \
    && rm -rf afl-latest.tgz \
    && cd afl-2.52b/ \
    && make \
    && sudo make install

# Install Eclipser
RUN git clone https://github.com/SoftSec-KAIST/Eclipser \
    && cd Eclipser \
    && make \
    && cd ../

# Install DeepState using a few different compilers for AFL/libFuzzer/Eclipser+normal
RUN cd deepstate \
    && rm -Rf CMakeFiles CMakeCache.txt \
    && rm -Rf build \
    && mkdir -p build \
    && cd build \
    && rm -rf CMakeFiles CMakeCache.txt \
    && CXX=clang++ CC=clang BUILD_LIBFUZZER=TRUE cmake ../ \
    && sudo make install \
    && rm -rf CMakeFiles CMakeCache.txt \
    && CXX=afl-clang++ CC=afl-clang BUILD_AFL=TRUE cmake ../ \
    && sudo make install \
    && rm -rf CMakeFiles CMakeCache.txt \
    && cmake ../ \
    && sudo make install \
    && cd .. \
    && sudo pip3 install 'z3-solver==4.5.1.0.post2' angr 'manticore==0.2.5' \
    && sudo python3 ./build/setup.py install

CMD ["/bin/bash"]
