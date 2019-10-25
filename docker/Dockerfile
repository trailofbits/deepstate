FROM ubuntu:18.04

# Set up the non-root user
RUN apt-get update \
    &&  apt-get -y install sudo \
    && useradd -ms /bin/bash user && echo "user:user" | chpasswd && adduser user sudo

ADD /docker/sudoers.txt /etc/sudoers

ENV ECLIPSER_HOME /home/user/Eclipser/build

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
#RUN apt-get install -y rustc \
#    cargo libstdc++-7-dev

# Install DeepState/AFL/libFuzzer dependencies
RUN apt-get install -y build-essential \
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

ENV PATH "${ECLIPSER_HOME}:${PATH}"

# Install Angora
#RUN git clone https://github.com/AngoraFuzzer/Angora \
#    && cd Angora \
#    && ./build/build.sh \
#    && cd ../

#ENV ANGORA=/home/user/Angora

# Install DeepState using a few different compilers for AFL/libFuzzer/Eclipser/Angora+normal
RUN cd deepstate \
    && rm -Rf CMakeFiles CMakeCache.txt \
    && rm -Rf build \
    && mkdir -p build \
    && cd build \
    && rm -rf CMakeFiles CMakeCache.txt \
    && CXX=afl-clang++ CC=afl-clang cmake -DDEEPSTATE_AFL=ON ../ \
    && sudo make install \
    && rm -rf CMakeFiles CMakeCache.txt \
    && CXX=clang++ CC=clang cmake -DDEEPSTATE_LIBFUZZER=ON ../ \
    && sudo make install \
#    && rm -rf CMakeFiles CMakeCache.txt \
#    && USE_TRACK=1 CXX=$ANGORA/bin/angora-clang++ CC=$ANGORA/bin/angora-clang cmake -DDEEPSTATE_ANGORA=ON ../ \
#    && export USE_TRACK=1 && sudo -E sh -c 'make -i install' \
#    && make clean \
#    && rm -rf CMakeFiles CMakeCache.txt \
#    && CXX=$ANGORA/bin/angora-clang++ CC=$ANGORA/bin/angora-clang cmake -DDEEPSTATE_ANGORA=ON ../ \
#    && export USE_FAST=1 && sudo -E sh -c 'make install' \
    && cd .. \
    && sudo pip3 install 'z3-solver==4.5.1.0.post2' angr git+git://github.com/trailofbits/manticore.git \
    && sudo python3 ./build/setup.py install

ENV CC=clang
ENV CXX=clang++

CMD ["/bin/bash"]
