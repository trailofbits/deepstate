FROM ubuntu:18.04

# Set up the non-root user
RUN apt-get update \
    && apt-get -y install sudo \
    && useradd -ms /bin/bash user && echo "user:user" | chpasswd && adduser user sudo
ADD /docker/sudoers.txt /etc/sudoers

# Define envvars for fuzzer paths
ENV ECLIPSER_HOME /home/user/Eclipser
ENV ANGORA=/home/user/Angora

WORKDIR /home/user
COPY . /home/user/deepstate

# Switch to permissioned user
RUN chown -R user:user /home/user
USER user

# Install dependencies
RUN sudo ./deepstate/docker/deps

# Install fuzzers needed by DeepState, and build instances of DeepState with those fuzzers
RUN sudo ./deepstate/docker/install

# Reset compilers to clang
ENV CC=clang
ENV CXX=clang++

CMD ["/bin/bash"]
