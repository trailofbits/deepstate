FROM deepstate-base

COPY . /home/user/deepstate
WORKDIR /home/user/deepstate
RUN sudo chown user:user -R /home/user

ARG DEPS_HOME
ARG AFL_HOME

# build basic instance of DeepState
RUN echo 'Building deepstate' \
    && mkdir -p ./build && cd ./build \
    && cmake ../ \
    && make \
    && sudo make install \
    && cd ../ && sudo rm -rf ./build 

RUN echo 'Building deepstate with AFL' \
    && mkdir -p build && cd build \
    && CXX="$AFL_HOME/afl-clang++" CC="$AFL_HOME/afl-clang" cmake -DDEEPSTATE_AFL=ON ../ \
    && make \
    && sudo mv ./libdeepstate_AFL.a /usr/local/lib/ \
    && cd ../ && sudo rm -rf build

# RUN cd deepstate \
#     && mkdir -p build && cd build \
#     && export USE_TRACK=1 \
#     && CXX=$ANGORA_HOME/bin/angora-clang++ CC=$ANGORA_HOME/bin/angora-clang cmake -DDEEPSTATE_ANGORA=ON ../ \
#     && sudo make -i install \
#     && make clean \
#     && rm -rf CMakeFiles CMakeCache.txt \
#     && unset USE_TRACK && export USE_FAST=1 \
#     && CXX=$ANGORA_HOME/bin/angora-clang++ CC=$ANGORA_HOME/bin/angora-clang cmake -DDEEPSTATE_ANGORA=ON ../ \
#     && sudo make install \
#     && cd ../ && rm -rf build

# Reset compilers to clang
ENV CXX=clang++ CC=clang

CMD ["/bin/bash"]
