# -- AFL
FROM deepstate-base AS AFL
COPY ./docker/install_afl.sh ./
ARG make_j
RUN bash install_afl.sh $make_j

# -- Honggfuzz
FROM deepstate-base AS Honggfuzz
COPY ./docker/install_honggfuzz.sh ./
ARG make_j
RUN bash install_honggfuzz.sh $make_j

# -- Eclipser
FROM deepstate-base AS Eclipser
COPY ./docker/install_eclipser.sh ./
ARG make_j
RUN bash install_eclipser.sh $make_j

# -- Angora
FROM deepstate-base AS Angora
COPY ./docker/install_angora.sh ./
ARG make_j
RUN bash install_angora.sh $make_j

# -- DeepState
FROM deepstate-base
COPY . ./deepstate
RUN sudo chown user:user -R ./deepstate
WORKDIR ./deepstate

ENV DEPS_DIR /home/user/deps
ARG make_j

# general
RUN echo 'Building deepstate' \
    && mkdir -p ./build && cd ./build \
    && CXX=clang++ CC=clang cmake ../ \
    && make -j $make_j \
    && sudo make install \
    && cd ../ && sudo rm -rf ./build

# libFuzzer
RUN echo 'Building deepstate with libFuzzer' \
    && mkdir -p build && cd build \
    && CXX=clang++ CC=clang cmake -DDEEPSTATE_LIBFUZZER=ON ../ \
    && make -j $make_j \
    && sudo mv ./libdeepstate_LF.a /usr/local/lib/ \
    && cd ../ && sudo rm -rf build

# AFL
COPY --from=AFL /home/user/afl-2.52b $DEPS_DIR/afl
RUN echo 'Building deepstate with AFL' \
    && mkdir -p build && cd build \
    && export AFL_HOME="$DEPS/afl" \
    && cmake -DDEEPSTATE_AFL=ON ../ \
    && make -j $make_j \
    && sudo mv ./libdeepstate_AFL.a /usr/local/lib/ \
    && cd ../ && sudo rm -rf build

# Honggfuzz
COPY --from=Honggfuzz /home/user/honggfuzz $DEPS_DIR/honggfuzz
RUN echo 'Building deepstate with Honggfuzz' \
    && mkdir -p build && cd build \
    && export HONGGFUZZ_HOME="$DEPS_DIR/honggfuzz" \
    && cmake -DDEEPSTATE_HONGGFUZZ=ON ../ \
    && make -j $make_j \
    && sudo mv ./libdeepstate_HFUZZ.a /usr/local/lib/ \
    && cd ../ && sudo rm -rf build

# Eclipser
COPY --from=Eclipser /home/user/Eclipser $DEPS_DIR/eclipser

# Angora
COPY --from=Angora /home/user/Angora $DEPS_DIR/angora
COPY --from=Angora /home/user/clang+llvm $DEPS_DIR/angora/clang+llvm
RUN echo 'Building deepstate with Angora - taint' \
    && mkdir -p build && cd build \
    && export PATH="$DEPS_DIR/angora/clang+llvm/bin:$PATH" \
    && export LD_LIBRARY_PATH="$DEPS_DIR/angora/clang+llvm/lib:$LD_LIBRARY_PATH" \
    && export USE_TRACK=1 \
    && export ANGORA_HOME="$DEPS_DIR/angora" \
    && cmake -DDEEPSTATE_ANGORA=ON ../ \
    && make -j $make_j -i \  # ignore errors, because Angora doesn't support 32bit builds
    && sudo mv ./libdeepstate_taint.a /usr/local/lib/ \
    && cd ../ && sudo rm -rf build

RUN echo 'Building deepstate with Angora - fast' \
    && mkdir -p build && cd build \
    && export PATH="$DEPS_DIR/angora/clang+llvm/bin:$PATH" \
    && export LD_LIBRARY_PATH="$DEPS_DIR/angora/clang+llvm/lib:$LD_LIBRARY_PATH" \
    && export USE_FAST=1 \
    && export ANGORA_HOME="$DEPS_DIR/angora" \
    && cmake -DDEEPSTATE_ANGORA=ON ../ \
    && make -j $make_j -i \
    && sudo mv ./libdeepstate_fast.a /usr/local/lib/ \
    && cd ../ && sudo rm -rf build

ENV CXX=clang++ CC=clang

CMD ["/bin/bash"]