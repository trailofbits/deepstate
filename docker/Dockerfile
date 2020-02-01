# -- AFL
FROM deepstate-base AS AFL
COPY ./docker/install_afl.sh ./
RUN bash install_afl.sh

# -- Honggfuzz
FROM deepstate-base AS Honggfuzz
COPY ./docker/install_honggfuzz.sh ./
RUN bash install_honggfuzz.sh

# -- Eclipser
FROM deepstate-base AS Eclipser
COPY ./docker/install_eclipser.sh ./
RUN bash install_eclipser.sh

# -- Angora
FROM deepstate-base AS Angora
COPY ./docker/install_angora.sh ./
RUN bash install_angora.sh

# -- deepstate
FROM deepstate-base
COPY . ./deepstate
RUN sudo chown user:user -R ./deepstate
WORKDIR ./deepstate

ENV DEPS_DIR /home/user/deps

# general
RUN echo 'Building deepstate' \
    && mkdir -p ./build && cd ./build \
    && CXX=clang++ CC=clang cmake ../ \
    && make \
    && sudo make install \
    && cd ../ && sudo rm -rf ./build

# libFuzzer
RUN echo 'Building deepstate with libFuzzer' \
    && mkdir -p build && cd build \
    && CXX=clang++ CC=clang cmake -DDEEPSTATE_LIBFUZZER=ON ../ \
    && make \
    && sudo mv ./libdeepstate_LF.a /usr/local/lib/ \
    && cd ../ && sudo rm -rf build

# AFL
COPY --from=AFL /home/user/afl-2.52b $DEPS_DIR/afl
RUN echo 'Building deepstate with AFL' \
    && mkdir -p build && cd build \
    && CXX="$DEPS_DIR/afl/afl-clang++" CC="$DEPS_DIR/afl/afl-clang" cmake -DDEEPSTATE_AFL=ON ../ \
    && make \
    && sudo mv ./libdeepstate_AFL.a /usr/local/lib/ \
    && cd ../ && sudo rm -rf build

# Honggfuzz
COPY --from=Honggfuzz /home/user/honggfuzz $DEPS_DIR/honggfuzz
RUN echo 'Building deepstate with Honggfuzz' \
    && mkdir -p build && cd build \
    && CXX="$DEPS_DIR/honggfuzz/hfuzz_cc/hfuzz-clang++" CC="$DEPS_DIR/honggfuzz/hfuzz_cc/hfuzz-clang" cmake -DDEEPSTATE_HONGGFUZZ=ON ../ \
    && make \
    && sudo mv ./libdeepstate_HFUZZ.a /usr/local/lib/ \
    && cd ../ && sudo rm -rf build

# Eclipser
COPY --from=Eclipser /home/user/Eclipser $DEPS_DIR/eclipser

# Angora
COPY --from=Angora /home/user/Angora $DEPS_DIR/angora
#ENV PATH_OLD="${PATH}" LD_LIBRARY_PATH_OLD="${LD_LIBRARY_PATH}"
#ENV PATH="$DEPS_DIR/angora/clang+llvm/bin:${PATH}"
#ENV LD_LIBRARY_PATH="$DEPS_DIR/angora/clang+llvm/lib:${LD_LIBRARY_PATH}"
RUN echo 'Building deepstate with Angora - taint' \
    && mkdir -p build && cd build \
    && export USE_TRACK=1 \
    && CXX="$DEPS_DIR/angora/bin/angora-clang++" CC="$DEPS_DIR/angora/bin/angora-clang" cmake -DDEEPSTATE_ANGORA=ON ../ \
    && make -i \
    && sudo mv ./libdeepstate_taint.a /usr/local/lib/ \
    && cd ../ && sudo rm -rf build

RUN echo 'Building deepstate with Angora - fast' \
    && mkdir -p build && cd build \
    && export USE_FAST=1 \
    && CXX="$DEPS_DIR/angora/bin/angora-clang++" CC="$DEPS_DIR/angora/bin/angora-clang" cmake -DDEEPSTATE_ANGORA=ON ../ \
    && make -i \
    && sudo mv ./libdeepstate_fast.a /usr/local/lib/ \
    && cd ../ && sudo rm -rf build

#ENV PATH="${PATH_OLD}" LD_LIBRARY_PATH="${LD_LIBRARY_PATH_OLD}"
ENV CXX=clang++ CC=clang

CMD ["/bin/bash"]