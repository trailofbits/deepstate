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
    && mkdir -p ./build_deepstate && cd ./build_deepstate \
    && CXX=clang++ CC=clang cmake ../ \
    && make -j $make_j \
    && sudo make install

# libFuzzer
RUN echo 'Building deepstate with libFuzzer' \
    && mkdir -p build_libfuzzer && cd build_libfuzzer \
    && CXX=clang++ CC=clang cmake -DDEEPSTATE_LIBFUZZER=ON ../ \
    && make -j $make_j \
    && sudo cp ./libdeepstate_LF.a /usr/local/lib/

# AFL
COPY --from=AFL /home/user/afl-2.52b $DEPS_DIR/afl
RUN echo 'Building deepstate with AFL' \
    && mkdir -p build_afl && cd build_afl \
    && export AFL_HOME="$DEPS_DIR/afl" \
    && CXX="$AFL_HOME/afl-clang++" CC="$AFL_HOME/afl-clang" cmake -DDEEPSTATE_AFL=ON ../ \
    && make -j $make_j \
    && sudo cp ./libdeepstate_AFL.a /usr/local/lib/

# Honggfuzz
COPY --from=Honggfuzz /home/user/honggfuzz $DEPS_DIR/honggfuzz
RUN echo 'Building deepstate with Honggfuzz' \
    && mkdir -p build_honggfuzz && cd build_honggfuzz \
    && export HONGGFUZZ_HOME="$DEPS_DIR/honggfuzz" \
    && CXX="$HONGGFUZZ_HOME/hfuzz_cc/hfuzz-clang++" CC="$HONGGFUZZ_HOME/hfuzz_cc/hfuzz-clang" cmake -DDEEPSTATE_HONGGFUZZ=ON ../ \
    && make -j $make_j \
    && sudo cp ./libdeepstate_HFUZZ.a /usr/local/lib/

# Eclipser
COPY --from=Eclipser /home/user/Eclipser $DEPS_DIR/eclipser
RUN echo 'Eclipser - installing dotnet' \
    && wget -q https://packages.microsoft.com/config/ubuntu/18.04/packages-microsoft-prod.deb \
    && sudo dpkg -i packages-microsoft-prod.deb \
    && sudo apt-get update \
    && sudo apt-get install -y dotnet-sdk-2.2
COPY --from=Eclipser /home/user/.nuget /home/user/.nuget

# Angora
COPY --from=Angora /home/user/Angora $DEPS_DIR/angora
COPY --from=Angora /home/user/clang+llvm $DEPS_DIR/angora/clang+llvm
RUN echo 'Building deepstate with Angora - taint' \
    && mkdir -p build_angora_taint && cd build_angora_taint \
    && export PATH="$DEPS_DIR/angora/clang+llvm/bin:$PATH" \
    && export LD_LIBRARY_PATH="$DEPS_DIR/angora/clang+llvm/lib:$LD_LIBRARY_PATH" \
    && export USE_TRACK=1 \
    && export ANGORA_HOME="$DEPS_DIR/angora" \
    && CXX="$ANGORA_HOME/bin/angora-clang++" CC="$ANGORA_HOME/bin/angora-clang" cmake -DDEEPSTATE_ANGORA=ON ../ \
    && make -j $make_j -i  # ignore errors, because Angora doesn't support 32bit builds \
    && sudo cp ./libdeepstate_taint.a /usr/local/lib/

RUN echo 'Building deepstate with Angora - fast' \
    && mkdir -p build_angora_fast && cd build_angora_fast \
    && export PATH="$DEPS_DIR/angora/clang+llvm/bin:$PATH" \
    && export LD_LIBRARY_PATH="$DEPS_DIR/angora/clang+llvm/lib:$LD_LIBRARY_PATH" \
    && export USE_FAST=1 \
    && export ANGORA_HOME="$DEPS_DIR/angora" \
    && CXX="$ANGORA_HOME/bin/angora-clang++" CC="$ANGORA_HOME/bin/angora-clang" cmake -DDEEPSTATE_ANGORA=ON ../ \
    && make -j $make_j -i \
    && sudo cp ./libdeepstate_fast.a /usr/local/lib/

# Angr, Manticore
RUN echo 'Installing angr and manticore' \
    && pip3 install z3-solver angr git+git://github.com/trailofbits/manticore.git --user

ENV CXX=clang++ CC=clang

CMD ["/bin/bash"]