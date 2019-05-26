FROM python:3.7-slim

WORKDIR /deepstate

COPY . /deepstate

RUN apt-get update \
    && apt-get install -y build-essential \
    gcc-multilib g++-multilib cmake \
    python3-setuptools libffi-dev z3 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir build \
    && cd build \
    && cmake ../ \
    && make \
    && cd .. \
    && pip install claripy angr manticore \
    && python ./build/setup.py install

CMD ["/bin/bash"]
