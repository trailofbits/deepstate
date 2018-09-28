# Copyright (c) 2018 Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

CXX=clang++
CXX_FLAGS=-std=c++11 -O0 -mno-avx -fno-exceptions -fno-rtti
FUZZ_FLAGS=-fsanitize=fuzzer,undefined -DLIBFUZZER
TARGETS = Wallet Wallet_tests Wallet_fuzz_tests

Wallet: Wallet.cpp
	$(CXX) $(CXX_FLAGS) $^ -o $@

Wallet_tests: Wallet_tests.cpp
	$(CXX) $(CXX_FLAGS) $^ -ldeepstate -o $@

Wallet_fuzz_tests: Wallet_tests.cpp
	$(CXX) $(CXX_FLAGS) $(FUZZ_FLAGS) $^ -ldeepstate -o $@

exercise_1: Wallet Wallet_tests Wallet_fuzz_tests

clean:
	@rm $(TARGETS)

all: exercise_1

.PHONY: all
