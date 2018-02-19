/*
 * Copyright (c) 2018 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include <deepstate/DeepState.hpp>

using namespace deepstate;

DEEPSTATE_NOINLINE void func(uint32_t x) {
  CHECK_LT(x, 0x1234)
    << "Found x=" << x << " was not greater than 0x1234.";

  if (x < 0x1234) {
    printf("hi\n");
  } else {
    printf("bye\n");
  }
}

int main(int argc, char *argv[]) {
  DeepState_InitOptions(argc, argv);

  uint32_t x = 123;
  func(x);  // Unexplored

  DeepState_TakeOver();

  Symbolic<uint32_t> y;
  Symbolic<uint32_t> z;
  func(y);  // Explored
  func(z);  // Explored
}
