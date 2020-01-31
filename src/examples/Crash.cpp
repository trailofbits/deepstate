/*
 * Copyright (c) 2019 Trail of Bits, Inc.
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

DEEPSTATE_NOINLINE static unsigned segfault(unsigned x) {
  if (x == 0x1234) {  // Magic number for engine to discover
    unsigned *p = NULL;
    *(p+1) = 0xdeadbeef;  // Trigger segfault here
  }

  return x;
}

TEST(Crash, SegFault) {
  symbolic_unsigned x;

  segfault(x);

  ASSERT_EQ(x, x);
}
