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
#include <climits>
using namespace deepstate;

DEEPSTATE_NOINLINE int ident1(int x) {
  return x;
}

DEEPSTATE_NOINLINE int ident2(int x) {
  return x;
}

TEST(SignedInteger, AdditionOverflow) {
  Symbolic<int> x;
  int y = ident1(x) + ident2(x);  // Can overflow!
  ASSERT_GE(y, 0)
      << "Found y=" << y << " was not always positive.";
}

TEST(SignedInteger, MultiplicationOverflow) {
  Symbolic<int> x;
  int y = ident1(x) * ident2(x);  // Can overflow!
  ASSERT_GE(y, 0)
      << x << " squared overflowed.";
}
