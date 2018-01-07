/*
 * Copyright (c) 2017 Trail of Bits, Inc.
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

DEEPSTATE_NOINLINE int add(int x, int y) {
  return x + y;
}

TEST(Arithmetic, AdditionIsCommutative) {
  ForAll<int, int>([] (int x, int y) {
    ASSERT_EQ(add(x, y), add(y, x))
        << "Addition of signed integers must commute.";
  });
}

TEST(Arithmetic, AdditionIsAssociative) {
  ForAll<int, int, int>([] (int x, int y, int z) {
    ASSERT_EQ(add(x, add(y, z)), add(add(x, y), z))
        << "Addition of signed integers must associate.";
  });
}

TEST(Arithmetic, InvertibleMultiplication_CanFail) {
  ForAll<int, int>([] (int x, int y) {
    ASSUME_NE(y, 0)
        << "Assumed non-zero value for y: " << y;
    ASSERT_EQ(x, (x / y) * y)
        << x << " != (" << x << " / " << y << ") * " << y;
  });
}

int main(int argc, char *argv[]) {
  DeepState_InitOptions(argc, argv);
  return DeepState_Run();
}
