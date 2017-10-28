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

#include <mctest/Quantified.hpp>

using namespace mctest;

MCTEST_NOINLINE int add(int x, int y) {
  return x + y;
}

McTest_EntryPoint(AdditionIsCommutative) {
  ForAll<int, int>([] (int x, int y) {
    McTest_Assert(add(x, y) == add(y, x));
  });
}

int main(int argc, char *argv[]) {
  return McTest_Run();
}
