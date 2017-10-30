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

#include <mctest/McUnit.hpp>

TEST(BoundsCheck, YIsAlwaysPositive) {
  int x = McTest_IntInRange(-10, 10);
  int y = x * x;
  ASSERT_GE(y, 0)
      << "Found y=" << y << " was not always positive.";
}

TEST(BoundsCheck, YIsAlwaysPositive_CanFail) {
  int x = McTest_Int();
  int y = x * x;  // Can overflow!
  ASSERT_GE(y, 0)
      << "Found y=" << y << " was not always positive.";
}

int main(int argc, char *argv[]) {
  return McTest_Run();
}
