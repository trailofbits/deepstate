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

#include <algorithm>
#include <vector>

using namespace deepstate;

TEST(Vector, DoubleReversal) {
  ForAll<std::vector<int>>([] (const std::vector<int> &vec1) {
    std::vector<int> vec2 = vec1;
    std::reverse(vec2.begin(), vec2.end());
    std::reverse(vec2.begin(), vec2.end());
    ASSERT_EQ(vec1, vec2)
        << "Double reverse of vectors must be equal.";
  });
}
