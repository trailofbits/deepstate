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

static unsigned pow5(unsigned v) {
  return v * v * v * v * v;
}

TEST(Euler, SumsOfLikePowers) {
  symbolic_unsigned a, b, c, d, e;
  ASSERT_GT(a, 1);
  ASSERT_GT(b, 1);
  ASSERT_GT(c, 1);
  ASSERT_GT(d, 1);
  ASSERT_GT(e, 1);
  ASSERT_NE(a, b); ASSERT_NE(a, c); ASSERT_NE(a, d); ASSERT_NE(a, e);
  ASSERT_NE(b, c); ASSERT_NE(b, d); ASSERT_NE(b, e);
  ASSERT_NE(c, d); ASSERT_NE(c, e);
  ASSERT_NE(d, e);
  ASSERT_NE(pow5(a) + pow5(b) + pow5(c) + pow5(d), pow5(e))
      << a << "^5 + " << b << "^5" << " + " << c
      << "^5 + " << d << "^5 = " << e << "^5";
}

