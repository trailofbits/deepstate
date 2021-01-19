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

TEST(WithProbs, WP) {
  char out[12];
  out[11] = '\0';
  for (int i = 0; i < 10; i++) {
    OneOfP(
	   0.1, [&]{out[i] = 'a';},
	   // a probability of -1 indicates "just use even dist over non-specified"	   
	   -1, [&]{out[i] = 'b';},
	   -1, [&]{out[i] = 'c';},
	   0.6, [&]{out[i] = 'd';});
  }
  char a[3] = {'x', 'y', 'z'};
  out[10] = OneOfP({0.1, 0.1}, a);
  std::vector<int> pos = {0, 1, 2};
  int p = OneOfP({-1, -1, 0.9}, pos);
  out[p] = '!';
  LOG(TRACE) << "RESULT: '" << out << "'";
}
