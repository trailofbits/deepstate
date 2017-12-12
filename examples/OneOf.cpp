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



TEST(OneOfExample, ProduceSixtyOrHigher) {
  symbolic_int x;

  ASSUME_LT(x, 5);

  int N = 3;

  while (N > 0) {
    N--;
    OneOf(
	  [&x] {x += 1; printf("-1\n");},
	  [&x] {x -= 1; printf("+1\n");},
	  [&x] {x *= 2; printf("*2\n");},
	  [&x] {x += 10; printf("+=10\n");},	
	  [&x] {x = 0; printf("=0\n");});
    
    ASSERT_LE(x, 60)
      << x << " is >= 60!";
  }
}

int main(int argc, char *argv[]) {
  return DeepState_Run();
}
