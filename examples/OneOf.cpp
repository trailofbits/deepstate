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

#define LENGTH 3

TEST(OneOfExample, ProduceSixtyOrHigher) {
  symbolic_int start;
  ASSUME_LT(start, 5);
  int x = start;
  
  char choices[LENGTH + 1] = {};
  
  // Add this back in and uncomment out choices parts below, add
  // & choices, N to captures, and it becomes quite difficult.
  
  for (int n = 0; n < LENGTH; n++) {
    OneOf(
      [&] {
        x += 1;
        printf("+=1\n");
        choices[n] = '+';
      },
      [&] {
        x -= 1;
        printf("-=1\n");
        choices[n] = '-';
      },
      [&] {
        x *= 2;
        printf("*2\n");
        choices[n] = '2';
      },
      [&] {
        x += 10;
        printf("+=10\n");
        choices[n] = 'x';
      },
      [&] {
        x = 0;
        printf("=0\n");
        choices[n] = '0';
      });

    //choices[N+1] = 0;
    ASSERT_LE(x, 60)
      << x << " is >= 60: " << " did " << choices << " from " << start;
  }
}
