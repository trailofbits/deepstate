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

DEEPSTATE_NOINLINE static void segfault(char *first, char* second) {
  std::size_t hashed = std::hash<std::string>{}(first);
  std::size_t hashed2 = std::hash<std::string>{}(second);
  unsigned *p = NULL;
  if (hashed == 7169420828666634849U) {
    if (hashed2 == 10753164746288518855U) {
      *(p+2) = 0xdeadbeef;  /* crash */
    }
    printf("BOM\n");
  }
}

TEST(SimpleCrash, SegFault) {
  char *first = (char*)DeepState_CStr_C(9, 0);
  char *second = (char*)DeepState_CStr_C(9, 0);

  for (int i = 0; i < 9; ++i)
    printf("%02x", (unsigned char)first[i]);
  printf("\n");
  for (int i = 0; i < 9; ++i)
    printf("%02x", (unsigned char)second[i]);

  segfault(first, second);

  ASSERT_EQ(first, first);
  ASSERT_NE(first, second);
}
