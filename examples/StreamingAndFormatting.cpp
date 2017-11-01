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

TEST(Streaming, BasicLevels) {
  LOG(DEBUG) << "This is a debug message";
  LOG(INFO) << "This is an info message";
  LOG(WARNING) << "This is a warning message";
  LOG(ERROR) << "This is a error message";
  LOG(INFO) << "This is a info message again";
  ASSERT(true) << "This should not be printed.";
}

TEST(Streaming, BasicTypes) {
  LOG(INFO) << 'a';
  LOG(INFO) << 1;
  LOG(INFO) << 1.0;
  LOG(INFO) << "string";
  LOG(INFO) << nullptr;
}

TEST(Formatting, OverridePrintf) {
  printf("hello string=%s hex_lower=%x hex_upper=%X octal=%o char=%c dec=%d"
         "double=%f sci=%e SCI=%E pointer=%p",
         "world", 999, 999, 999, 'a', 999, 999.0, 999.0, 999.0, "world");
}

int main(void) {
  return McTest_Run();
}
