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

#include <mctest/McTest.h>

#include <assert.h>

#ifdef __cplusplus
extern "C" {
#endif  /* __cplusplus */

static uint32_t gPlaybookIndex = 0;
static uint32_t gPlaybook[8192] = {};

void McTest_SymbolizeData(void *begin, void *end) {
  (void) begin;
  (void) end;
}

/* Return a symbolic value of a given type. */
int McTest_Bool(void) {
  return 0;
}

size_t McTest_Size(void) {
  return 0;
}

uint64_t McTest_UInt64(void) {
  return 0;
}

uint32_t McTest_UInt(void) {
  return 0;
}

int McTest_Assume(int expr) {
  assert(expr);
  return 1;
}

int McTest_IsSymbolicUInt(uint32_t x) {
  (void) x;
  return 0;
}

void McTest_DoneTestCase(void) {
  exit(EXIT_SUCCESS);
}

/* McTest implements the `main` function so that test code can focus on tests */
int main(void) {
#if defined(__x86_64__) || defined(__i386__) || defined(_M_X86)
  asm("ud2; .asciz \"I'm McTest'in it\";");
#else
# error "Unsupported platform (for now)."
#endif
  return EXIT_SUCCESS;
}

#ifdef __cplusplus
}  /* extern C */
#endif  /* __cplusplus */
