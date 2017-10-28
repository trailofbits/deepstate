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

volatile uint8_t McTest_Input[8192]
    __attribute__((section(".mctest_input_data")));

uint32_t McTest_InputIndex = 0;

__attribute__((noreturn))
extern void McTest_Fail(void) {
  exit(EXIT_FAILURE);
}

__attribute__((noreturn))
extern void McTest_Pass(void) {
  exit(EXIT_SUCCESS);
}

void McTest_SymbolizeData(void *begin, void *end) {
  uintptr_t begin_addr = (uintptr_t) begin;
  uintptr_t end_addr = (uintptr_t) end;

  if (begin_addr > end_addr) {
    abort();
  } else if (begin_addr == end_addr) {
    return;
  } else {
    uint8_t *bytes = (uint8_t *) begin;
    for (uintptr_t i = 0, max_i = (end_addr - begin_addr); i < max_i; ++i) {
      bytes[i] = McTest_Input[McTest_InputIndex++];
    }
  }
}

/* Return a symbolic value of a given type. */
int McTest_Bool(void) {
  return McTest_Input[McTest_InputIndex++] & 1;
}

#define MAKE_SYMBOL_FUNC(Type, type) \
    type McTest_ ## Type(void) { \
      type val = 0; \
      _Pragma("unroll") \
      for (size_t i = 0; i < sizeof(type); ++i) { \
        val = (val << 8) | ((type) McTest_Input[McTest_InputIndex++]); \
      } \
      return val; \
    }

MAKE_SYMBOL_FUNC(UInt64, uint64_t)
int64_t McTest_Int64(void) {
  return (int64_t) McTest_UInt64();
}

MAKE_SYMBOL_FUNC(UInt, uint32_t)
int32_t McTest_Int(void) {
  return (int32_t) McTest_UInt();
}

MAKE_SYMBOL_FUNC(UShort, uint16_t)
int16_t McTest_Short(void) {
  return (int16_t) McTest_UShort();
}

MAKE_SYMBOL_FUNC(UChar, uint8_t)
int8_t McTest_Char(void) {
  return (int8_t) McTest_UChar();
}

#undef MAKE_SYMBOL_FUNC

void _McTest_Assume(int expr) {
  assert(expr);
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
  return EXIT_SUCCESS;
}

#ifdef __cplusplus
}  /* extern C */
#endif  /* __cplusplus */
