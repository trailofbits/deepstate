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
#include <setjmp.h>

#if defined(unix) || defined(__unix) || defined(__unix__)
# define _GNU_SOURCE
# include <unistd.h>  /* For `syscall` */
#endif

MCTEST_BEGIN_EXTERN_C

/* Pointer to the last registers McTest_TestInfo data structure */
struct McTest_TestInfo *McTest_LastTestInfo = NULL;

enum {
  McTest_InputLength = 8192
};

/* Byte buffer that will contain symbolic data that is used to supply requests
 * for symbolic values (e.g. `int`s). */
static volatile uint8_t McTest_Input[McTest_InputLength];

/* Index into the `McTest_Input` array that tracks how many input bytes have
 * been consumed. */
static uint32_t McTest_InputIndex = 0;

/* Jump buffer for returning to `McTest_Main`. */
static jmp_buf McTest_ReturnToMain;

static int McTest_TestPassed = 0;

/* Mark this test as failing. */
MCTEST_NORETURN
extern void McTest_Fail(void) {
  McTest_TestPassed = 0;
  longjmp(McTest_ReturnToMain, 1);
}

/* Mark this test as passing. */
MCTEST_NORETURN
extern void McTest_Pass(void) {
  McTest_TestPassed = 1;
  longjmp(McTest_ReturnToMain, 0);
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

/* A McTest-specific symbol that is needed for hooking. */
struct McTest_IndexEntry {
  const char * const name;
  void * const address;
};

/* An index of symbols that the symbolic executors will hook or
 * need access to. */
const struct McTest_IndexEntry McTest_API[] = {
  {"Pass",            (void *) McTest_Pass},
  {"Fail",            (void *) McTest_Fail},
  {"Assume",          (void *) _McTest_Assume},
  {"IsSymbolicUInt",  (void *) McTest_IsSymbolicUInt},
  {"InputBegin",      (void *) &(McTest_Input[0])},
  {"InputEnd",        (void *) &(McTest_Input[McTest_InputLength])},
  {"InputIndex",      (void *) &McTest_InputIndex},
  {"LastTestInfo",    (void *) &McTest_LastTestInfo},
  {NULL, NULL},
};

int McTest_Run(void) {

  /* Manticore entrypoint. Manticore doesn't (yet?) support symbol lookups, so
   * we instead interpose on this fake system call, and discover the API table
   * via the first argument to the system call. */
#if defined(_MSC_VER)
# warning "TODO: Implement Windows interception support for Manticore."
#else
  syscall(0x41414141, &McTest_API);
#endif

  int num_failed_tests = 0;
  for (struct McTest_TestInfo *info = McTest_LastTestInfo;
       info != NULL;
       info = info->prev) {

    McTest_TestPassed = 0;
    if (!setjmp(McTest_ReturnToMain)) {
      printf("Running %s from %s:%u\n", info->test_name, info->file_name,
             info->line_number);
      info->test_func();

    } else if (McTest_TestPassed) {
      printf("  %s Passed\n", info->test_name);
    } else {
      printf("  %s Failed\n", info->test_name);
      num_failed_tests += 1;
    }
  }
  return num_failed_tests;
}

MCTEST_END_EXTERN_C
