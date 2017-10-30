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
#include <stdio.h>

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

/* Jump buffer for returning to `McTest_Run`. */
jmp_buf McTest_ReturnToRun = {};

static int McTest_TestFailed = 0;

/* Mark this test as failing. */
MCTEST_NORETURN
void McTest_Fail(void) {
  McTest_TestFailed = 1;
  longjmp(McTest_ReturnToRun, 1);
}

/* Mark this test as passing. */
MCTEST_NORETURN
void McTest_Pass(void) {
  longjmp(McTest_ReturnToRun, 0);
}

void McTest_SoftFail(void) {
  McTest_TestFailed = 1;
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

MCTEST_NOINLINE int McTest_One(void) {
  return 1;
}

MCTEST_NOINLINE int McTest_Zero(void) {
  return 0;
}

/* Returns `1` if `expr` is true, and `0` otherwise. This is kind of an indirect
 * way to take a symbolic value, introduce a fork, and on each size, replace its
* value with a concrete value. */
int McTest_IsTrue(int expr) {
  if (expr == McTest_Zero()) {
    return McTest_Zero();
  } else {
    return McTest_One();
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


MAKE_SYMBOL_FUNC(Size, size_t)

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

/* Returns a printable string version of the log level. */
static const char *McTest_LogLevelStr(enum McTest_LogLevel level) {
  switch (level) {
    case McTest_LogDebug:
      return "DEBUG";
    case McTest_LogInfo:
      return "INFO";
    case McTest_LogWarning:
      return "WARNING";
    case McTest_LogError:
      return "ERROR";
    case McTest_LogFatal:
      return "FATAL";
    default:
      return "UNKNOWN";
  }
}

enum {
  McTest_LogBufSize = 4096
};

char McTest_LogBuf[McTest_LogBufSize + 1] = {};


void _McTest_Log(enum McTest_LogLevel level, const char *message) {
  fprintf(stderr, "%s: %s\n", McTest_LogLevelStr(level), message);
  if (McTest_LogError == level) {
    McTest_SoftFail();

  } else if (McTest_LogFatal == level) {
    McTest_Fail();
  }
}

/* Outputs information to a log, using a specific log level. */
void McTest_Log(enum McTest_LogLevel level, const char *begin,
                 const char *end) {
  if (end <= begin) {
    return;
  }

  size_t size = (size_t) (end - begin);
  if (size > McTest_LogBufSize) {
    size = McTest_LogBufSize;
  }

  /* When we interpose on _McTest_Log, we are looking for the first non-symbolic
   * zero byte as our end of string character, so we want to guarantee that we
   * have a bunch of those */
  memset(McTest_LogBuf, 0, McTest_LogBufSize);
  memcpy(McTest_LogBuf, begin, size);
  McTest_LogBuf[McTest_LogBufSize] = '\0';

  _McTest_Log(level, McTest_LogBuf);
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
  {"SoftFail",        (void *) McTest_SoftFail},
  {"Log",             (void *) _McTest_Log},
  {"Assume",          (void *) _McTest_Assume},
  {"IsSymbolicUInt",  (void *) McTest_IsSymbolicUInt},
  {"InputBegin",      (void *) &(McTest_Input[0])},
  {"InputEnd",        (void *) &(McTest_Input[McTest_InputLength])},
  {"InputIndex",      (void *) &McTest_InputIndex},
  {"LastTestInfo",    (void *) &McTest_LastTestInfo},
  {NULL, NULL},
};

/* Set up McTest. */
void McTest_Setup(void) {
  /* TODO(pag): Sort the test cases by file name and line number. */
}

/* Return the first test case to run. */
struct McTest_TestInfo *McTest_FirstTest(void) {
  return McTest_LastTestInfo;
}

/* Returns 1 if a failure was caught, otherwise 0. */
int McTest_CatchFail(void) {
  return McTest_TestFailed;
}

MCTEST_END_EXTERN_C
