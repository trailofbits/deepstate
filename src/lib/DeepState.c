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

#include "deepstate/DeepState.h"

#include <assert.h>
#include <limits.h>
#include <setjmp.h>
#include <stdio.h>

DEEPSTATE_BEGIN_EXTERN_C

/* Pointer to the last registers DeepState_TestInfo data structure */
struct DeepState_TestInfo *DeepState_LastTestInfo = NULL;

enum {
  DeepState_InputSize = 8192
};

/* Byte buffer that will contain symbolic data that is used to supply requests
 * for symbolic values (e.g. `int`s). */
static volatile uint8_t DeepState_Input[DeepState_InputSize];

/* Index into the `DeepState_Input` array that tracks how many input bytes have
 * been consumed. */
static uint32_t DeepState_InputIndex = 0;

/* Jump buffer for returning to `DeepState_Run`. */
jmp_buf DeepState_ReturnToRun = {};

static const char *DeepState_TestAbandoned = NULL;
static int DeepState_TestFailed = 0;

/* Abandon this test. We've hit some kind of internal problem. */
DEEPSTATE_NORETURN
void DeepState_Abandon(const char *reason) {
  DeepState_Log(DeepState_LogFatal, reason);
  DeepState_TestAbandoned = reason;
  longjmp(DeepState_ReturnToRun, 1);
}

/* Mark this test as failing. */
DEEPSTATE_NORETURN
void DeepState_Fail(void) {
  DeepState_TestFailed = 1;
  longjmp(DeepState_ReturnToRun, 1);
}

/* Mark this test as passing. */
DEEPSTATE_NORETURN
void DeepState_Pass(void) {
  longjmp(DeepState_ReturnToRun, 0);
}

void DeepState_SoftFail(void) {
  DeepState_TestFailed = 1;
}

/* Symbolize the data in the exclusive range `[begin, end)`. */
void DeepState_SymbolizeData(void *begin, void *end) {
  uintptr_t begin_addr = (uintptr_t) begin;
  uintptr_t end_addr = (uintptr_t) end;

  if (begin_addr > end_addr) {
    DeepState_Abandon("Invalid data bounds for DeepState_SymbolizeData");
  } else if (begin_addr == end_addr) {
    return;
  } else {
    uint8_t *bytes = (uint8_t *) begin;
    for (uintptr_t i = 0, max_i = (end_addr - begin_addr); i < max_i; ++i) {
      if (DeepState_InputIndex >= DeepState_InputSize) {
        DeepState_Abandon("Read too many symbols");
      }
      bytes[i] = DeepState_Input[DeepState_InputIndex++];
    }
  }
}

/* Concretize some data in exclusive the range `[begin, end)`. */
void *DeepState_ConcretizeData(void *begin, void *end) {
  return begin;
}

/* Return a symbolic C string of length `len`. */
char *DeepState_CStr(size_t len) {
  if (SIZE_MAX == len) {
    DeepState_Abandon("Can't create an SIZE_MAX-length string.");
  }
  char *str = (char *) malloc(sizeof(char) * (len + 1));
  if (len) {
    DeepState_SymbolizeData(str, &(str[len - 1]));
  }
  str[len] = '\0';
  return str;
}

/* Concretize a C string */
const char *DeepState_ConcretizeCStr(const char *begin) {
  return begin;
}

/* Allocate and return a pointer to `num_bytes` symbolic bytes. */
void *DeepState_Malloc(size_t num_bytes) {
  void *data = malloc(num_bytes);
  uintptr_t data_end = ((uintptr_t) data) + num_bytes;
  DeepState_SymbolizeData(data, (void *) data_end);
  return data;
}

DEEPSTATE_NOINLINE int DeepState_One(void) {
  return 1;
}

DEEPSTATE_NOINLINE int DeepState_Zero(void) {
  return 0;
}

/* Returns `1` if `expr` is true, and `0` otherwise. This is kind of an indirect
 * way to take a symbolic value, introduce a fork, and on each size, replace its
* value with a concrete value. */
int DeepState_IsTrue(int expr) {
  if (expr == DeepState_Zero()) {
    return DeepState_Zero();
  } else {
    return DeepState_One();
  }
}

/* Return a symbolic value of a given type. */
int DeepState_Bool(void) {
  if (DeepState_InputIndex >= DeepState_InputSize) {
    DeepState_Abandon("Read too many symbols");
  }
  return DeepState_Input[DeepState_InputIndex++] & 1;
}

#define MAKE_SYMBOL_FUNC(Type, type) \
    type DeepState_ ## Type(void) { \
      if ((DeepState_InputIndex + sizeof(type)) > DeepState_InputSize) { \
        DeepState_Abandon("Read too many symbols"); \
      } \
      type val = 0; \
      _Pragma("unroll") \
      for (size_t i = 0; i < sizeof(type); ++i) { \
        val = (val << 8) | ((type) DeepState_Input[DeepState_InputIndex++]); \
      } \
      return val; \
    }


MAKE_SYMBOL_FUNC(Size, size_t)

MAKE_SYMBOL_FUNC(UInt64, uint64_t)
int64_t DeepState_Int64(void) {
  return (int64_t) DeepState_UInt64();
}

MAKE_SYMBOL_FUNC(UInt, uint32_t)
int32_t DeepState_Int(void) {
  return (int32_t) DeepState_UInt();
}

MAKE_SYMBOL_FUNC(UShort, uint16_t)
int16_t DeepState_Short(void) {
  return (int16_t) DeepState_UShort();
}

MAKE_SYMBOL_FUNC(UChar, uint8_t)
int8_t DeepState_Char(void) {
  return (int8_t) DeepState_UChar();
}

#undef MAKE_SYMBOL_FUNC

void _DeepState_Assume(int expr) {
  assert(expr);
}

int DeepState_IsSymbolicUInt(uint32_t x) {
  (void) x;
  return 0;
}

/* Defined in Stream.c */
extern void _DeepState_StreamInt(enum DeepState_LogLevel level,
                                 const char *format,
                                 const char *unpack, uint64_t *val);

extern void _DeepState_StreamFloat(enum DeepState_LogLevel level,
                                   const char *format,
                                   const char *unpack, double *val);

extern void _DeepState_StreamString(enum DeepState_LogLevel level,
                                    const char *format,
                                    const char *str);

/* A DeepState-specific symbol that is needed for hooking. */
struct DeepState_IndexEntry {
  const char * const name;
  void * const address;
};

/* An index of symbols that the symbolic executors will hook or
 * need access to. */
const struct DeepState_IndexEntry DeepState_API[] = {

  /* Control-flow during the test. */
  {"Pass",            (void *) DeepState_Pass},
  {"Fail",            (void *) DeepState_Fail},
  {"SoftFail",        (void *) DeepState_SoftFail},
  {"Abandon",         (void *) DeepState_Abandon},

  /* Locating the tests. */
  {"LastTestInfo",    (void *) &DeepState_LastTestInfo},

  /* Source of symbolic bytes. */
  {"InputBegin",      (void *) &(DeepState_Input[0])},
  {"InputEnd",        (void *) &(DeepState_Input[DeepState_InputSize])},
  {"InputIndex",      (void *) &DeepState_InputIndex},

  /* Solver APIs. */
  {"Assume",          (void *) _DeepState_Assume},
  {"IsSymbolicUInt",  (void *) DeepState_IsSymbolicUInt},
  {"ConcretizeData",  (void *) DeepState_ConcretizeData},
  {"ConcretizeCStr",  (void *) DeepState_ConcretizeCStr},

  /* Logging API. */
  {"Log",             (void *) DeepState_Log},

  /* Streaming API for deferred logging. */
  {"LogStream",       (void *) DeepState_LogStream},
  {"StreamInt",       (void *) _DeepState_StreamInt},
  {"StreamFloat",     (void *) _DeepState_StreamFloat},
  {"StreamString",    (void *) _DeepState_StreamString},

  {NULL, NULL},
};

/* Set up DeepState. */
void DeepState_Setup(void) {
  /* TODO(pag): Sort the test cases by file name and line number. */
}

/* Tear down DeepState. */
void DeepState_Teardown(void) {

}

/* Notify that we're about to begin a test. */
void DeepState_Begin(struct DeepState_TestInfo *info) {
  DeepState_TestFailed = 0;
  DeepState_TestAbandoned = NULL;
  DeepState_LogFormat(DeepState_LogInfo, "Running: %s from %s(%u)",
                   info->test_name, info->file_name, info->line_number);
}

/* Return the first test case to run. */
struct DeepState_TestInfo *DeepState_FirstTest(void) {
  return DeepState_LastTestInfo;
}

/* Returns 1 if a failure was caught, otherwise 0. */
int DeepState_CatchFail(void) {
  return DeepState_TestFailed;
}

/* Returns 1 if this test case was abandoned. */
int DeepState_CatchAbandoned(void) {
  return DeepState_TestAbandoned != NULL;
}

DEEPSTATE_END_EXTERN_C
