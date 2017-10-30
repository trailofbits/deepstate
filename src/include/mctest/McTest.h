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

#ifndef INCLUDE_MCTEST_MCTEST_H_
#define INCLUDE_MCTEST_MCTEST_H_

#include <assert.h>
#include <setjmp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mctest/Compiler.h>

#ifdef assert
# undef assert
#endif
#define assert McTest_Assert

MCTEST_BEGIN_EXTERN_C

/* Return a symbolic value of a given type. */
extern int McTest_Bool(void);
extern size_t McTest_Size(void);
extern uint64_t McTest_UInt64(void);
extern int64_t McTest_Int64(void);
extern uint32_t McTest_UInt(void);
extern int32_t McTest_Int(void);
extern uint16_t McTest_UShort(void);
extern int16_t McTest_Short(void);
extern uint8_t McTest_UChar(void);
extern int8_t McTest_Char(void);

/* Returns `1` if `expr` is true, and `0` otherwise. This is kind of an indirect
 * way to take a symbolic value, introduce a fork, and on each size, replace its
* value with a concrete value. */
extern int McTest_IsTrue(int expr);

/* Symbolize the data in the range `[begin, end)`. */
extern void McTest_SymbolizeData(void *begin, void *end);

MCTEST_INLINE static void *McTest_Malloc(size_t num_bytes) {
  void *data = malloc(num_bytes);
  uintptr_t data_end = ((uintptr_t) data) + num_bytes;
  McTest_SymbolizeData(data, (void *) data_end);
  return data;
}

#define MCTEST_MAKE_SYMBOLIC_ARRAY(Tname, tname) \
    MCTEST_INLINE static \
    tname *McTest_Symbolic ## Tname ## Array(size_t num_elms) { \
      tname *arr = (tname *) malloc(sizeof(tname) * num_elms); \
      McTest_SymbolizeData(arr, &(arr[num_elms])); \
      return arr; \
    }

MCTEST_MAKE_SYMBOLIC_ARRAY(Int64, int64_t)
MCTEST_MAKE_SYMBOLIC_ARRAY(UInt64, uint64_t)
MCTEST_MAKE_SYMBOLIC_ARRAY(Int, int)
MCTEST_MAKE_SYMBOLIC_ARRAY(UInt, uint32_t)
MCTEST_MAKE_SYMBOLIC_ARRAY(Short, int16_t)
MCTEST_MAKE_SYMBOLIC_ARRAY(UShort, uint16_t)
MCTEST_MAKE_SYMBOLIC_ARRAY(Char, char)
MCTEST_MAKE_SYMBOLIC_ARRAY(UChar, unsigned char)

#undef MCTEST_MAKE_SYMBOLIC_ARRAY

/* Return a symbolic C string. */
MCTEST_INLINE static char *McTest_CStr(size_t len) {
  char *str = (char *) malloc(sizeof(char) * len);
  if (len) {
    McTest_SymbolizeData(str, &(str[len - 1]));
    str[len - 1] = '\0';
  }
  return str;
}

/* Creates an assumption about a symbolic value. Returns `1` if the assumption
 * can hold and was asserted. */
extern void _McTest_Assume(int expr);

#define McTest_Assume(x) _McTest_Assume(!!(x))

MCTEST_NORETURN
extern void McTest_Fail(void);

/* Mark this test as failing, but don't hard exit. */
extern void McTest_SoftFail(void);

MCTEST_NORETURN
extern void McTest_Pass(void);

/* Asserts that `expr` must hold. If it does not, then the test fails and
 * immediately stops. */
MCTEST_INLINE static void McTest_Assert(int expr) {
  if (!expr) {
    McTest_Fail();
  }
}

/* Asserts that `expr` must hold. If it does not, then the test fails, but
 * nonetheless continues on. */
MCTEST_INLINE static void McTest_Check(int expr) {
  if (!expr) {
    McTest_SoftFail();
  }
}

enum McTest_LogLevel {
  McTest_LogDebug = 0,
  McTest_LogInfo = 1,
  McTest_LogWarning = 2,
  McTest_LogWarn = McTest_LogWarning,
  McTest_LogError = 3,
  McTest_LogFatal = 4,
  McTest_LogCritical = McTest_LogFatal
};

/* Outputs information to a log, using a specific log level. */
extern void McTest_Log(enum McTest_LogLevel level, const char *begin,
                       const char *end);

/* Return a symbolic value in a the range `[low_inc, high_inc]`. */
#define MCTEST_MAKE_SYMBOLIC_RANGE(Tname, tname) \
    MCTEST_INLINE static tname McTest_ ## Tname ## InRange( \
        tname low, tname high) { \
      tname x = McTest_ ## Tname(); \
      (void) McTest_Assume(low <= x && x <= high); \
      return x; \
    }

MCTEST_MAKE_SYMBOLIC_RANGE(Size, size_t)
MCTEST_MAKE_SYMBOLIC_RANGE(Int64, int64_t)
MCTEST_MAKE_SYMBOLIC_RANGE(UInt64, uint64_t)
MCTEST_MAKE_SYMBOLIC_RANGE(Int, int)
MCTEST_MAKE_SYMBOLIC_RANGE(UInt, uint32_t)
MCTEST_MAKE_SYMBOLIC_RANGE(Short, int16_t)
MCTEST_MAKE_SYMBOLIC_RANGE(UShort, uint16_t)
MCTEST_MAKE_SYMBOLIC_RANGE(Char, char)
MCTEST_MAKE_SYMBOLIC_RANGE(UChar, unsigned char)

#undef MCTEST_MAKE_SYMBOLIC_RANGE

/* Predicates to check whether or not a particular value is symbolic */
extern int McTest_IsSymbolicUInt(uint32_t x);

/* The following predicates are implemented in terms of `McTest_IsSymbolicUInt`.
 * This simplifies the portability of hooking this predicate interface across
 * architectures, because basically all hooking mechanisms know how to get at
 * the first integer argument. Passing in floating point values, or 64-bit
 * integers on 32-bit architectures, can be more subtle. */

MCTEST_INLINE static int McTest_IsSymbolicInt(int x) {
  return McTest_IsSymbolicUInt((uint32_t) x);
}

MCTEST_INLINE static int McTest_IsSymbolicUShort(uint16_t x) {
  return McTest_IsSymbolicUInt((uint32_t) x);
}

MCTEST_INLINE static int McTest_IsSymbolicShort(int16_t x) {
  return McTest_IsSymbolicUInt((uint32_t) (uint16_t) x);
}

MCTEST_INLINE static int McTest_IsSymbolicUChar(unsigned char x) {
  return McTest_IsSymbolicUInt((uint32_t) x);
}

MCTEST_INLINE static int McTest_IsSymbolicChar(char x) {
  return McTest_IsSymbolicUInt((uint32_t) (unsigned char) x);
}

MCTEST_INLINE static int McTest_IsSymbolicUInt64(uint64_t x) {
  return McTest_IsSymbolicUInt((uint32_t) x) ||
         McTest_IsSymbolicUInt((uint32_t) (x >> 32U));
}

MCTEST_INLINE static int McTest_IsSymbolicInt64(int64_t x) {
  return McTest_IsSymbolicUInt64((uint64_t) x);
}

MCTEST_INLINE static int McTest_IsSymbolicBool(int x) {
  return McTest_IsSymbolicInt(x);
}

MCTEST_INLINE static int McTest_IsSymbolicFloat(float x) {
  return McTest_IsSymbolicUInt(*((uint32_t *) &x));
}

MCTEST_INLINE static int McTest_IsSymbolicDouble(double x) {
  return McTest_IsSymbolicUInt64(*((uint64_t *) &x));
}

/* Used to define the entrypoint of a test case. */
#define McTest_EntryPoint(test_name) \
    _McTest_EntryPoint(test_name, __FILE__, __LINE__)

/* Contains information about a test case */
struct McTest_TestInfo {
  struct McTest_TestInfo *prev;
  void (*test_func)(void);
  const char *test_name;
  const char *file_name;
  unsigned line_number;
};

/* Pointer to the last registered `TestInfo` structure. */
extern struct McTest_TestInfo *McTest_LastTestInfo;

/* Defines the entrypoint of a test case. This creates a data structure that
 * contains the information about the test, and then creates an initializer
 * function that runs before `main` that registers the test entrypoint with
 * McTest. */
#define _McTest_EntryPoint(test_name, file, line) \
    static void McTest_Test_ ## test_name (void); \
    static void McTest_Run_ ## test_name (void) { \
      McTest_Test_ ## test_name(); \
      McTest_Pass(); \
    } \
    static struct McTest_TestInfo McTest_Info_ ## test_name = { \
      NULL, \
      McTest_Run_ ## test_name, \
      MCTEST_TO_STR(test_name), \
      file, \
      line, \
    }; \
    MCTEST_INITIALIZER(McTest_Register_ ## test_name) { \
      McTest_Info_ ## test_name.prev = McTest_LastTestInfo; \
      McTest_LastTestInfo = &(McTest_Info_ ## test_name); \
    } \
    void McTest_Test_ ## test_name(void)

/* Set up McTest. */
extern void McTest_Setup(void);

/* Return the first test case to run. */
extern struct McTest_TestInfo *McTest_FirstTest(void);

/* Returns 1 if a failure was caught, otherwise 0. */
extern int McTest_CatchFail(void);

/* Jump buffer for returning to `McTest_Run`. */
extern jmp_buf McTest_ReturnToRun;

/* Start McTest and run the tests. Returns the number of failed tests. */
static int McTest_Run(void) {
  int num_failed_tests = 0;
  struct McTest_TestInfo *test = NULL;
  char buff[1024];
  int num_buff_bytes_used = 0;

  McTest_Setup();

  for (test = McTest_FirstTest(); test != NULL; test = test->prev) {

    /* Print the test that we're going to run. */
    num_buff_bytes_used = sprintf(buff, "Running: %s from %s:%u",
                                  test->test_name, test->file_name,
                                  test->line_number);
    McTest_Log(McTest_LogInfo, buff, &(buff[num_buff_bytes_used]));

    /* Run the test. */
    if (!setjmp(McTest_ReturnToRun)) {
      
      /* Convert uncaught C++ exceptions into a test failure. */
#if defined(__cplusplus) && defined(__cpp_exceptions)
      try {
#endif  /* __cplusplus */

      test->test_func();  /* Run the test function. */
      McTest_Pass();

#if defined(__cplusplus) && defined(__cpp_exceptions)
      } catch(...) {
        McTest_Fail();
      }
#endif  /* __cplusplus */

    /* We caught a failure when running the test. */
    } else if (McTest_CatchFail()) {
      ++num_failed_tests;

      num_buff_bytes_used = sprintf(buff, "Failed: %s", test->test_name);
      McTest_Log(McTest_LogInfo, buff, &(buff[num_buff_bytes_used]));

    /* The test passed. */
    } else {
      num_buff_bytes_used = sprintf(buff, "Passed: %s", test->test_name);
      McTest_Log(McTest_LogInfo, buff, &(buff[num_buff_bytes_used]));
    }
  }

  return num_failed_tests;
}

MCTEST_END_EXTERN_C

#endif  /* INCLUDE_MCTEST_MCTEST_H_ */
