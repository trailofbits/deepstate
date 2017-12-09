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

#ifndef SRC_INCLUDE_DEEPSTATE_DEEPSTATE_H_
#define SRC_INCLUDE_DEEPSTATE_DEEPSTATE_H_

#include <assert.h>
#include <setjmp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <deepstate/Log.h>
#include <deepstate/Compiler.h>
#include <deepstate/Stream.h>

#ifdef assert
# undef assert
#endif

#define assert DeepState_Assert
#define assume DeepState_Assume
#define check DeepState_Check

#define MAYBE(...) \
    if (DeepState_Bool()) { \
      __VA_ARGS__ ; \
    }

DEEPSTATE_BEGIN_EXTERN_C

/* Return a symbolic value of a given type. */
extern int DeepState_Bool(void);
extern size_t DeepState_Size(void);
extern uint64_t DeepState_UInt64(void);
extern int64_t DeepState_Int64(void);
extern uint32_t DeepState_UInt(void);
extern int32_t DeepState_Int(void);
extern uint16_t DeepState_UShort(void);
extern int16_t DeepState_Short(void);
extern uint8_t DeepState_UChar(void);
extern int8_t DeepState_Char(void);

/* Returns the minimum satisfiable value for a given symbolic value, given
 * the constraints present on that value. */
extern uint32_t DeepState_MinUInt(uint32_t);
extern int32_t DeepState_MinInt(int32_t);

DEEPSTATE_INLINE static uint16_t DeepState_MinUShort(uint16_t v) {
  return DeepState_MinUInt(v);
}

DEEPSTATE_INLINE static uint8_t DeepState_MinUChar(uint8_t v) {
  return DeepState_MinUInt(v);
}

DEEPSTATE_INLINE static int16_t DeepState_MinShort(int16_t v) {
  return DeepState_MinInt(v);
}

DEEPSTATE_INLINE static int8_t DeepState_MinChar(int8_t v) {
  return DeepState_MinInt(v);
}

/* Returns `1` if `expr` is true, and `0` otherwise. This is kind of an indirect
 * way to take a symbolic value, introduce a fork, and on each size, replace its
* value with a concrete value. */
extern int DeepState_IsTrue(int expr);

/* Symbolize the data in the exclusive range `[begin, end)`. */
extern void DeepState_SymbolizeData(void *begin, void *end);

/* Concretize some data in exclusive the range `[begin, end)`. Returns a
 * concrete pointer to the beginning of the concretized data. */
extern void *DeepState_ConcretizeData(void *begin, void *end);

/* Return a symbolic C string of length `len`. */
extern char *DeepState_CStr(size_t len);

/* Symbolize a C string */
void DeepState_SymbolizeCStr(char *begin);

/* Concretize a C string. Returns a pointer to the beginning of the
 * concretized C string. */
extern const char *DeepState_ConcretizeCStr(const char *begin);

/* Allocate and return a pointer to `num_bytes` symbolic bytes. */
extern void *DeepState_Malloc(size_t num_bytes);

#define DEEPSTATE_MAKE_SYMBOLIC_ARRAY(Tname, tname) \
    DEEPSTATE_INLINE static \
    tname *DeepState_Symbolic ## Tname ## Array(size_t num_elms) { \
      tname *arr = (tname *) malloc(sizeof(tname) * num_elms); \
      DeepState_SymbolizeData(arr, &(arr[num_elms])); \
      return arr; \
    }

DEEPSTATE_MAKE_SYMBOLIC_ARRAY(Int64, int64_t)
DEEPSTATE_MAKE_SYMBOLIC_ARRAY(UInt64, uint64_t)
DEEPSTATE_MAKE_SYMBOLIC_ARRAY(Int, int)
DEEPSTATE_MAKE_SYMBOLIC_ARRAY(UInt, uint32_t)
DEEPSTATE_MAKE_SYMBOLIC_ARRAY(Short, int16_t)
DEEPSTATE_MAKE_SYMBOLIC_ARRAY(UShort, uint16_t)
DEEPSTATE_MAKE_SYMBOLIC_ARRAY(Char, char)
DEEPSTATE_MAKE_SYMBOLIC_ARRAY(UChar, unsigned char)

#undef DEEPSTATE_MAKE_SYMBOLIC_ARRAY

/* Creates an assumption about a symbolic value. Returns `1` if the assumption
 * can hold and was asserted. */
extern void _DeepState_Assume(int expr, const char *expr_str, const char *file,
                              unsigned line);

#define DeepState_Assume(x) _DeepState_Assume(!!(x), #x, __FILE__, __LINE__)

/* Abandon this test. We've hit some kind of internal problem. */
DEEPSTATE_NORETURN
extern void DeepState_Abandon(const char *reason);

DEEPSTATE_NORETURN
extern void DeepState_Fail(void);

/* Mark this test as failing, but don't hard exit. */
extern void DeepState_SoftFail(void);

DEEPSTATE_NORETURN
extern void DeepState_Pass(void);

/* Asserts that `expr` must hold. If it does not, then the test fails and
 * immediately stops. */
DEEPSTATE_INLINE static void DeepState_Assert(int expr) {
  if (!expr) {
    DeepState_Fail();
  }
}

/* Asserts that `expr` must hold. If it does not, then the test fails, but
 * nonetheless continues on. */
DEEPSTATE_INLINE static void DeepState_Check(int expr) {
  if (!expr) {
    DeepState_SoftFail();
  }
}

/* Return a symbolic value in a the range `[low_inc, high_inc]`. */
#define DEEPSTATE_MAKE_SYMBOLIC_RANGE(Tname, tname) \
    DEEPSTATE_INLINE static tname DeepState_ ## Tname ## InRange( \
        tname low, tname high) { \
      tname x = DeepState_ ## Tname(); \
      (void) DeepState_Assume(low <= x && x <= high); \
      return x; \
    }

DEEPSTATE_MAKE_SYMBOLIC_RANGE(Size, size_t)
DEEPSTATE_MAKE_SYMBOLIC_RANGE(Int64, int64_t)
DEEPSTATE_MAKE_SYMBOLIC_RANGE(UInt64, uint64_t)
DEEPSTATE_MAKE_SYMBOLIC_RANGE(Int, int)
DEEPSTATE_MAKE_SYMBOLIC_RANGE(UInt, uint32_t)
DEEPSTATE_MAKE_SYMBOLIC_RANGE(Short, int16_t)
DEEPSTATE_MAKE_SYMBOLIC_RANGE(UShort, uint16_t)
DEEPSTATE_MAKE_SYMBOLIC_RANGE(Char, char)
DEEPSTATE_MAKE_SYMBOLIC_RANGE(UChar, unsigned char)

#undef DEEPSTATE_MAKE_SYMBOLIC_RANGE

/* Predicates to check whether or not a particular value is symbolic */
extern int DeepState_IsSymbolicUInt(uint32_t x);

/* The following predicates are implemented in terms of `DeepState_IsSymbolicUInt`.
 * This simplifies the portability of hooking this predicate interface across
 * architectures, because basically all hooking mechanisms know how to get at
 * the first integer argument. Passing in floating point values, or 64-bit
 * integers on 32-bit architectures, can be more subtle. */

DEEPSTATE_INLINE static int DeepState_IsSymbolicInt(int x) {
  return DeepState_IsSymbolicUInt((uint32_t) x);
}

DEEPSTATE_INLINE static int DeepState_IsSymbolicUShort(uint16_t x) {
  return DeepState_IsSymbolicUInt((uint32_t) x);
}

DEEPSTATE_INLINE static int DeepState_IsSymbolicShort(int16_t x) {
  return DeepState_IsSymbolicUInt((uint32_t) (uint16_t) x);
}

DEEPSTATE_INLINE static int DeepState_IsSymbolicUChar(unsigned char x) {
  return DeepState_IsSymbolicUInt((uint32_t) x);
}

DEEPSTATE_INLINE static int DeepState_IsSymbolicChar(char x) {
  return DeepState_IsSymbolicUInt((uint32_t) (unsigned char) x);
}

DEEPSTATE_INLINE static int DeepState_IsSymbolicUInt64(uint64_t x) {
  return DeepState_IsSymbolicUInt((uint32_t) x) ||
         DeepState_IsSymbolicUInt((uint32_t) (x >> 32U));
}

DEEPSTATE_INLINE static int DeepState_IsSymbolicInt64(int64_t x) {
  return DeepState_IsSymbolicUInt64((uint64_t) x);
}

DEEPSTATE_INLINE static int DeepState_IsSymbolicBool(int x) {
  return DeepState_IsSymbolicInt(x);
}

DEEPSTATE_INLINE static int DeepState_IsSymbolicFloat(float x) {
  return DeepState_IsSymbolicUInt(*((uint32_t *) &x));
}

DEEPSTATE_INLINE static int DeepState_IsSymbolicDouble(double x) {
  return DeepState_IsSymbolicUInt64(*((uint64_t *) &x));
}

/* Used to define the entrypoint of a test case. */
#define DeepState_EntryPoint(test_name) \
    _DeepState_EntryPoint(test_name, __FILE__, __LINE__)

/* Contains information about a test case */
struct DeepState_TestInfo {
  struct DeepState_TestInfo *prev;
  void (*test_func)(void);
  const char *test_name;
  const char *file_name;
  unsigned line_number;
};

/* Pointer to the last registered `TestInfo` structure. */
extern struct DeepState_TestInfo *DeepState_LastTestInfo;

/* Defines the entrypoint of a test case. This creates a data structure that
 * contains the information about the test, and then creates an initializer
 * function that runs before `main` that registers the test entrypoint with
 * DeepState. */
#define _DeepState_EntryPoint(test_name, file, line) \
    static void DeepState_Test_ ## test_name (void); \
    static void DeepState_Run_ ## test_name (void) { \
      DeepState_Test_ ## test_name(); \
      DeepState_Pass(); \
    } \
    static struct DeepState_TestInfo DeepState_Info_ ## test_name = { \
      NULL, \
      DeepState_Run_ ## test_name, \
      DEEPSTATE_TO_STR(test_name), \
      file, \
      line, \
    }; \
    DEEPSTATE_INITIALIZER(DeepState_Register_ ## test_name) { \
      DeepState_Info_ ## test_name.prev = DeepState_LastTestInfo; \
      DeepState_LastTestInfo = &(DeepState_Info_ ## test_name); \
    } \
    void DeepState_Test_ ## test_name(void)

/* Set up DeepState. */
extern void DeepState_Setup(void);

/* Tear down DeepState. */
extern void DeepState_Teardown(void);

/* Notify that we're about to begin a test while running under Dr. Fuzz. */
extern void DeepState_BeginDrFuzz(struct DeepState_TestInfo *info);

/* Notify that we're about to begin a test. */
extern void DeepState_Begin(struct DeepState_TestInfo *info);

/* Return the first test case to run. */
extern struct DeepState_TestInfo *DeepState_FirstTest(void);

/* Returns 1 if a failure was caught, otherwise 0. */
extern int DeepState_CatchFail(void);

/* Returns 1 if this test case was abandoned. */
extern int DeepState_CatchAbandoned(void);

/* Jump buffer for returning to `DeepState_Run`. */
extern jmp_buf DeepState_ReturnToRun;

/* Start DeepState and run the tests. Returns the number of failed tests. */
static int DeepState_Run(void) {
  int num_failed_tests = 0;
  int use_drfuzz = getenv("DYNAMORIO_EXE_PATH") != NULL;
  struct DeepState_TestInfo *test = NULL;

  DeepState_Setup();

  for (test = DeepState_FirstTest(); test != NULL; test = test->prev) {
    if (use_drfuzz) {
      if (!fork()) {
        DeepState_BeginDrFuzz(test);
      } else {
        continue;
      }
    } else {
      DeepState_Begin(test);
    }
    /* Run the test. */
    if (!setjmp(DeepState_ReturnToRun)) {
      
      /* Convert uncaught C++ exceptions into a test failure. */
#if defined(__cplusplus) && defined(__cpp_exceptions)
      try {
#endif  /* __cplusplus */

      test->test_func();  /* Run the test function. */
      DeepState_Pass();

#if defined(__cplusplus) && defined(__cpp_exceptions)
      } catch(...) {
        DeepState_Fail();
      }
#endif  /* __cplusplus */


    /* We caught a failure when running the test. */
    } else if (DeepState_CatchFail()) {
      ++num_failed_tests;
      DeepState_LogFormat(DeepState_LogError, "Failed: %s", test->test_name);

    /* The test was abandoned. We may have gotten soft failures before
     * abandoning, so we prefer to catch those first. */
    } else if (DeepState_CatchAbandoned()) {
      DeepState_LogFormat(DeepState_LogFatal, "Abandoned: %s", test->test_name);

    /* The test passed. */
    } else {
      DeepState_LogFormat(DeepState_LogInfo, "Passed: %s", test->test_name);
    }
  }

  if (use_drfuzz) {
    waitpid(-1, NULL, 0);  /* Wait for all children. */
  }

  DeepState_Teardown();

  return num_failed_tests;
}

DEEPSTATE_END_EXTERN_C

#endif  /* SRC_INCLUDE_DEEPSTATE_DEEPSTATE_H_ */
