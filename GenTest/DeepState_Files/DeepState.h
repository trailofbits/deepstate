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

#ifndef SRC_INCLUDE_DEEPSTATE_DEEPSTATE_H_
#define SRC_INCLUDE_DEEPSTATE_DEEPSTATE_H_

#include <assert.h>
#include <dirent.h>
#include <libgen.h>
#include <setjmp.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <fnmatch.h>
#include <stdio.h>

#include <deepstate/Log.h>
#include <deepstate/Compiler.h>
#include <deepstate/Option.h>
#include <deepstate/Stream.h>
#include <deepstate/GenTestBridge.h>

#ifdef assert
# undef assert
#endif

#define assert DeepState_Assert
#define assume DeepState_Assume
#define check DeepState_Check

#ifdef DEEPSTATE_TAKEOVER_RAND
#define rand DeepState_RandInt
#define srand DeepState_Warn_srand
#endif

#ifndef DEEPSTATE_SIZE
#define DEEPSTATE_SIZE 8192
#endif

#ifndef DEEPSTATE_MAX_SWARM_CONFIGS
#define DEEPSTATE_MAX_SWARM_CONFIGS 1024
#endif

#ifndef DEEPSTATE_SWARM_MAX_PROB_RATIO
#define DEEPSTATE_SWARM_MAX_PROB_RATIO 16
#endif

#define MAYBE(...) \
    if (DeepState_Bool()) { \
      __VA_ARGS__ ; \
    }

DEEPSTATE_BEGIN_EXTERN_C

DECLARE_string(input_test_dir);
DECLARE_string(input_source_file);
DECLARE_string(input_translation_config);
DECLARE_string(input_test_file);
DECLARE_string(input_test_files_dir);
DECLARE_string(input_which_test);
DECLARE_string(output_test_dir);
DECLARE_string(output_standalone_test);
DECLARE_string(output_num);
DECLARE_string(test_filter);

DECLARE_bool(take_over);
DECLARE_bool(abort_on_fail);
DECLARE_bool(exit_on_fail);
DECLARE_bool(verbose_reads);
DECLARE_bool(fuzz);
DECLARE_bool(fuzz_save_passing);
DECLARE_bool(fork);
DECLARE_bool(list_tests);
DECLARE_bool(boring_only);
DECLARE_bool(run_disabled);

DECLARE_int(min_log_level);
DECLARE_int(seed);
DECLARE_int(timeout);


enum {
  DeepState_InputSize = DEEPSTATE_SIZE
};


/* Byte buffer that will contain symbolic data that is used to supply requests
 * for symbolic values (e.g. `int`s). */
extern volatile uint8_t DeepState_Input[DeepState_InputSize];

/* Index into the `DeepState_Input` array that tracks how many input bytes have
 * been consumed. */
extern uint32_t DeepState_InputIndex;

enum DeepState_SwarmType {
  DeepState_SwarmTypePure = 0,
  DeepState_SwarmTypeMixed = 1,
  DeepState_SwarmTypeProb = 2
};

/* Contains info about a swarm configuration */
struct DeepState_SwarmConfig {
  char* file;
  unsigned line;
  unsigned orig_fcount;
  /* We identify a configuration by these first three elements of the struct */

  /* These fields allow us to map choices to the restricted configuration */
  unsigned fcount;
  unsigned* fmap;
};

/* Index into the set of swarm configurations. */
extern uint32_t DeepState_SwarmConfigsIndex;

/* Function to return a swarm configuration. */
extern struct DeepState_SwarmConfig* DeepState_GetSwarmConfig(unsigned fcount, const char* file, unsigned line, enum DeepState_SwarmType stype);

/* Return a symbolic value of a given type. */
extern int DeepState_Bool(void);
extern size_t DeepState_Size(void);
extern long DeepState_Long(void);
extern float DeepState_Float(void);
extern double DeepState_Double(void);
extern uint64_t DeepState_UInt64(void);
extern int64_t DeepState_Int64(void);
extern uint32_t DeepState_UInt(void);
extern int32_t DeepState_Int(void);
extern int32_t DeepState_RandInt(void);
extern uint16_t DeepState_UShort(void);
extern int16_t DeepState_Short(void);
extern uint8_t DeepState_UChar(void);
extern int8_t DeepState_Char(void);

/* Returns the minimum satisfiable value for a given symbolic value, given
 * the constraints present on that value. */
extern uint32_t DeepState_MinUInt(uint32_t);
extern int32_t DeepState_MinInt(int32_t);

extern uint32_t DeepState_MaxUInt(uint32_t);
extern int32_t DeepState_MaxInt(int32_t);

DEEPSTATE_INLINE static uint16_t DeepState_MinUShort(uint16_t v) {
  return DeepState_MinUInt(v);
}

DEEPSTATE_INLINE static uint8_t DeepState_MinUChar(uint8_t v) {
  return (uint8_t) DeepState_MinUInt(v);
}

DEEPSTATE_INLINE static int16_t DeepState_MinShort(int16_t v) {
  return (int16_t) DeepState_MinInt(v);
}

DEEPSTATE_INLINE static int8_t DeepState_MinChar(int8_t v) {
  return (int8_t) DeepState_MinInt(v);
}

DEEPSTATE_INLINE static uint16_t DeepState_MaxUShort(uint16_t v) {
  return (uint16_t) DeepState_MaxUInt(v);
}

DEEPSTATE_INLINE static uint8_t DeepState_MaxUChar(uint8_t v) {
  return (uint8_t) DeepState_MaxUInt(v);
}

DEEPSTATE_INLINE static int16_t DeepState_MaxShort(int16_t v) {
  return (int16_t) DeepState_MaxInt(v);
}

DEEPSTATE_INLINE static int8_t DeepState_MaxChar(int8_t v) {
  return (int8_t) DeepState_MaxInt(v);
}

/* Function to clean up generated strings, and any other DeepState-managed data. */
extern void DeepState_CleanUp();

/* Returns `1` if `expr` is true, and `0` otherwise. This is kind of an indirect
 * way to take a symbolic value, introduce a fork, and on each size, replace its
 * value with a concrete value. */
extern int DeepState_IsTrue(int expr);

/* Always returns `1`. */
extern int DeepState_One(void);

/* Always returns `0`. */
extern int DeepState_Zero(void);

/* Always returns `0`. */
extern int DeepState_ZeroSink(int);

/* Symbolize the data in the exclusive range `[begin, end)`. */
extern void DeepState_SymbolizeData(void *begin, void *end);

/* Symbolize the data in the exclusive range `[begin, end)` with no nulls. */
extern void DeepState_SymbolizeDataNoNull(void *begin, void *end);

/* Concretize some data in exclusive the range `[begin, end)`. Returns a
 * concrete pointer to the beginning of the concretized data. */
extern void *DeepState_ConcretizeData(void *begin, void *end);

/* Assign a symbolic C string of _strlen_ `len` -- with only chars in allowed,
 * if `allowed` is non-null; needs space for null + len bytes */
extern void DeepState_AssignCStr_C(char* str, size_t len, const char* allowed);

/* Assign a symbolic C string of _strlen_ `len` -- with only chars in allowed,
 * if `allowed` is non-null; needs space for null + len bytes */
extern void DeepState_SwarmAssignCStr_C(const char* file, unsigned line, int mix,
					char* str, size_t len, const char* allowed);

/* Return a symbolic C string of strlen `len`. */
extern char *DeepState_CStr_C(size_t len, const char* allowed);

/* Return a symbolic C string of strlen `len`. */
extern char *DeepState_SwarmCStr_C(const char* file, unsigned line, int mix,
				   size_t len, const char* allowed);

/* Symbolize a C string */
void DeepState_SymbolizeCStr_C(char *begin, const char* allowed);

/* Symbolize a C string */
void DeepState_SwarmSymbolizeCStr_C(const char* file, unsigned line, int mix,
				    char *begin, const char* allowed);

/* Concretize a C string. Returns a pointer to the beginning of the
 * concretized C string. */
extern const char *DeepState_ConcretizeCStr(const char *begin);

/* Allocate and return a pointer to `num_bytes` symbolic bytes. */
extern void *DeepState_Malloc(size_t num_bytes);

/* Returns the path to a testcase without parsing to any aforementioned types */
extern const char *DeepState_InputPath(char *testcase_path);

/* Portable and architecture-independent memory scrub without dead store elimination. */
extern void *DeepState_MemScrub(void *pointer, size_t data_size);

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

/* Result of a single forked test run.
 *
 * Will be passed to the parent process as an exit code. */
enum DeepState_TestRunResult {
  DeepState_TestRunPass = 0,
  DeepState_TestRunFail = 1,
  DeepState_TestRunCrash = 2,
  DeepState_TestRunAbandon = 3,
};

/* Abandon this test. We've hit some kind of internal problem. */
DEEPSTATE_NORETURN
extern void DeepState_Abandon(const char *reason);

/* Mark this test as having crashed. */
extern void DeepState_Crash(void);

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

/* Used to make DeepState really crash for fuzzers, on any platform. */
DEEPSTATE_INLINE static void DeepState_HardCrash() {
  raise(SIGABRT);
}

/* Asserts that `expr` must hold. If it does not, then the test fails, but
 * nonetheless continues on. */
DEEPSTATE_INLINE static void DeepState_Check(int expr) {
  if (!expr) {
    DeepState_SoftFail();
  }
}

/* Return a symbolic value in a the range `[low_inc, high_inc]`. */
/* Saturating version here is an alternative, but worse for fuzzing:
#define DEEPSTATE_MAKE_SYMBOLIC_RANGE(Tname, tname) \
    DEEPSTATE_INLINE static tname DeepState_ ## Tname ## InRange( \
        tname low, tname high) { \
      if (low > high) { \
        return DeepState_ ## Tname ## InRange(high, low); \
      } \
      const tname x = DeepState_ ## Tname(); \
      if (DeepState_UsingSymExec) { \
        (void) DeepState_Assume(low <= x && x <= high); \
        return x; \
      } \
      if (x < low) { \
        return low; \
      } else if (x > high) { \
        return high; \
      } else { \
        return x; \
      } \
    }
*/
#define DEEPSTATE_MAKE_SYMBOLIC_RANGE(Tname, tname) \
    DEEPSTATE_INLINE static tname DeepState_ ## Tname ## InRange( \
        tname low, tname high) { \
      if (low > high) { \
        return DeepState_ ## Tname ## InRange(high, low); \
      } \
      if (low == high) { \
        return low;	 \
      } \
      tname x = DeepState_ ## Tname(); \
      if (DeepState_UsingSymExec) { \
        (void) DeepState_Assume(low <= x && x <= high); \
        return x;					\
      } \
      if (FLAGS_verbose_reads) { \
        printf("Range read low %lld high %lld\n", (long long)low, (long long)high); \
      } \
      if ((x < low) || (x > high)) { \
        const tname size = (high - low) + 1; \
        if (x < 0) x = -x;		     \
        if (x < 0) x = 0;		     \
        if (FLAGS_verbose_reads) { \
          printf("Converting out-of-range value to %lld\n", (long long)(low + (x % size))); \
        } \
        return low + (x % size); \
      } \
      return x; \
    }

DEEPSTATE_MAKE_SYMBOLIC_RANGE(Size, size_t)
DEEPSTATE_MAKE_SYMBOLIC_RANGE(Long, long)
DEEPSTATE_MAKE_SYMBOLIC_RANGE(Int64, int64_t)
DEEPSTATE_MAKE_SYMBOLIC_RANGE(UInt64, uint64_t)
DEEPSTATE_MAKE_SYMBOLIC_RANGE(Int, int)
DEEPSTATE_MAKE_SYMBOLIC_RANGE(UInt, uint32_t)
DEEPSTATE_MAKE_SYMBOLIC_RANGE(Short, int16_t)
DEEPSTATE_MAKE_SYMBOLIC_RANGE(UShort, uint16_t)
DEEPSTATE_MAKE_SYMBOLIC_RANGE(Char, char)
DEEPSTATE_MAKE_SYMBOLIC_RANGE(UChar, unsigned char)

#undef DEEPSTATE_MAKE_SYMBOLIC_RANGE

extern float DeepState_FloatInRange(float low, float high);
extern double DeepState_DoubleInRange(double low, double high);

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

struct DeepState_TestRunInfo {
  struct DeepState_TestInfo *test;
  enum DeepState_TestRunResult result;
  const char *reason;
};

/* Pointer to the last registered `TestInfo` structure. */
extern struct DeepState_TestInfo *DeepState_LastTestInfo;

/* Pointer to first structure of ordered `TestInfo` list (reverse of LastTestInfo). */
extern struct DeepState_TestInfo *DeepState_FirstTestInfo;

extern int DeepState_TakeOver(void);

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

/* Returns `true` if a failure was caught for the current test case. */
extern bool DeepState_CatchFail(void);

/* Returns `true` if the current test case was abandoned. */
extern bool DeepState_CatchAbandoned(void);

/* Save a passing test to the output test directory. */
extern void DeepState_SavePassingTest(void);

/* Save a failing test to the output test directory. */
extern void DeepState_SaveFailingTest(void);

/* Save a crashing test to the output test directory. */
extern void DeepState_SaveCrashingTest(void);

/* Jump buffer for returning to `DeepState_Run`. */
extern jmp_buf DeepState_ReturnToRun;

/* Checks a filename to see if might be a saved test case.
 *
 * Valid saved test cases have the suffix `.pass` or `.fail`. */
static bool DeepState_IsTestCaseFile(const char *name) {
  const char *suffix = strchr(name, '.');
  if (suffix == NULL) {
    return false;
  }

  const char *extensions[] = {
    ".pass",
    ".fail",
    ".crash",
  };
  const size_t ext_count = sizeof(extensions) / sizeof(char *);

  for (size_t i = 0; i < ext_count; i++) {
    if (!strcmp(suffix, extensions[i])) {
      return true;
    }
  }

  return false;
}

extern void DeepState_Warn_srand(unsigned int seed);

/* Resets the global `DeepState_Input` buffer, then fills it with the
 * data found in the file `path`. */
static void DeepState_InitInputFromFile(const char *path) {
  struct stat stat_buf;

  FILE *fp = fopen(path, "r");
  if (fp == NULL) {
    /* TODO(joe): Add error log with more info. */
    DeepState_Abandon("Unable to open file");
  }

  int fd = fileno(fp);
  if (fd < 0) {
    DeepState_Abandon("Tried to get file descriptor for invalid stream");
  }
  if (fstat(fd, &stat_buf) < 0) {
    DeepState_Abandon("Unable to access input file");
  };

  size_t to_read = stat_buf.st_size;

  if (stat_buf.st_size > sizeof(DeepState_Input)) {
    DeepState_LogFormat(DeepState_LogWarning, "File too large, truncating to max input size");
    to_read = DeepState_InputSize;
  }

  /* Reset the input buffer and reset the index. */
  DeepState_MemScrub((void *) DeepState_Input, sizeof(DeepState_Input));
  DeepState_InputIndex = 0;
  DeepState_SwarmConfigsIndex = 0;

  size_t count = fread((void *) DeepState_Input, 1, to_read, fp);
  fclose(fp);

  if (count != to_read) {
    /* TODO(joe): Add error log with more info. */
    DeepState_Abandon("Error reading file");
  }

  DeepState_LogFormat(DeepState_LogTrace,
                      "Initialized test input buffer with data from `%s`",
                      path);
}

/* Run a test case, assuming we have forked from the test harness to do so.
 *
 * An exit code of 0 indicates that the test passed. Any other exit
 * code, or termination by a signal, indicates a test failure. */
static void DeepState_RunTest(struct DeepState_TestInfo *test) {
  /* Run the test. */
  if (!setjmp(DeepState_ReturnToRun)) {
    /* Convert uncaught C++ exceptions into a test failure. */
#if defined(__cplusplus) && defined(__cpp_exceptions)
    try {
#endif  /* __cplusplus */

      test->test_func();  /* Run the test function. */
      exit(DeepState_TestRunPass);

#if defined(__cplusplus) && defined(__cpp_exceptions)
    } catch(...) {
      DeepState_Fail();
    }
#endif  /* __cplusplus */

    /* We caught a failure when running the test. */
  } else if (DeepState_CatchFail()) {
    DeepState_LogFormat(DeepState_LogError, "Failed: %s", test->test_name);
    if (HAS_FLAG_output_test_dir) {
      DeepState_SaveFailingTest();
    }
    exit(DeepState_TestRunFail);

    /* The test was abandoned. We may have gotten soft failures before
     * abandoning, so we prefer to catch those first. */
  } else if (DeepState_CatchAbandoned()) {
    DeepState_LogFormat(DeepState_LogError, "Abandoned: %s", test->test_name);
    exit(DeepState_TestRunAbandon);

    /* The test passed. */
  } else {
    DeepState_LogFormat(DeepState_LogTrace, "Passed: %s", test->test_name);
    if (HAS_FLAG_output_test_dir) {
      if (!FLAGS_fuzz || FLAGS_fuzz_save_passing) {
	DeepState_SavePassingTest();
      }
    }
    exit(DeepState_TestRunPass);
  }
}

/* Run a test case, but in libFuzzer, so not inside a fork. */
static int DeepState_RunTestNoFork(struct DeepState_TestInfo *test) {
  /* Run the test. */
  if (!setjmp(DeepState_ReturnToRun)) {
    /* Convert uncaught C++ exceptions into a test failure. */
#if defined(__cplusplus) && defined(__cpp_exceptions)
    try {
#endif  /* __cplusplus */

      test->test_func();  /* Run the test function. */
      return(DeepState_TestRunPass);

#if defined(__cplusplus) && defined(__cpp_exceptions)
    } catch(...) {
      DeepState_Fail();
    }
#endif  /* __cplusplus */

    /* We caught a failure when running the test. */
  } else if (DeepState_CatchFail()) {
    DeepState_LogFormat(DeepState_LogError, "Failed: %s", test->test_name);
    if (HAS_FLAG_output_test_dir) {
      DeepState_SaveFailingTest();
    }
    if (HAS_FLAG_abort_on_fail) {
      DeepState_HardCrash();
    }
    return(DeepState_TestRunFail);

    /* The test was abandoned. We may have gotten soft failures before
     * abandoning, so we prefer to catch those first. */
  } else if (DeepState_CatchAbandoned()) {
    DeepState_LogFormat(DeepState_LogError, "Abandoned: %s", test->test_name);
    return(DeepState_TestRunAbandon);

    /* The test passed. */
  } else {
    DeepState_LogFormat(DeepState_LogTrace, "Passed: %s", test->test_name);
    if (HAS_FLAG_output_test_dir) {
      if (!FLAGS_fuzz || FLAGS_fuzz_save_passing) {
	DeepState_SavePassingTest();
      }
    }
    return(DeepState_TestRunPass);
  }
}

/* Fork and run `test`. */
static enum DeepState_TestRunResult
DeepState_ForkAndRunTest(struct DeepState_TestInfo *test) {
  pid_t test_pid;
  if (FLAGS_fork) {
    test_pid = fork();
    if (!test_pid) {
      DeepState_RunTest(test);
      /* No need to clean up in a fork; exit() is the ultimate garbage collector */
    }
  }
  int wstatus = 0;
  if (FLAGS_fork) {
    waitpid(test_pid, &wstatus, 0);
  } else {
    wstatus = DeepState_RunTestNoFork(test);
    DeepState_CleanUp();
  }

  /* If we exited normally, the status code tells us if the test passed. */
  if (!FLAGS_fork) {
    return (enum DeepState_TestRunResult) wstatus;
  } else if (WIFEXITED(wstatus)) {
    uint8_t status = WEXITSTATUS(wstatus);
    return (enum DeepState_TestRunResult) status;
  }

  /* If here, we exited abnormally but didn't catch it in the signal
   * handler, and thus the test failed due to a crash. */
  return DeepState_TestRunCrash;
}

extern enum DeepState_TestRunResult DeepState_FuzzOneTestCase(struct DeepState_TestInfo *test);

/* Run a single saved test case with input initialized from the file
 * `name` in directory `dir`. */
static enum DeepState_TestRunResult
DeepState_RunSavedTestCase(struct DeepState_TestInfo *test, const char *dir,
                           const char *name) {
  if (!setjmp(DeepState_ReturnToRun)) {
    size_t path_len = 2 + sizeof(char) * (strlen(dir) + strlen(name));
    char *path = (char *) malloc(path_len);
    if (path == NULL) {
      DeepState_Abandon("Error allocating memory");
    }
    if (strncmp(dir, "", strlen(dir)) != 0) {
      snprintf(path, path_len, "%s/%s", dir, name);
    } else {
      snprintf(path, path_len, "%s", name);
    }

    DeepState_InitInputFromFile(path);

    DeepState_Begin(test);

    enum DeepState_TestRunResult result = DeepState_ForkAndRunTest(test);

    if (result == DeepState_TestRunFail) {
      DeepState_LogFormat(DeepState_LogError, "Test case %s failed", path);
      free(path);
    }
    else if (result == DeepState_TestRunCrash) {
      DeepState_LogFormat(DeepState_LogError, "Crashed: %s", test->test_name);
      DeepState_LogFormat(DeepState_LogError, "Test case %s crashed", path);
      free(path);
      if (HAS_FLAG_output_test_dir) {
        DeepState_SaveCrashingTest();
      }

      DeepState_Crash();
    } else {
      free(path);
    }

    return result;
  } else {
    DeepState_LogFormat(DeepState_LogError, "Something went wrong running the test case %s", name);
    return DeepState_TestRunCrash;
  }
}

/* Run a single test many times, initialized against each saved test case in
 * `FLAGS_input_test_dir`. */
static int DeepState_RunSavedCasesForTest(struct DeepState_TestInfo *test) {
  int num_failed_tests = 0;
  const char *test_file_name = basename((char *) test->file_name);

  size_t test_case_dir_len = 3 + strlen(FLAGS_input_test_dir)
    + strlen(test_file_name) + strlen(test->test_name);
  char *test_case_dir = (char *) malloc(test_case_dir_len);
  if (test_case_dir == NULL) {
    DeepState_Abandon("Error allocating memory");
  }
  snprintf(test_case_dir, test_case_dir_len, "%s/%s/%s",
           FLAGS_input_test_dir, test_file_name, test->test_name);

  struct dirent *dp;
  DIR *dir_fd;

  dir_fd = opendir(test_case_dir);
  if (dir_fd == NULL) {
    DeepState_LogFormat(DeepState_LogInfo,
                        "Skipping test `%s`, no saved test cases",
                        test->test_name);
    free(test_case_dir);
    return 0;
  }

  unsigned int i = 0;

  /* Read generated test cases and run a test for each file found. */
  while ((dp = readdir(dir_fd)) != NULL) {
    if (DeepState_IsTestCaseFile(dp->d_name)) {
      i++;
      enum DeepState_TestRunResult result =
        DeepState_RunSavedTestCase(test, test_case_dir, dp->d_name);

      if (result != DeepState_TestRunPass) {
        num_failed_tests++;
      }
    }
  }
  closedir(dir_fd);
  free(test_case_dir);

  DeepState_LogFormat(DeepState_LogInfo, "Ran %u tests for %s; %d tests failed",
		      i, test->test_name, num_failed_tests);

  return num_failed_tests;
}

/* Returns a sorted list of all available tests to run, and exits after */
static int DeepState_RunListTests(void) {
  char buff[4096];
  ssize_t write_len = 0;

  int total_test_count = 0;
  int boring_count = 0;
  int disabled_count = 0;

  struct DeepState_TestInfo *current_test = DeepState_FirstTestInfo;

  sprintf(buff, "Available Tests:\n\n");
  write_len = write(STDERR_FILENO, buff, strlen(buff));

  /* Print each test and increment counter from linked list */
  for (; current_test != NULL; current_test = current_test->prev) {

	const char * curr_test = current_test->test_name;

	/* Classify tests */
	if (strstr(curr_test, "Boring") || strstr(curr_test, "BORING")) {
	  boring_count++;
	} else if (strstr(curr_test, "Disabled") || strstr(curr_test, "DISABLED")) {
	  disabled_count++;
	}

    /* TODO(alan): also output file name, luckily its sorted :) */
    sprintf(buff, " *  %s (line %d)\n", curr_test, current_test->line_number);
	write_len = write(STDERR_FILENO, buff, strlen(buff));
    total_test_count++;
  }

  sprintf(buff, "\nBoring Tests: %d\nDisabled Tests: %d\n", boring_count, disabled_count);
  write_len = write(STDERR_FILENO, buff, strlen(buff));

  sprintf(buff, "\nTotal Number of Tests: %d\n", total_test_count);
  write_len = write(STDERR_FILENO, buff, strlen(buff));
  return 0;
}

/* Run test from `FLAGS_input_test_file`, under `FLAGS_input_which_test`
 * or first test, if not defined. */
static int DeepState_RunSingleSavedTestCase(void) {
  int num_failed_tests = 0;
  struct DeepState_TestInfo *test = NULL;

  for (test = DeepState_FirstTest(); test != NULL; test = test->prev) {
    if (HAS_FLAG_input_which_test) {
      if (strcmp(FLAGS_input_which_test, test->test_name) == 0) {
        break;
      }
    } else {
      DeepState_LogFormat(DeepState_LogWarning,
			  "No test specified, defaulting to first test defined (%s)",
			  test->test_name);
      break;
    }
  }

  if (test == NULL) {
    DeepState_LogFormat(DeepState_LogInfo,
                        "Could not find matching test for %s",
                        FLAGS_input_which_test);
    return 0;
  }

  enum DeepState_TestRunResult result =
    DeepState_RunSavedTestCase(test, "", FLAGS_input_test_file);

  if ((result == DeepState_TestRunFail) || (result == DeepState_TestRunCrash)) {
    if (FLAGS_abort_on_fail) {
      DeepState_HardCrash();
    }
    if (FLAGS_exit_on_fail) {
      exit(255); // Terminate the testing
    }
    num_failed_tests++;
  }

  DeepState_Teardown();

  return num_failed_tests;
}

extern int DeepState_Fuzz(void);

/* Run tests from `FLAGS_input_test_files_dir`, under `FLAGS_input_which_test`
 * or first test, if not defined. */
static int DeepState_RunSingleSavedTestDir(void) {
  int num_failed_tests = 0;
  struct DeepState_TestInfo *test = NULL;

  if (!HAS_FLAG_min_log_level) {
    FLAGS_min_log_level = 2;
  }

  for (test = DeepState_FirstTest(); test != NULL; test = test->prev) {
    if (HAS_FLAG_input_which_test) {
      if (strcmp(FLAGS_input_which_test, test->test_name) == 0) {
        break;
      }
    } else {
      DeepState_LogFormat(DeepState_LogWarning,
			  "No test specified, defaulting to first test defined (%s)",
			  test->test_name);
      break;
    }
  }

  if (test == NULL) {
    DeepState_LogFormat(DeepState_LogInfo,
                        "Could not find matching test for %s",
                        FLAGS_input_which_test);
    return 0;
  }

  struct dirent *dp;
  DIR *dir_fd;

  struct stat path_stat;

  dir_fd = opendir(FLAGS_input_test_files_dir);
  if (dir_fd == NULL) {
    DeepState_LogFormat(DeepState_LogInfo,
                        "No tests to run");
    return 0;
  }

  unsigned int i = 0;

  /* Read generated test cases and run a test for each file found. */
  while ((dp = readdir(dir_fd)) != NULL) {
    size_t path_len = 2 + sizeof(char) * (strlen(FLAGS_input_test_files_dir) + strlen(dp->d_name));
    char *path = (char *) malloc(path_len);
    snprintf(path, path_len, "%s/%s", FLAGS_input_test_files_dir, dp->d_name);
    stat(path, &path_stat);

    if (S_ISREG(path_stat.st_mode)) {
      i++;
      enum DeepState_TestRunResult result =
        DeepState_RunSavedTestCase(test, FLAGS_input_test_files_dir, dp->d_name);

      if ((result == DeepState_TestRunFail) || (result == DeepState_TestRunCrash)) {
        if (FLAGS_abort_on_fail) {
          DeepState_HardCrash();
        }
        if (FLAGS_exit_on_fail) {
          exit(255); // Terminate the testing
        }
        num_failed_tests++;
      }
    }
  }
  closedir(dir_fd);

  DeepState_LogFormat(DeepState_LogInfo, "Ran %u tests; %d tests failed",
		      i, num_failed_tests);

  return num_failed_tests;
}

/* Run test `FLAGS_input_which_test` with saved input from `FLAGS_input_test_file`.
 *
 * For each test unit and case, see if there are input files in the
 * expected directories. If so, use them to initialize
 * `DeepState_Input`, then run the test. If not, skip the test. */
static int DeepState_RunSavedTestCases(void) {
  int num_failed_tests = 0;
  struct DeepState_TestInfo *test = NULL;

  if (!HAS_FLAG_min_log_level) {
    FLAGS_min_log_level = 2;
  }

  for (test = DeepState_FirstTest(); test != NULL; test = test->prev) {
    num_failed_tests += DeepState_RunSavedCasesForTest(test);
  }

  DeepState_Teardown();

  return num_failed_tests;
}

/* Start DeepState and run the tests. Returns the number of failed tests. */
static int DeepState_Run(void) {
  if (!DeepState_OptionsAreInitialized) {
    DeepState_Abandon("Please call DeepState_InitOptions(argc, argv) in main");
  }

  if (HAS_FLAG_list_tests) {
	return DeepState_RunListTests();
  }

  if (HAS_FLAG_output_standalone_test) {
      return DeepStateCreateStandalone( FLAGS_output_standalone_test,
                                        FLAGS_input_source_file,
                                        FLAGS_input_test_file,
                                        FLAGS_input_translation_config,
					FLAGS_input_test_dir,
					FLAGS_output_num,
					FLAGS_fuzz,
					FLAGS_fuzz && FLAGS_exit_on_fail,
					FLAGS_input_which_test
                                      );
  }

  if (HAS_FLAG_input_test_file) {
    return DeepState_RunSingleSavedTestCase();
  }

  if (HAS_FLAG_input_test_dir) {
    return DeepState_RunSavedTestCases();
  }

  if (HAS_FLAG_input_test_files_dir) {
    return DeepState_RunSingleSavedTestDir();
  }

  if (FLAGS_fuzz) {
    return DeepState_Fuzz();
  }

  int num_failed_tests = 0;
  int use_drfuzz = getenv("DYNAMORIO_EXE_PATH") != NULL;
  struct DeepState_TestInfo *test = NULL;


  for (test = DeepState_FirstTest(); test != NULL; test = test->prev) {

	const char * curr_test = test->test_name;

	/* Run only the Boring* tests */
	if (HAS_FLAG_boring_only) {
	  if (strstr(curr_test, "Boring") || strstr(curr_test, "BORING")) {
        DeepState_Begin(test);
		if (DeepState_ForkAndRunTest(test) != 0) {
		  num_failed_tests++;
		}
	  } else {
		continue;
	  }
	}

	/* Check if pattern match exists in test, skip if not */
	if (HAS_FLAG_test_filter) {
	  if (fnmatch(FLAGS_test_filter, curr_test, FNM_NOESCAPE)) {
	    continue;
	  }
	}

	/* Check if --run_disabled is set, and if not, skip Disabled* tests */
	if (!HAS_FLAG_run_disabled) {
	  if (strstr(curr_test, "Disabled") || strstr(test->test_name, "DISABLED")) {
		continue;
	  }
	}

	/* Check if we should use Dr.Fuzz or run regularly */
	if (use_drfuzz) {
      if (!fork()) {
        DeepState_BeginDrFuzz(test);
      } else {
        continue;
      }
    } else {
	  DeepState_Begin(test);
      if (DeepState_ForkAndRunTest(test) != 0) {
        num_failed_tests++;
      }
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
