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
#include "deepstate/Option.h"
#include "deepstate/Log.h"

#include <assert.h>
#include <limits.h>
#include <setjmp.h>
#include <stdio.h>

DEEPSTATE_BEGIN_EXTERN_C

DEFINE_uint(num_workers, 1,
            "Number of workers to spawn for testing and test generation.");

DEFINE_string(input_test_dir, "", "Directory of saved tests to run.");
DEFINE_string(input_which_test, "", "Test to use with --input_test_file or --input_test_files_dir.");
DEFINE_string(input_test_file, "", "Saved test to run.");
DEFINE_string(input_test_files_dir, "", "Directory of saved test files to run (flat structure).");
DEFINE_string(output_test_dir, "", "Directory where tests will be saved.");

DEFINE_bool(take_over, false, "Replay test cases in take-over mode.");
DEFINE_bool(abort_on_fail, false, "Abort on file replay failure (useful in file fuzzing).");
DEFINE_bool(verbose_reads, false, "Report on bytes being read during execution of test.");
DEFINE_bool(fuzz, false, "Perform brute force unguided fuzzing.");

DEFINE_int(log_level, 0, "Minimum level of logging to output.");
DEFINE_int(seed, 0, "Seed for brute force fuzzing (uses time if not set).");
DEFINE_int(timeout, 120, "Timeout for brute force fuzzing.")

/* Set to 1 by Manticore/Angr/etc. when we're running symbolically. */
int DeepState_UsingSymExec = 0;

/* Set to 1 when we're using libFuzzer. */
int DeepState_UsingLibFuzzer = 0;

/* Pointer to the last registers DeepState_TestInfo data structure */
struct DeepState_TestInfo *DeepState_LastTestInfo = NULL;

/* Pointer to the test being run in this process by Dr. Fuzz. */
static struct DeepState_TestInfo *DeepState_DrFuzzTest = NULL;

/* Initialize global input buffer and index. */
volatile uint8_t DeepState_Input[DeepState_InputSize] = {};
uint32_t DeepState_InputIndex = 0;

/* Jump buffer for returning to `DeepState_Run`. */
jmp_buf DeepState_ReturnToRun = {};

/* Information about the current test run, if any. */
static struct DeepState_TestRunInfo *DeepState_CurrentTestRun = NULL;

static void DeepState_SetTestPassed(void) {
  DeepState_CurrentTestRun->result = DeepState_TestRunPass;
}

static void DeepState_SetTestFailed(void) {
  DeepState_CurrentTestRun->result = DeepState_TestRunFail;
}

static void DeepState_SetTestAbandoned(const char *reason) {
  DeepState_CurrentTestRun->result = DeepState_TestRunAbandon;
  DeepState_CurrentTestRun->reason = reason;
}

void DeepState_AllocCurrentTestRun(void) {
  int mem_prot = PROT_READ | PROT_WRITE;
  int mem_vis = MAP_ANONYMOUS | MAP_SHARED;
  void *shared_mem = mmap(NULL, sizeof(struct DeepState_TestRunInfo), mem_prot,
                          mem_vis, 0, 0);

  if (shared_mem == MAP_FAILED) {
    DeepState_Log(DeepState_LogError, "Unable to map shared memory.");
    exit(1);
  }

  DeepState_CurrentTestRun = (struct DeepState_TestRunInfo *) shared_mem;
}

static void DeepState_InitCurrentTestRun(struct DeepState_TestInfo *test) {
  DeepState_CurrentTestRun->test = test;
  DeepState_CurrentTestRun->result = DeepState_TestRunPass;
  DeepState_CurrentTestRun->reason = NULL;
}

/* Abandon this test. We've hit some kind of internal problem. */
DEEPSTATE_NORETURN
void DeepState_Abandon(const char *reason) {
  DeepState_Log(DeepState_LogError, reason);

  DeepState_CurrentTestRun->result = DeepState_TestRunAbandon;
  DeepState_CurrentTestRun->reason = reason;

  longjmp(DeepState_ReturnToRun, 1);
}

/* Mark this test as having crashed. */
void DeepState_Crash(void) {
  DeepState_SetTestFailed();
}

/* Mark this test as failing. */
DEEPSTATE_NORETURN
void DeepState_Fail(void) {
  DeepState_SetTestFailed();

  if (FLAGS_take_over) {
    // We want to communicate the failure to a parent process, so exit.
    exit(DeepState_TestRunFail);
  } else {
    longjmp(DeepState_ReturnToRun, 1);
  }
}

/* Mark this test as passing. */
DEEPSTATE_NORETURN
void DeepState_Pass(void) {
  longjmp(DeepState_ReturnToRun, 0);
}

void DeepState_SoftFail(void) {
  DeepState_SetTestFailed();
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
      if (FLAGS_verbose_reads) {
        printf("Reading byte at %u\n", DeepState_InputIndex);
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
  if (NULL == str) {
    DeepState_Abandon("Can't allocate memory.");
  }
  if (len) {
    DeepState_SymbolizeData(str, &(str[len - 1]));
  }
  str[len] = '\0';
  return str;
}

/* Symbolize a C string */
void DeepState_SymbolizeCStr(char *begin) {
  if (begin && begin[0]) {
    DeepState_SymbolizeData(begin, begin + strlen(begin));
  }
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

/* Always returns `0`. */
int DeepState_ZeroSink(int sink) {
  (void) sink;
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
  if (FLAGS_verbose_reads) {
    printf("Reading byte as boolean at %u\n", DeepState_InputIndex);
  }  
  return DeepState_Input[DeepState_InputIndex++] & 1;
}

#define MAKE_SYMBOL_FUNC(Type, type) \
    type DeepState_ ## Type(void) { \
      if ((DeepState_InputIndex + sizeof(type)) > DeepState_InputSize) { \
        DeepState_Abandon("Read too many symbols"); \
      } \
      type val = 0; \
      if (FLAGS_verbose_reads) { \
        printf("STARTING MULTI-BYTE READ\n"); \
      } \
      _Pragma("unroll") \
      for (size_t i = 0; i < sizeof(type); ++i) { \
        if (FLAGS_verbose_reads) { \
          printf("Reading byte at %u\n", DeepState_InputIndex); \
        } \
        val = (val << 8) | ((type) DeepState_Input[DeepState_InputIndex++]); \
      } \
      if (FLAGS_verbose_reads) { \
        printf("FINISHED MULTI-BYTE READ\n"); \
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

/* Returns the minimum satisfiable value for a given symbolic value, given
 * the constraints present on that value. */
uint32_t DeepState_MinUInt(uint32_t v) {
  return v;
}

int32_t DeepState_MinInt(int32_t v) {
  return (int32_t) (DeepState_MinUInt(((uint32_t) v) + 0x80000000U) -
                    0x80000000U);
}

/* Returns the maximum satisfiable value for a given symbolic value, given
 * the constraints present on that value. */
uint32_t DeepState_MaxUInt(uint32_t v) {
  return v;
}

int32_t DeepState_MaxInt(int32_t v) {
  return (int32_t) (DeepState_MaxUInt(((uint32_t) v) + 0x80000000U) -
                    0x80000000U);
}

void _DeepState_Assume(int expr, const char *expr_str, const char *file,
                       unsigned line) {
  if (!expr) {
    DeepState_LogFormat(DeepState_LogError,
                        "%s(%u): Assumption %s failed",
                        file, line, expr_str);    
    DeepState_Abandon("Assumption failed");
  }
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
  {"Crash",           (void *) DeepState_Crash},
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
  {"MinUInt",         (void *) DeepState_MinUInt},
  {"MaxUInt",         (void *) DeepState_MaxUInt},

  /* Logging API. */
  {"Log",             (void *) DeepState_Log},

  /* Streaming API for deferred logging. */
  {"ClearStream",     (void *) DeepState_ClearStream},
  {"LogStream",       (void *) DeepState_LogStream},
  {"StreamInt",       (void *) _DeepState_StreamInt},
  {"StreamFloat",     (void *) _DeepState_StreamFloat},
  {"StreamString",    (void *) _DeepState_StreamString},

  {"UsingLibFuzzer", (void *) &DeepState_UsingLibFuzzer},
  {"UsingSymExec", (void *) &DeepState_UsingSymExec},

  {NULL, NULL},
};

/* Set up DeepState. */
DEEPSTATE_NOINLINE
void DeepState_Setup(void) {
  static int was_setup = 0;
  if (!was_setup) {
    DeepState_AllocCurrentTestRun();
    was_setup = 1;
  }

  /* TODO(pag): Sort the test cases by file name and line number. */
}

/* Tear down DeepState. */
void DeepState_Teardown(void) {

}

/* Notify that we're about to begin a test. */
void DeepState_Begin(struct DeepState_TestInfo *test) {
  DeepState_InitCurrentTestRun(test);
  DeepState_LogFormat(DeepState_LogInfo, "Running: %s from %s(%u)",
                      test->test_name, test->file_name, test->line_number);
}

/* Save a failing test. */

/* Runs in a child process, under the control of Dr. Memory */
void DrMemFuzzFunc(volatile uint8_t *buff, size_t size) {
  struct DeepState_TestInfo *test = DeepState_DrFuzzTest;
  DeepState_InputIndex = 0;
  DeepState_InitCurrentTestRun(test);
  DeepState_LogFormat(DeepState_LogInfo, "Running: %s from %s(%u)",
                      test->test_name, test->file_name, test->line_number);

  if (!setjmp(DeepState_ReturnToRun)) {
    /* Convert uncaught C++ exceptions into a test failure. */
#if defined(__cplusplus) && defined(__cpp_exceptions)
    try {
#endif  /* __cplusplus */

    test->test_func();
    DeepState_Pass();

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

  /* The test was abandoned. We may have gotten soft failures before
   * abandoning, so we prefer to catch those first. */
  } else if (DeepState_CatchAbandoned()) {
    DeepState_LogFormat(DeepState_LogError, "Abandoned: %s", test->test_name);

  /* The test passed. */
  } else {
    DeepState_LogFormat(DeepState_LogInfo, "Passed: %s", test->test_name);
    if (HAS_FLAG_output_test_dir) {
      DeepState_SavePassingTest();
    }
  }
}

void DeepState_RunSavedTakeOverCases(jmp_buf env,
                                     struct DeepState_TestInfo *test) {
  int num_failed_tests = 0;
  const char *test_case_dir = FLAGS_input_test_dir;

  DIR *dir_fd = opendir(test_case_dir);
  if (dir_fd == NULL) {
    DeepState_LogFormat(DeepState_LogInfo,
                        "Skipping test `%s`, no saved test cases",
                        test->test_name);
    return;
  }

  struct dirent *dp;

  /* Read generated test cases and run a test for each file found. */
  while ((dp = readdir(dir_fd)) != NULL) {
    if (DeepState_IsTestCaseFile(dp->d_name)) {
      DeepState_InitCurrentTestRun(test);

      pid_t case_pid = fork();
      if (!case_pid) {
        DeepState_Begin(test);

        size_t path_len = 2 + sizeof(char) * (strlen(test_case_dir) +
                                              strlen(dp->d_name));
        char *path = (char *) malloc(path_len);
        if (path == NULL) {
          DeepState_Abandon("Error allocating memory");
        }
        snprintf(path, path_len, "%s/%s", test_case_dir, dp->d_name);
        DeepState_InitInputFromFile(path);
        free(path);

        longjmp(env, 1);
      }

      int wstatus;
      waitpid(case_pid, &wstatus, 0);

      /* If we exited normally, the status code tells us if the test passed. */
      if (WIFEXITED(wstatus)) {
        switch (DeepState_CurrentTestRun->result) {
        case DeepState_TestRunPass:
          DeepState_LogFormat(DeepState_LogInfo,
                              "Passed: TakeOver test with data from `%s`",
                              dp->d_name);
          break;
        case DeepState_TestRunFail:
          DeepState_LogFormat(DeepState_LogError,
                              "Failed: TakeOver test with data from `%s`",
                              dp->d_name);
          break;
        case DeepState_TestRunCrash:
          DeepState_LogFormat(DeepState_LogError,
                              "Crashed: TakeOver test with data from `%s`",
                              dp->d_name);
          break;
        case DeepState_TestRunAbandon:
          DeepState_LogFormat(DeepState_LogError,
                              "Abandoned: TakeOver test with data from `%s`",
                              dp->d_name);
          break;
        default:  /* Should never happen */
          DeepState_LogFormat(DeepState_LogError,
                              "Error: Invalid test run result %d from `%s`",
                              DeepState_CurrentTestRun->result, dp->d_name);
        }
      } else {
        /* If here, we exited abnormally but didn't catch it in the signal
         * handler, and thus the test failed due to a crash. */
        DeepState_LogFormat(DeepState_LogError,
                            "Crashed: TakeOver test with data from `%s`",
                            dp->d_name);
      }
    }
  }
  closedir(dir_fd);
}

int DeepState_TakeOver(void) {
  struct DeepState_TestInfo test = {
    .prev = NULL,
    .test_func = NULL,
    .test_name = "__takeover_test",
    .file_name = "__takeover_file",
    .line_number = 0,
  };

  DeepState_AllocCurrentTestRun();

  jmp_buf env;
  if (!setjmp(env)) {
    DeepState_RunSavedTakeOverCases(env, &test);
    exit(0);
  }

  return 0;
}

/* Notify that we're about to begin a test while running under Dr. Fuzz. */
void DeepState_BeginDrFuzz(struct DeepState_TestInfo *test) {
  DeepState_DrFuzzTest = test;
  DrMemFuzzFunc(DeepState_Input, DeepState_InputSize);
}

/* Save a passing test to the output test directory. */
void DeepState_SavePassingTest(void) {}

/* Save a failing test to the output test directory. */
void DeepState_SaveFailingTest(void) {}

/* Save a crashing test to the output test directory. */
void DeepState_SaveCrashingTest(void) {}

/* Return the first test case to run. */
struct DeepState_TestInfo *DeepState_FirstTest(void) {
  return DeepState_LastTestInfo;
}

/* Returns `true` if a failure was caught for the current test case. */
bool DeepState_CatchFail(void) {
  return DeepState_CurrentTestRun->result == DeepState_TestRunFail;
}

/* Returns `true` if the current test case was abandoned. */
bool DeepState_CatchAbandoned(void) {
  return DeepState_CurrentTestRun->result == DeepState_TestRunAbandon;
}

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size > sizeof(DeepState_Input)) {
    return 0; // Just ignore any too-big inputs
  }

  DeepState_UsingLibFuzzer = 1;
  
  struct DeepState_TestInfo *test = NULL;

  DeepState_InitOptions(0, "");  
  //DeepState_Setup(); we want to do our own, simpler, memory management
  void *mem = malloc(sizeof(struct DeepState_TestRunInfo));
  DeepState_CurrentTestRun = (struct DeepState_TestRunInfo *) mem;

  test = DeepState_FirstTest();
  const char* which_test = getenv("LIBFUZZER_WHICH_TEST");
  if (which_test != NULL) {
    for (test = DeepState_FirstTest(); test != NULL; test = test->prev) {
      if (strncmp(which_test, test->test_name, strnlen(which_test, 1024)) == 0) {
	break;
      }
    }
  }

  memset((void *) DeepState_Input, 0, sizeof(DeepState_Input));
  DeepState_InputIndex = 0;

  memcpy((void *) DeepState_Input, (void *) Data, Size);

  DeepState_Begin(test);

  enum DeepState_TestRunResult result = DeepState_RunTestLLVM(test);

  const char* abort_check = getenv("LIBFUZZER_ABORT_ON_FAIL");
  if (abort_check != NULL) {
    if ((result == DeepState_TestRunFail) || (result == DeepState_TestRunCrash)) {
      abort();
    }
  }

  DeepState_Teardown();
  DeepState_CurrentTestRun = NULL;
  free(mem);
  
  return 0;  // Non-zero return values are reserved for future use.
}

/* Overwrite libc's abort. */
void abort(void) {
  DeepState_Fail();
}

void __assert_fail(const char * assertion, const char * file,
                   unsigned int line, const char * function) {
  DeepState_LogFormat(DeepState_LogFatal,
                      "%s(%u): Assertion %s failed in function %s",
                      file, line, assertion, function);
  __builtin_unreachable();
}

void __stack_chk_fail(void) {
  DeepState_Log(DeepState_LogFatal, "Stack smash detected.");
  __builtin_unreachable();
}

__attribute__((weak))
int main(int argc, char *argv[]) {
  int ret = 0;
  DeepState_Setup();
  DeepState_InitOptions(argc, argv);
  ret = DeepState_Run();
  DeepState_Teardown();
  return ret;
}

DEEPSTATE_END_EXTERN_C
