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

#include "deepstate/DeepState.h"
#include "deepstate/Option.h"
#include "deepstate/Log.h"
#include "DeepState.h"

#include <assert.h>
#include <limits.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef DEEPSTATE_TAKEOVER_RAND
#undef rand
#undef srand
#endif

DEEPSTATE_BEGIN_EXTERN_C

/* Basic input and output options, specifies files for read/write before and after test analysis */
DEFINE_string(input_test_dir, InputOutputGroup, "", "Directory of saved tests to run.");
DEFINE_string(input_test_file, InputOutputGroup, "", "Saved test to run.");
DEFINE_string(input_test_files_dir, InputOutputGroup, "", "Directory of saved test files to run (flat structure).");
DEFINE_string(output_test_dir, InputOutputGroup, "", "Directory where tests will be saved.");
DEFINE_bool(input_stdin, InputOutputGroup, false, "Run a test from stdin.");

/* Test execution-related options, configures how an execution run is carried out */
DEFINE_bool(take_over, ExecutionGroup, false, "Replay test cases in take-over mode.");
DEFINE_bool(abort_on_fail, ExecutionGroup, false, "Abort on file replay failure (useful in file fuzzing).");
DEFINE_bool(exit_on_fail, ExecutionGroup, false, "Exit with status 255 on test failure.");
DEFINE_bool(verbose_reads, ExecutionGroup, false, "Report on bytes being read during execution of test.");
DEFINE_int(min_log_level, ExecutionGroup, 0, "Minimum level of logging to output (default 0, 0=debug, 1=trace, 2=info, ...).");
DEFINE_int(timeout, ExecutionGroup, 3600, "Timeout for brute force fuzzing.");
DEFINE_uint(num_workers, ExecutionGroup, 1, "Number of workers to spawn for testing and test generation.");
#if defined(_WIN32) || defined(_MSC_VER)
DEFINE_bool(direct_run, ExecutionGroup, false, "Run test function directly.");
#endif

/* Fuzzing and symex related options, baked in to perform analysis-related tasks without auxiliary tools */
DEFINE_bool(fuzz, AnalysisGroup, false, "Perform brute force unguided fuzzing.");
DEFINE_bool(random, AnalysisGroup, false, "Run one test with random inputs.");
DEFINE_bool(fuzz_save_passing, AnalysisGroup, false, "Save passing tests during fuzzing.");
DEFINE_bool(fork, AnalysisGroup, true, "Fork when running a test.");
DEFINE_int(seed, AnalysisGroup, 0, "Seed for brute force fuzzing (uses time if not set).");

/* Test selection options to configure what test or tests should be executed during a run */
DEFINE_string(input_which_test, TestSelectionGroup, "", "Test to use with --input_test_file or --input_test_files_dir.");
DEFINE_string(test_filter, TestSelectionGroup, "", "Run all tests matched with wildcard pattern.");
DEFINE_bool(list_tests, TestSelectionGroup, false, "List all available tests instead of running tests.");
DEFINE_bool(boring_only, TestSelectionGroup, false, "Run Boring concrete tests only.");
DEFINE_bool(run_disabled, TestSelectionGroup, false, "Run Disabled tests alongside other tests.");

/* Set to 1 by Manticore/Angr/etc. when we're running symbolically. */
int DeepState_UsingSymExec = 0;

/* Set to 1 when we're using libFuzzer. */
int DeepState_UsingLibFuzzer = 0;

/* To make libFuzzer louder on mac OS. */
int DeepState_LibFuzzerLoud = 0;

/* Array of DeepState generated allocations.  Impossible for there to
 * be more than there are input bytes.  Index stores where we are. */
char* DeepState_GeneratedAllocs[DeepState_InputSize];
uint32_t DeepState_GeneratedAllocsIndex = 0;

/* Pointer to the last registers DeepState_TestInfo data structure */
struct DeepState_TestInfo *DeepState_LastTestInfo = NULL;

/* Pointer to structure for ordered DeepState_TestInfo */
struct DeepState_TestInfo *DeepState_FirstTestInfo = NULL;

/* Pointer to the test being run in this process by Dr. Fuzz. */
static struct DeepState_TestInfo *DeepState_DrFuzzTest = NULL;

/* Initialize global input buffer and index / initialized index. */
volatile uint8_t DeepState_Input[DeepState_InputSize] = {};
uint32_t DeepState_InputIndex = 0;
uint32_t DeepState_InputInitialized = 0;

/* Used if we need to generate on-the-fly data while we fuzz */
uint32_t DeepState_InternalFuzzing = 0;

/* Swarm related state. */
uint32_t DeepState_SwarmConfigsIndex = 0;
struct DeepState_SwarmConfig *DeepState_SwarmConfigs[DEEPSTATE_MAX_SWARM_CONFIGS];

/* Jump buffer for returning to `DeepState_Run`. */
jmp_buf DeepState_ReturnToRun = {};

/* Information about the current test run, if any. */
extern struct DeepState_TestRunInfo *DeepState_CurrentTestRun = NULL;

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

void DeepState_InitCurrentTestRun(struct DeepState_TestInfo *test) {
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

/* Abandon this test due to failed assumption. Less important to log. */
DEEPSTATE_NORETURN
void DeepState_Abandon_Due_to_Assumption(const char *reason) {
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
        DeepState_Abandon("Exceeded set input limit. Set or expand DEEPSTATE_SIZE to write more bytes.");
      }
      if (FLAGS_verbose_reads) {
        printf("Reading byte at %u\n", DeepState_InputIndex);
      }
      bytes[i] = DEEPSTATE_READBYTE;
    }
  }
}

/* Symbolize the data in the exclusive range `[begin, end)` without null
 * characters included.  Primarily useful for C strings. */
void DeepState_SymbolizeDataNoNull(void *begin, void *end) {
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
        DeepState_Abandon("Exceeded set input limit. Set or expand DEEPSTATE_SIZE to write more bytes.");
      }
      if (FLAGS_verbose_reads) {
        printf("Reading byte at %u\n", DeepState_InputIndex);
      }
      bytes[i] = DEEPSTATE_READBYTE;
      if (bytes[i] == 0) {
        bytes[i] = 1;
      }
    }
  }
}

/* Concretize some data in exclusive the range `[begin, end)`. */
void *DeepState_ConcretizeData(void *begin, void *end) {
  return begin;
}

/* Assign a symbolic C string of strlen length `len`.  str should include
 * storage for both `len` characters AND the null terminator.  Allowed
 * is a set of chars that are allowed (ignored if null). */
void DeepState_AssignCStr_C(char* str, size_t len, const char* allowed) {
  if (SIZE_MAX <= len) {
    DeepState_Abandon("Can't create a SIZE_MAX-length string.");
  }
  if (NULL == str) {
    DeepState_Abandon("Attempted to populate null pointer.");
  }
  if (len) {
    if (allowed == 0) {
      DeepState_SymbolizeDataNoNull(str, &(str[len]));
    } else {
      uint32_t allowed_size = strlen(allowed);
      for (int i = 0; i < len; i++) {
        str[i] = allowed[DeepState_UIntInRange(0, allowed_size-1)];
      }
    }
  }
  str[len] = '\0';
}

void DeepState_SwarmAssignCStr_C(const char* file, unsigned line, int stype,
				 char* str, size_t len, const char* allowed) {
  if (SIZE_MAX <= len) {
    DeepState_Abandon("Can't create a SIZE_MAX-length string.");
  }
  if (NULL == str) {
    DeepState_Abandon("Attempted to populate null pointer.");
  }
  char swarm_allowed[256];  
  if (allowed == 0) {
    /* In swarm mode, if there is no allowed string, create one over all chars. */
    for (int i = 0; i < 255; i++) {
      swarm_allowed[i] = i+1;
    }
    swarm_allowed[255] = 0;
    allowed = (const char*)&swarm_allowed;
  }
  if (len) {
    uint32_t allowed_size = strlen(allowed);
    struct DeepState_SwarmConfig* sc = DeepState_GetSwarmConfig(allowed_size, file, line, stype);
    for (int i = 0; i < len; i++) {
      str[i] = allowed[sc->fmap[DeepState_UIntInRange(0U, sc->fcount-1)]];
    }
  }
  str[len] = '\0';
}

/* Return a symbolic C string of strlen `len`. */
char *DeepState_CStr_C(size_t len, const char* allowed) {
  if (SIZE_MAX <= len) {
    DeepState_Abandon("Can't create a SIZE_MAX-length string");
  }
  char *str = (char *) malloc(sizeof(char) * (len + 1));
  if (NULL == str) {
    DeepState_Abandon("Can't allocate memory");
  }
  DeepState_GeneratedAllocs[DeepState_GeneratedAllocsIndex++] = str;
  if (len) {
    if (allowed == 0) {
      DeepState_SymbolizeDataNoNull(str, &(str[len]));
    } else {
      uint32_t allowed_size = strlen(allowed);
      for (int i = 0; i < len; i++) {
        str[i] = allowed[DeepState_UIntInRange(0, allowed_size-1)];
      }
    }
  }
  str[len] = '\0';
  return str;
}

char *DeepState_SwarmCStr_C(const char* file, unsigned line, int stype,
			    size_t len, const char* allowed) {
  if (SIZE_MAX <= len) {
    DeepState_Abandon("Can't create a SIZE_MAX-length string");
  }
  char *str = (char *) malloc(sizeof(char) * (len + 1));
  if (NULL == str) {
    DeepState_Abandon("Can't allocate memory");
  }
  char swarm_allowed[256];  
  if (allowed == 0) {
    /* In swarm mode, if there is no allowed string, create one over all chars. */
    for (int i = 0; i < 255; i++) {
      swarm_allowed[i] = i+1;
    }
    swarm_allowed[255] = 0;
    allowed = (const char*)&swarm_allowed;
  }
  DeepState_GeneratedAllocs[DeepState_GeneratedAllocsIndex++] = str;
  if (len) {
    uint32_t allowed_size = strlen(allowed);
    struct DeepState_SwarmConfig* sc = DeepState_GetSwarmConfig(allowed_size, file, line, stype);
    for (int i = 0; i < len; i++) {
      str[i] = allowed[sc->fmap[DeepState_UIntInRange(0U, sc->fcount-1)]];
    }
  }
  str[len] = '\0';
  return str;
}

/* Symbolize a C string; keeps the null terminator where it was. */
void DeepState_SymbolizeCStr_C(char *begin, const char* allowed) {
  if (begin && begin[0]) {
    if (allowed == 0) {
      DeepState_SymbolizeDataNoNull(begin, begin + strlen(begin));
    } else {
      uint32_t allowed_size = strlen(allowed);
      uint8_t *bytes = (uint8_t *) begin;
      uintptr_t begin_addr = (uintptr_t) begin;
      uintptr_t end_addr = (uintptr_t) (begin + strlen(begin));
      for (uintptr_t i = 0, max_i = (end_addr - begin_addr); i < max_i; ++i) {
        bytes[i] = allowed[DeepState_UIntInRange(0, allowed_size-1)];
      }
    }
  }
}

void DeepState_SwarmSymbolizeCStr_C(const char* file, unsigned line, int stype,
				    char *begin, const char* allowed) {
  if (begin && begin[0]) {
    char swarm_allowed[256];    
    if (allowed == 0) {
      /* In swarm mode, if there is no allowed string, create one over all chars. */
      for (int i = 0; i < 255; i++) {
	swarm_allowed[i] = i+1;
      }
      swarm_allowed[255] = 0;
      allowed = (const char*)&swarm_allowed;      
    }
    uint32_t allowed_size = strlen(allowed);
    struct DeepState_SwarmConfig* sc = DeepState_GetSwarmConfig(allowed_size, file, line, stype);
    uint8_t *bytes = (uint8_t *) begin;
    uintptr_t begin_addr = (uintptr_t) begin;
    uintptr_t end_addr = (uintptr_t) (begin + strlen(begin));
    for (uintptr_t i = 0, max_i = (end_addr - begin_addr); i < max_i; ++i) {
      bytes[i] = allowed[sc->fmap[DeepState_UIntInRange(0U, sc->fcount-1)]];
    }
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

/* Allocate and return a pointer to `num_bytes` symbolic bytes. */
void *DeepState_GCMalloc(size_t num_bytes) {
  void *data = malloc(num_bytes);
  uintptr_t data_end = ((uintptr_t) data) + num_bytes;
  DeepState_SymbolizeData(data, (void *) data_end);
  DeepState_GeneratedAllocs[DeepState_GeneratedAllocsIndex++] = data;
  return data;
}

/* Portable and architecture-independent memory scrub without dead store elimination. */
void *DeepState_MemScrub(void *pointer, size_t data_size) {
  volatile unsigned char *p = pointer;
  while (data_size--) {
    *p++ = 0;
  }
  return pointer;
}

/* Generate a new swarm configuration. */
struct DeepState_SwarmConfig *DeepState_NewSwarmConfig(unsigned fcount, const char* file, unsigned line,
						       enum DeepState_SwarmType stype) {
  struct DeepState_SwarmConfig *new_config = malloc(sizeof(struct DeepState_SwarmConfig));
  size_t buf_len = strlen(file) + 1;
  new_config->file = malloc(buf_len);
  strncpy(new_config->file, file, buf_len);
  new_config->line = line;
  new_config->orig_fcount = fcount;
  new_config->fcount = 0;
  if (stype == DeepState_SwarmTypeProb) {
    new_config->fmap = malloc(sizeof(unsigned) * fcount * DEEPSTATE_SWARM_MAX_PROB_RATIO);
    for (int i = 0; i < fcount; i++) {
      unsigned int prob = DeepState_UIntInRange(0U, DEEPSTATE_SWARM_MAX_PROB_RATIO);
      for (int j = 0; j < prob; j++) {
	new_config->fmap[new_config->fcount++] = i;
      }
    }
    if (new_config->fcount == 0) {
      new_config->fmap[new_config->fcount++] = DeepState_UIntInRange(0, fcount-1);
    }
  } else {
    new_config->fmap = malloc(sizeof(unsigned) * fcount);
    /* In mix mode, "half" the time just use everything */
    int full_config = (stype == DeepState_SwarmTypeMixed) && DeepState_Bool();
    if ((stype == DeepState_SwarmTypeMixed) && DeepState_UsingSymExec) {
      /* We don't want to make additional pointless paths to explore for symex */
      (void) DeepState_Assume(full_config);
    }
    for (int i = 0; i < fcount; i++) {
      if (full_config) {
	new_config->fmap[new_config->fcount++] = i;
      } else {
	int in_swarm = DeepState_Bool();
	if (DeepState_UsingSymExec) {
	  /* If not in mix mode, just allow everything in each configuration for symex */
	  (void) DeepState_Assume(in_swarm);
	}
	if (in_swarm) {
	  new_config->fmap[new_config->fcount++] = i;
	}
      }
    }
  }
  /* We always need to allow at least one option! */
  if (new_config->fcount == 0) {
    new_config->fmap[new_config->fcount++] = DeepState_UIntInRange(0, fcount-1);
  }
  return new_config;
}

/* Either fetch existing configuration, or generate a new one. */
struct DeepState_SwarmConfig *DeepState_GetSwarmConfig(unsigned fcount, const char* file, unsigned line,
						       enum DeepState_SwarmType stype) {
  /* In general, there should be few enough OneOfs in a harness that linear search is fine. */
  for (int i = 0; i < DeepState_SwarmConfigsIndex; i++) {
    struct DeepState_SwarmConfig* sc = DeepState_SwarmConfigs[i];
    if ((sc->line == line) && (sc->orig_fcount == fcount) && (strncmp(sc->file, file, strlen(file)) == 0)) {
      return sc;
    }
  }
  if (DeepState_SwarmConfigsIndex == DEEPSTATE_MAX_SWARM_CONFIGS) {
    DeepState_Abandon("Exceeded swarm config limit. Set or expand DEEPSTATE_MAX_SWARM_CONFIGS. This is highly unusual.");
  }
  DeepState_SwarmConfigs[DeepState_SwarmConfigsIndex] = DeepState_NewSwarmConfig(fcount, file, line, stype);
  return DeepState_SwarmConfigs[DeepState_SwarmConfigsIndex++];
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
    DeepState_Abandon("Exceeded set input limit. Set or expand DEEPSTATE_SIZE to write more bytes.");
  }
  if (FLAGS_verbose_reads) {
    printf("Reading byte as boolean at %u\n", DeepState_InputIndex);
  }
  return DEEPSTATE_READBYTE & 1;
}



#define MAKE_SYMBOL_FUNC(Type, type) \
    type DeepState_ ## Type(void) { \
      if ((DeepState_InputIndex + sizeof(type)) > DeepState_InputSize) { \
        DeepState_Abandon("Exceeded set input limit. Set or expand DEEPSTATE_SIZE to write more bytes."); \
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
        val = (val << 8) | ((type) DEEPSTATE_READBYTE); \
      } \
      if (FLAGS_verbose_reads) { \
        printf("FINISHED MULTI-BYTE READ\n"); \
      } \
      return val; \
    }


MAKE_SYMBOL_FUNC(Size, size_t)
MAKE_SYMBOL_FUNC(Long, long)

float DeepState_Float(void) {
  float float_v;
  DeepState_SymbolizeData(&float_v, &float_v + 1);
  return float_v;
}

double DeepState_Double(void) {
  double double_v;
  DeepState_SymbolizeData(&double_v, &double_v + 1);
  return double_v;
}

MAKE_SYMBOL_FUNC(UInt64, uint64_t)
int64_t DeepState_Int64(void) {
  return (int64_t) DeepState_UInt64();
}

MAKE_SYMBOL_FUNC(UInt, unsigned)
int DeepState_Int(void) {
  return (int) DeepState_UInt();
}

MAKE_SYMBOL_FUNC(UShort, unsigned short)
short DeepState_Short(void) {
  return (short) DeepState_UShort();
}

MAKE_SYMBOL_FUNC(UChar, unsigned char)
char DeepState_Char(void) {
  return (char) DeepState_UChar();
}

#undef MAKE_SYMBOL_FUNC

float DeepState_FloatInRange(float low, float high) {
  if (low > high) {
    return DeepState_FloatInRange(high, low);
  }
  if (low < 0.0) { // Handle negatives differently
    if (high > 0.0) {
      if (DeepState_Bool()) {
        return -(DeepState_FloatInRange(0.0, -low));
      } else {
        return DeepState_FloatInRange(0.0, high);
      }
    } else {
      return -(DeepState_FloatInRange(-high, -low));
    }
  }
  int32_t int_v = DeepState_IntInRange(*(int32_t *)&low, *(int32_t *)&high);
  float float_v = *(float*)&int_v;
  assume (float_v >= low);
  assume (float_v <= high);
  return float_v;
}

double DeepState_DoubleInRange(double low, double high) {
  if (low > high) {
    return DeepState_DoubleInRange(high, low);
  }
  if (low < 0.0) { // Handle negatives differently
    if (high > 0.0) {
      if (DeepState_Bool()) {
        return -(DeepState_DoubleInRange(0.0, -low));
      } else {
        return DeepState_DoubleInRange(0.0, high);
      }
    } else {
      return -(DeepState_DoubleInRange(-high, -low));
    }
  }
  int64_t int_v = DeepState_Int64InRange(*(int64_t *)&low, *(int64_t *)&high);
  double double_v = *(double*)&int_v;
  assume (double_v >= low);
  assume (double_v <= high);
  return double_v;
}

int32_t DeepState_RandInt() {
  return DeepState_IntInRange(0, RAND_MAX);
}

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

/* Function to clean up generated strings, and any other DeepState-managed data. */
extern void DeepState_CleanUp() {
  for (int i = 0; i < DeepState_GeneratedAllocsIndex; i++) {
    free(DeepState_GeneratedAllocs[i]);
  }
  DeepState_GeneratedAllocsIndex = 0;
  
  for (int i = 0; i < DeepState_SwarmConfigsIndex; i++) {
    free(DeepState_SwarmConfigs[i]->file);
    free(DeepState_SwarmConfigs[i]->fmap);
    free(DeepState_SwarmConfigs[i]);
  }
  DeepState_SwarmConfigsIndex = 0;
}

void _DeepState_Assume(int expr, const char *expr_str, const char *file,
                       unsigned line) {
  if (!expr) {
    DeepState_LogFormat(DeepState_LogTrace,
                        "%s(%u): Assumption %s failed",
                        file, line, expr_str);
    DeepState_Abandon_Due_to_Assumption("Assumption failed");
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

  /* Sort the test cases by line number. */
  struct DeepState_TestInfo *current = DeepState_LastTestInfo;
  if (current == NULL) {
    DeepState_LogFormat(DeepState_LogError,
       "No tests to run have been defined!  Did you include the harness to compile?");
    exit(1);
  }
  struct DeepState_TestInfo *min_node = current->prev;
  current->prev = NULL;

  while (min_node != NULL) {
    struct DeepState_TestInfo *temp = min_node;

    min_node = min_node->prev;
    temp->prev = current;
    current = temp;
  }
  DeepState_FirstTestInfo = current;
}

/* Tear down DeepState. */
void DeepState_Teardown(void) {

}

/* Notify that we're about to begin a test. */
void DeepState_Begin(struct DeepState_TestInfo *test) {
  DeepState_InitCurrentTestRun(test);
  DeepState_LogFormat(DeepState_LogTrace, "Running: %s from %s(%u)",
                      test->test_name, test->file_name, test->line_number);
}

void DeepState_Warn_srand(unsigned int seed) {
  DeepState_LogFormat(DeepState_LogWarning,
              "srand under DeepState has no effect: rand is re-defined as DeepState_Int");
}

static uint32_t DeepState_RotateLeft32(uint32_t value, uint32_t distance) {
  return (value << distance) | (value >> (32U - distance));
}

static void DeepState_MD5(const volatile uint8_t *data, size_t size,
                          uint8_t digest[16]) {
  static const uint32_t shifts[] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
  };
  static const uint32_t constants[] = {
    0xd76aa478U, 0xe8c7b756U, 0x242070dbU, 0xc1bdceeeU,
    0xf57c0fafU, 0x4787c62aU, 0xa8304613U, 0xfd469501U,
    0x698098d8U, 0x8b44f7afU, 0xffff5bb1U, 0x895cd7beU,
    0x6b901122U, 0xfd987193U, 0xa679438eU, 0x49b40821U,
    0xf61e2562U, 0xc040b340U, 0x265e5a51U, 0xe9b6c7aaU,
    0xd62f105dU, 0x02441453U, 0xd8a1e681U, 0xe7d3fbc8U,
    0x21e1cde6U, 0xc33707d6U, 0xf4d50d87U, 0x455a14edU,
    0xa9e3e905U, 0xfcefa3f8U, 0x676f02d9U, 0x8d2a4c8aU,
    0xfffa3942U, 0x8771f681U, 0x6d9d6122U, 0xfde5380cU,
    0xa4beea44U, 0x4bdecfa9U, 0xf6bb4b60U, 0xbebfbc70U,
    0x289b7ec6U, 0xeaa127faU, 0xd4ef3085U, 0x04881d05U,
    0xd9d4d039U, 0xe6db99e5U, 0x1fa27cf8U, 0xc4ac5665U,
    0xf4292244U, 0x432aff97U, 0xab9423a7U, 0xfc93a039U,
    0x655b59c3U, 0x8f0ccc92U, 0xffeff47dU, 0x85845dd1U,
    0x6fa87e4fU, 0xfe2ce6e0U, 0xa3014314U, 0x4e0811a1U,
    0xf7537e82U, 0xbd3af235U, 0x2ad7d2bbU, 0xeb86d391U
  };

  uint32_t a0 = 0x67452301U;
  uint32_t b0 = 0xefcdab89U;
  uint32_t c0 = 0x98badcfeU;
  uint32_t d0 = 0x10325476U;
  size_t padded_size = size + 1U;
  uint8_t *message = NULL;

  while ((padded_size % 64U) != 56U) {
    ++padded_size;
  }

  message = calloc(padded_size + 8U, sizeof(uint8_t));
  if (message == NULL) {
    DeepState_Abandon("Can't allocate memory for saved test hashing.");
  }

  for (size_t i = 0; i < size; ++i) {
    message[i] = data[i];
  }
  message[size] = 0x80U;

  uint64_t bit_size = (uint64_t) size * 8U;
  for (size_t i = 0; i < 8U; ++i) {
    message[padded_size + i] = (uint8_t) (bit_size >> (8U * i));
  }

  for (size_t offset = 0; offset < (padded_size + 8U); offset += 64U) {
    uint32_t words[16];
    for (size_t i = 0; i < 16U; ++i) {
      size_t word_offset = offset + (i * 4U);
      words[i] = ((uint32_t) message[word_offset]) |
                 ((uint32_t) message[word_offset + 1U] << 8U) |
                 ((uint32_t) message[word_offset + 2U] << 16U) |
                 ((uint32_t) message[word_offset + 3U] << 24U);
    }

    uint32_t a = a0;
    uint32_t b = b0;
    uint32_t c = c0;
    uint32_t d = d0;

    for (uint32_t i = 0; i < 64U; ++i) {
      uint32_t mix = 0U;
      uint32_t word_index = 0U;

      if (i < 16U) {
        mix = (b & c) | ((~b) & d);
        word_index = i;
      } else if (i < 32U) {
        mix = (d & b) | ((~d) & c);
        word_index = ((5U * i) + 1U) % 16U;
      } else if (i < 48U) {
        mix = b ^ c ^ d;
        word_index = ((3U * i) + 5U) % 16U;
      } else {
        mix = c ^ (b | (~d));
        word_index = (7U * i) % 16U;
      }

      uint32_t next_d = d;
      d = c;
      c = b;
      b += DeepState_RotateLeft32(a + mix + constants[i] + words[word_index],
                                  shifts[i]);
      a = next_d;
    }

    a0 += a;
    b0 += b;
    c0 += c;
    d0 += d;
  }

  free(message);

  uint32_t state[] = {a0, b0, c0, d0};
  for (size_t i = 0; i < 4U; ++i) {
    digest[(i * 4U)] = (uint8_t) (state[i] & 0xffU);
    digest[(i * 4U) + 1U] = (uint8_t) ((state[i] >> 8U) & 0xffU);
    digest[(i * 4U) + 2U] = (uint8_t) ((state[i] >> 16U) & 0xffU);
    digest[(i * 4U) + 3U] = (uint8_t) ((state[i] >> 24U) & 0xffU);
  }
}

void makeFilename(char *name, size_t size) {
  const char *entities = "0123456789abcdef";
  uint8_t digest[16];
  size_t hex_size = size;

  if (hex_size > (sizeof(digest) * 2U)) {
    hex_size = sizeof(digest) * 2U;
  }

  DeepState_MD5(DeepState_Input, DeepState_InputIndex, digest);
  for (size_t i = 0; i < hex_size; ++i) {
    uint8_t nibble = digest[i / 2U];
    if ((i % 2U) == 0U) {
      nibble >>= 4U;
    }
    name[i] = entities[nibble & 0x0fU];
  }
}

void writeInputData(char* name, int important) {
  size_t path_len = 2 + sizeof(char) * (strlen(FLAGS_output_test_dir) + strlen(name));
  char *path = (char *) malloc(path_len);
  snprintf(path, path_len, "%s/%s", FLAGS_output_test_dir, name);
  FILE *fp = fopen(path, "wb");
  if (fp == NULL) {
    DeepState_LogFormat(DeepState_LogError, "Failed to create file `%s`", path);
    free(path);
    return;
  }
  size_t written = fwrite((void *)DeepState_Input, 1, DeepState_InputIndex, fp);
  if (written != DeepState_InputIndex) {
    DeepState_LogFormat(DeepState_LogError, "Failed to write to file `%s`", path);
  } else {
    if (important) {
      DeepState_LogFormat(DeepState_LogInfo, "Saved test case in file `%s`", path);
    } else {
      DeepState_LogFormat(DeepState_LogTrace, "Saved test case in file `%s`", path);
    }
  }
  free(path);
  fclose(fp);
}

/* Save a passing test to the output test directory. */
void DeepState_SavePassingTest(void) {
  char name[48];
  makeFilename(name, 32);
  name[32] = 0;
  strncat(name, ".pass", 48);
  writeInputData(name, 0);
}

/* Save a failing test to the output test directory. */
void DeepState_SaveFailingTest(void) {
  char name[48];
  makeFilename(name, 32);
  name[32] = 0;
  strncat(name, ".fail", 48);
  writeInputData(name, 1);
}

/* Save a crashing test to the output test directory. */
void DeepState_SaveCrashingTest(void) {
  char name[48];
  makeFilename(name, 32);
  name[32] = 0;
  strncat(name, ".crash", 48);
  writeInputData(name, 1);
}

/* Return the first test case to run. */
struct DeepState_TestInfo *DeepState_FirstTest(void) {
  return DeepState_FirstTestInfo;
}

/* Returns `true` if a failure was caught for the current test case. */
bool DeepState_CatchFail(void) {
  return DeepState_CurrentTestRun->result == DeepState_TestRunFail;
}

/* Returns `true` if the current test case was abandoned. */
bool DeepState_CatchAbandoned(void) {
  return DeepState_CurrentTestRun->result == DeepState_TestRunAbandon;
}

/* Fuzz test `FLAGS_input_which_test` or first test, if not defined.
   Has to be defined here since we redefine rand in the header. */
int DeepState_Fuzz(void){
  DeepState_LogFormat(DeepState_LogInfo, "Starting fuzzing");

  if (!HAS_FLAG_min_log_level && !HAS_FLAG_random) {
    FLAGS_min_log_level = 2;
  }

  if (HAS_FLAG_seed) {
    srand(FLAGS_seed);
  } else {
    unsigned int seed = time(NULL);
    DeepState_LogFormat(DeepState_LogWarning, "No seed provided; using %u", seed);
    srand(seed);
  }

  if (HAS_FLAG_fork) {
    if (FLAGS_fork) {
      DeepState_LogFormat(DeepState_LogFatal,
			  "Forking should not be combined with brute force fuzzing.");
    }
  } else {
    FLAGS_fork = 0;
  }

  long start = (long)time(NULL);
  long current = (long)time(NULL);
  unsigned diff = 0;
  unsigned int i = 0;

  int num_failed_tests = 0;
  int num_passed_tests = 0;
  int num_abandoned_tests = 0;

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

  unsigned int last_status = 0;

  while (diff < FLAGS_timeout) {
    i++;
    if ((diff != last_status) && ((diff % 30) == 0) ) {
      time_t t = time(NULL);
      struct tm tm = *localtime(&t);
      DeepState_LogFormat(DeepState_LogInfo, "%d-%02d-%02d %02d:%02d:%02d: %u tests/second: %d failed/%d passed/%d abandoned",
			  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, i/diff,
			  num_failed_tests, num_passed_tests, num_abandoned_tests);
      last_status = diff;
    }
    enum DeepState_TestRunResult result = DeepState_FuzzOneTestCase(test);
    if ((result == DeepState_TestRunFail) || (result == DeepState_TestRunCrash)) {
      num_failed_tests++;
    } else if (result == DeepState_TestRunPass) {
      num_passed_tests++;
    } else if (result == DeepState_TestRunAbandon) {
      num_abandoned_tests++;
    }

    current = (long)time(NULL);
    diff = current-start;

    if ((FLAGS_random) && (i > 0)) {
      break;
    }
  }

  if (!FLAGS_random) {
    DeepState_LogFormat(DeepState_LogInfo, "Done fuzzing! Ran %u tests (%u tests/second) with %d failed/%d passed/%d abandoned tests",
			i, i/diff, num_failed_tests, num_passed_tests, num_abandoned_tests);
  }
  return num_failed_tests;
}


/* Run a test case with input initialized by fuzzing.
   Has to be defined here since we redefine rand in the header. */
enum DeepState_TestRunResult DeepState_FuzzOneTestCase(struct DeepState_TestInfo *test) {
  DeepState_InputIndex = 0;
  DeepState_InputInitialized = 0;
  DeepState_SwarmConfigsIndex = 0;
  DeepState_InternalFuzzing = 1;

  DeepState_Begin(test);

  enum DeepState_TestRunResult result = DeepState_ForkAndRunTest(test);

  if (result == DeepState_TestRunCrash) {
    DeepState_LogFormat(DeepState_LogError, "Crashed: %s", test->test_name);

    if (HAS_FLAG_output_test_dir) {
      DeepState_SaveCrashingTest();
    }

    DeepState_Crash();
  }

  if (FLAGS_abort_on_fail && ((result == DeepState_TestRunCrash) ||
                  (result == DeepState_TestRunFail))) {
    DeepState_HardCrash();
  }

  if (FLAGS_exit_on_fail && ((result == DeepState_TestRunCrash) ||
                  (result == DeepState_TestRunFail))) {
    exit(255); // Terminate the testing
  }

  return result;
}

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size > sizeof(DeepState_Input)) {
    return 0; // Just ignore any too-big inputs
  }

  DeepState_UsingLibFuzzer = 1;

  FLAGS_min_log_level = 3;

  const char* log_control = getenv("DEEPSTATE_LOG");
  if (log_control != NULL) {
    FLAGS_min_log_level = atoi(log_control);
  }

  const char* loud = getenv("LIBFUZZER_LOUD");
  if (loud != NULL) {
    DeepState_LibFuzzerLoud = 1;
  }

  struct DeepState_TestInfo *test = NULL;

  DeepState_InitOptions(0, "");
  DeepState_Setup();

  /* we also want to manually allocate CurrentTestRun */
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
  
  if (test == NULL) {
    DeepState_LogFormat(DeepState_LogFatal,
                        "Could not find matching test for %s (from LIBFUZZER_WHICH_TEST)",
                        which_test);
    exit(255);
  }

  DeepState_InputIndex = 0;
  DeepState_SwarmConfigsIndex = 0;

  memcpy((void *) DeepState_Input, (void *) Data, Size);
  DeepState_InputInitialized = Size;

  DeepState_Begin(test);

  enum DeepState_TestRunResult result = DeepState_RunTestNoFork(test);
  DeepState_CleanUp();

  const char* abort_check = getenv("LIBFUZZER_ABORT_ON_FAIL");
  if (abort_check != NULL) {
    if ((result == DeepState_TestRunFail) || (result == DeepState_TestRunCrash)) {
      assert(0); // Terminate the testing more permanently
    }
  }

  const char* exit_check = getenv("LIBFUZZER_EXIT_ON_FAIL");
  if (exit_check != NULL) {
    if ((result == DeepState_TestRunFail) || (result == DeepState_TestRunCrash)) {
      exit(255); // Terminate the testing
    }
  }

  DeepState_Teardown();
  DeepState_CurrentTestRun = NULL;
  free(mem);

  return 0;  // Non-zero return values are reserved for future use.
}

extern int FuzzerEntrypoint(const uint8_t *data, size_t size) {
  return LLVMFuzzerTestOneInput(data, size);
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
  if (FLAGS_abort_on_fail) {
    DeepState_HardCrash();
  }
  __builtin_unreachable();
}

void __stack_chk_fail(void) {
  DeepState_Log(DeepState_LogFatal, "Stack smash detected");
  __builtin_unreachable();
}

#ifndef LIBFUZZER
#ifndef HEADLESS
#if defined(__unix)
__attribute__((weak))
#endif
int main(int argc, char *argv[]) {
  int ret = 0;
  DeepState_Setup();
  DeepState_InitOptions(argc, argv);
  ret = DeepState_Run();
  DeepState_Teardown();
  return ret;
}
#endif
#endif

DEEPSTATE_END_EXTERN_C
