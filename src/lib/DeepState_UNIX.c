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

#include "deepstate/Platform.h"
#include "deepstate/DeepState.h"
#include "deepstate/Option.h"
#include "deepstate/Log.h"

DEEPSTATE_BEGIN_EXTERN_C

void DeepState_AllocCurrentTestRun(void) {
  int mem_prot = PROT_READ | PROT_WRITE;
  int mem_vis = MAP_ANONYMOUS | MAP_SHARED;
  void *shared_mem = mmap(NULL, sizeof(struct DeepState_TestRunInfo), mem_prot,
                          mem_vis, 0, 0);

  if (shared_mem == MAP_FAILED) {
    DeepState_Log(DeepState_LogError, "Unable to map shared memory");
    exit(1);
  }

  DeepState_CurrentTestRun = (struct DeepState_TestRunInfo *) shared_mem;
}

/* Return a string path to an input file or directory without parsing it to a type. This is
 * useful method in the case where a tested function only takes a path input in order
 * to generate some specialized structured type. Note: the returned path must be 
 * deallocated at the end by the caller. */
char* DeepState_InputPath(const char* testcase_path) {

  struct stat statbuf;
  char *abspath;

  /* Use specified path if no --input_test* flag specified. Override if --input_* args specified. */
  if (testcase_path) {
    if (!HAS_FLAG_input_test_file && !HAS_FLAG_input_test_files_dir) {
      abspath = realpath(testcase_path, NULL);
    }
  }

  /* Prioritize using CLI-specified input paths, for the sake of fuzzing */
  if (HAS_FLAG_input_test_file) {
    abspath = realpath(FLAGS_input_test_file, NULL);
  } else if (HAS_FLAG_input_test_files_dir) {
    abspath = realpath(FLAGS_input_test_files_dir, NULL);
  } else {
    DeepState_Abandon("No usable path specified for DeepState_InputPath.");
  }

  if (stat(abspath, &statbuf) != 0) {
    DeepState_Abandon("Specified input path does not exist.");
  }

  if (HAS_FLAG_input_test_files_dir) {
    if (!S_ISDIR(statbuf.st_mode)) {
      DeepState_Abandon("Specified input directory is not a directory.");
    }
  }

  DeepState_LogFormat(DeepState_LogInfo, "Using `%s` as input path.", abspath);
  return abspath;
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
          DeepState_LogFormat(DeepState_LogTrace,
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


/* Fork and run `test`. */
extern enum DeepState_TestRunResult
DeepState_ForkAndRunTest(struct DeepState_TestInfo *test) {
  int wstatus;
  pid_t test_pid;
  
  if (FLAGS_fork) {
    test_pid = fork();
    if (!test_pid) {
      DeepState_RunTest(test);
      /* No need to clean up in a fork; exit() is the ultimate garbage collector */
    }
  }

  /* If we exited normally, the status code tells us if the test passed. */
  if (FLAGS_fork) {
    waitpid(test_pid, &wstatus, 0);
    return (enum DeepState_TestRunResult) wstatus;
  } else {
    wstatus = DeepState_RunTestNoFork(test);
    DeepState_CleanUp();
    return (enum DeepState_TestRunResult) wstatus;
  }
  

  /* If here, we exited abnormally but didn't catch it in the signal
   * handler, and thus the test failed due to a crash. */
  return DeepState_TestRunCrash;
}

DEEPSTATE_END_EXTERN_C