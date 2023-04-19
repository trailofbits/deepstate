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

#include <windows.h>

#include "deepstate/Platform.h"
#include "deepstate/DeepState.h"
#include "deepstate/Option.h"
#include "deepstate/Log.h"

DEEPSTATE_BEGIN_EXTERN_C

void DeepState_AllocCurrentTestRun(void) {
  HANDLE shared_mem_handle = INVALID_HANDLE_VALUE;
  
  shared_mem_handle = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 
                  0, sizeof(struct DeepState_TestRunInfo), "DeepState_CurrentTestRun");
  if (!shared_mem_handle){
    DeepState_LogFormat(DeepState_LogError, "Unable to map shared memory (%d)", GetLastError());
    exit(1);
  }

  struct DeepState_TestRunInfo *shared_mem = (struct DeepState_TestRunInfo*) MapViewOfFile(shared_mem_handle, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(struct DeepState_TestRunInfo));
  if (!shared_mem){
    DeepState_LogFormat(DeepState_LogError, "Unable to map shared memory (%d)", GetLastError());
    exit(1);
  }

  DeepState_CurrentTestRun = (struct DeepState_TestRunInfo *) shared_mem;
}


/* Return a string path to an input file or directory without parsing it to a type. This is
 * useful method in the case where a tested function only takes a path input in order
 * to generate some specialized structured type. Note: the returned path must be 
 * deallocated at the end by the caller. */
char* DeepState_InputPath(const char* testcase_path) {

  char *abspath = (char*) malloc(MAX_CMD_LEN * sizeof(char));

  /* Use specified path if no --input_test* flag specified. Override if --input_* args specified. */
  if (testcase_path) {
    if (!HAS_FLAG_input_test_file && !HAS_FLAG_input_test_files_dir) {
      _fullpath(abspath, testcase_path, MAX_CMD_LEN);
    }
  }

  /* Prioritize using CLI-specified input paths, for the sake of fuzzing */
  if (HAS_FLAG_input_test_file) {
    _fullpath(abspath, FLAGS_input_test_file, MAX_CMD_LEN);
  } else if (HAS_FLAG_input_test_files_dir) {
    _fullpath(abspath, FLAGS_input_test_files_dir, MAX_CMD_LEN);
  } else {
    DeepState_Abandon("No usable path specified for DeepState_InputPath.");
  }

  DWORD file_attributes = GetFileAttributes(abspath);
  if (file_attributes == INVALID_FILE_ATTRIBUTES){
    DeepState_Abandon("Specified input path does not exist.");
  }

  if (HAS_FLAG_input_test_files_dir) {
    if (!(file_attributes & INVALID_FILE_ATTRIBUTES)){
      DeepState_Abandon("Specified input directory is not a directory.");
    }
  }

  DeepState_LogFormat(DeepState_LogInfo, "Using `%s` as input path.", abspath);
  return abspath;
}

void DeepState_RunSavedTakeOverCases(jmp_buf env,
                                     struct DeepState_TestInfo *test) {

  /* The method is not supported on Windows, and thus exit with an error. */
  DeepState_LogFormat(DeepState_LogError,
                      "Error: takeover works only on Unix based systems.");
}

int DeepState_TakeOver(void) {

  /* The method is not supported on Windows, and thus exit with an error. */
  DeepState_LogFormat(DeepState_LogError,
                      "Error: takeover works only on Unix based systems.");
  return -1;

}

/* Run a test case inside a new Windows process */
int DeepState_RunTestWin(struct DeepState_TestInfo *test){

  PROCESS_INFORMATION pi;
  STARTUPINFO si;
  DWORD exit_code = DeepState_TestRunPass;

  ZeroMemory( &si, sizeof(si) );
  si.cb = sizeof(si);
  ZeroMemory( &pi, sizeof(pi) );
  
  /* Get the fully qualified path of the current module */
  char command[MAX_CMD_LEN]; 
  if (!GetModuleFileName(NULL, command, MAX_CMD_LEN)){
    DeepState_LogFormat(DeepState_LogError, "GetModuleFileName failed (%d)", GetLastError());
    return DeepState_TestRunAbandon;
  }

  /* Append the parameters to specify which test to run and to run the test
      directly in the main process */
  snprintf(command, MAX_CMD_LEN, "%s --direct_run --input_which_test %s", command, test->test_name);

  if (HAS_FLAG_output_test_dir) {
    snprintf(command, MAX_CMD_LEN, "%s --output_test_dir %s", command, FLAGS_output_test_dir);
  }

  if (!FLAGS_fuzz || FLAGS_fuzz_save_passing) {
    snprintf(command, MAX_CMD_LEN, "%s --fuzz_save_passing", command);
  }

  /* Create the process */
  if(!CreateProcess(NULL, command, NULL, NULL, false, 0, NULL, NULL, &si, &pi)){
    DeepState_LogFormat(DeepState_LogError, "CreateProcess failed (%d)", GetLastError());
    return DeepState_TestRunAbandon;
  }

  /* Wait for the process to complete and get it's exit code */
  WaitForSingleObject(pi.hProcess, INFINITE);
  if (!GetExitCodeProcess(pi.hProcess, &exit_code)){
    DeepState_LogFormat(DeepState_LogError, "GetExitCodeProcess failed (%d)", GetLastError());
    return DeepState_TestRunAbandon;
  }

  /* If at this point the exit code is not DeepState_TestRunPass, it means that
   * DeepState_RunTest never reached the end of test->test_func(), and thus the 
   * function exited abnormally:
   *   test->test_func();
   *   exit(DeepState_TestRunPass); */
  if (exit_code != DeepState_TestRunPass){
    exit_code = DeepState_TestRunCrash;
  }

  return exit_code;
}

/* Run a single test. This function is intended to be executed within a new 
Windows process. */
void DeepState_RunSingle(){
  struct DeepState_TestInfo *test = DeepState_FirstTest(); 

  /* Seek for the TEST to run */
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
    return;
  }

  /* Run the test */
  DeepState_RunTest(test);

}

/* Fork and run `test`. */
extern enum DeepState_TestRunResult
DeepState_ForkAndRunTest(struct DeepState_TestInfo *test) {
  int wstatus;

  if (FLAGS_fork) {
    wstatus = DeepState_RunTestWin(test);
    return (enum DeepState_TestRunResult) wstatus;
  }
  wstatus = DeepState_RunTestNoFork(test);
  DeepState_CleanUp();
  return (enum DeepState_TestRunResult) wstatus;
}

/* Checks if the given path corresponds to a regular file. */
bool DeepState_IsRegularFile(char *path){
  DWORD file_attributes = GetFileAttributes(path);
  return file_attributes != INVALID_FILE_ATTRIBUTES && !(file_attributes & FILE_ATTRIBUTE_DIRECTORY);
}


/* Resets the global `DeepState_Input` buffer, then fills it with the
 * data found in the file `path`. */
void DeepState_InitInputFromFile(const char *path) {

  FILE *fp = fopen(path, "r");
  if (fp == NULL) {
    /* TODO(joe): Add error log with more info. */
    DeepState_Abandon("Unable to open file");
  }

  int fd = fileno(fp);
  if (fd < 0) {
    DeepState_Abandon("Tried to get file descriptor for invalid stream");
  }

  if (fseek(fp, 0L, SEEK_END) < 0){
    DeepState_Abandon("Unable to get test input size");
  }
  size_t to_read = ftell(fp);
  if(to_read < 0 || fseek(fp, 0L, SEEK_SET) < 0){
    DeepState_Abandon("Unable to get test input size");
  }

  if (to_read > sizeof(DeepState_Input)) {
    DeepState_LogFormat(DeepState_LogWarning, "File too large, truncating to max input size");
    to_read = DeepState_InputSize;
  }

  /* Reset the index. */
  DeepState_InputIndex = 0;
  DeepState_SwarmConfigsIndex = 0;

  size_t count = fread((void *) DeepState_Input, 1, to_read, fp);
  fclose(fp);

  if (count != to_read) {
    /* TODO(joe): Add error log with more info. */
    DeepState_Abandon("Error reading file");
  }

  DeepState_InputInitialized = count;

  DeepState_LogFormat(DeepState_LogTrace,
                      "Initialized test input buffer with %zu bytes of data from `%s`",
                      count, path);
}
DEEPSTATE_END_EXTERN_C