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

#ifndef SRC_INCLUDE_DEEPSTATE_PLATFORM_H_
#define SRC_INCLUDE_DEEPSTATE_PLATFORM_H_

#include <deepstate/Option.h>

DEEPSTATE_BEGIN_EXTERN_C

/* Contains information about a test case */
struct DeepState_TestInfo;

#if defined(_WIN32) || defined(_MSC_VER)

#include <windows.h>

DECLARE_bool(direct_run);

/* Maximum command length on Windows */
#define MAX_CMD_LEN 512

/* Enables the direct_run flag */
#define ENABLE_DIRECT_RUN_FLAG if (FLAGS_direct_run) { \
  DeepState_RunSingle(); \
  return 0; \
}

#define IS_REGULAR_FILE(PATH) ({ \
  DWORD file_attributes = GetFileAttributes(PATH); \
  file_attributes != INVALID_FILE_ATTRIBUTES && !(file_attributes & FILE_ATTRIBUTE_DIRECTORY); \
})

/* Match a regular expression pattern inside a given string 
  * TODO: implementation for Windows */
#define REG_MATCH(PATTERN, STRING) false

/* PRId64 definition */
#if !defined(PRId64) 
  #define PRId64 "lld" 
#endif 

/* Direct run of a test in a new Windows process. Platform specific function. */
extern int DeepState_RunTestWin(struct DeepState_TestInfo *test);

/* Direct run of a single test case. Platform specific function. */
extern void DeepState_RunSingle();
  

#elif defined(__unix)

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fnmatch.h>

#define ENABLE_DIRECT_RUN_FLAG

#define IS_REGULAR_FILE(PATH) ({ \
  struct stat path_stat; \
  stat(path, &path_stat); \
  S_ISREG(path_stat.st_mode); \
})

/* Match a regular expression pattern inside a given string */
#define REG_MATCH(PATTERN, STRING) (fnmatch(PATTERN, STRING, FNM_NOESCAPE))

#endif

DEEPSTATE_END_EXTERN_C

#endif /* SRC_INCLUDE_DEEPSTATE_PLATFORM_H_ */