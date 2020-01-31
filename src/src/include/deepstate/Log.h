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

#ifndef SRC_INCLUDE_DEEPSTATE_LOG_H_
#define SRC_INCLUDE_DEEPSTATE_LOG_H_

#include <stdarg.h>

#include <deepstate/Compiler.h>

DEEPSTATE_BEGIN_EXTERN_C

extern int DeepState_UsingLibFuzzer;
extern int DeepState_UsingSymExec;

struct DeepState_Stream;

struct DeepState_VarArgs {
  va_list args;
};

enum DeepState_LogLevel {
  DeepState_LogDebug = 0,
  DeepState_LogTrace = 1,  
  DeepState_LogInfo = 2,  
  DeepState_LogWarning = 3,
  DeepState_LogWarn = DeepState_LogWarning,
  DeepState_LogError = 4,
  DeepState_LogExternal = 5,
  DeepState_LogFatal = 6,
  DeepState_LogCritical = DeepState_LogFatal,
};

/* Log a C string. */
extern void DeepState_Log(enum DeepState_LogLevel level, const char *str);

/* Log some formatted output. */
extern void DeepState_LogFormat(enum DeepState_LogLevel level,
                                const char *format, ...);

/* Log some formatted output. */
extern void DeepState_LogVFormat(enum DeepState_LogLevel level,
                                 const char *format, va_list args);

DEEPSTATE_END_EXTERN_C

#endif  /* SRC_INCLUDE_DEEPSTATE_LOG_H_ */
