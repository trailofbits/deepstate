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

#ifndef SRC_INCLUDE_MCTEST_LOG_H_
#define SRC_INCLUDE_MCTEST_LOG_H_

#include <stdarg.h>

#include <mctest/Compiler.h>

MCTEST_BEGIN_EXTERN_C

struct McTest_Stream;

enum McTest_LogLevel {
  McTest_LogDebug = 0,
  McTest_LogInfo = 1,
  McTest_LogWarning = 2,
  McTest_LogWarn = McTest_LogWarning,
  McTest_LogError = 3,
  McTest_LogFatal = 4,
  McTest_LogCritical = McTest_LogFatal
};

/* Log a C string. */
extern void McTest_Log(enum McTest_LogLevel level, const char *str);

/* Log some formatted output. */
extern void McTest_LogFormat(enum McTest_LogLevel level,
                             const char *format, ...);

/* Log some formatted output. */
extern void McTest_LogVFormat(enum McTest_LogLevel level,
                              const char *format, va_list args);

MCTEST_END_EXTERN_C

#endif  /* SRC_INCLUDE_MCTEST_LOG_H_ */
