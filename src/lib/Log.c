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

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <mctest/McTest.h>

MCTEST_BEGIN_EXTERN_C

/* Returns a printable string version of the log level. */
static const char *McTest_LogLevelStr(enum McTest_LogLevel level) {
  switch (level) {
    case McTest_LogDebug:
      return "DEBUG";
    case McTest_LogInfo:
      return "INFO";
    case McTest_LogWarning:
      return "WARNING";
    case McTest_LogError:
      return "ERROR";
    case McTest_LogFatal:
      return "FATAL";
    default:
      return "UNKNOWN";
  }
}

enum {
  McTest_LogBufSize = 4096
};

char McTest_LogBuf[McTest_LogBufSize + 1] = {};

/* Log a C string. */
void McTest_Log(enum McTest_LogLevel level, const char *str) {
  memset(McTest_LogBuf, 0, McTest_LogBufSize);
  snprintf(McTest_LogBuf, McTest_LogBufSize, "%s: %s",
           McTest_LogLevelStr(level), str);
  fputs(McTest_LogBuf, stderr);

  if (McTest_LogError == level) {
    McTest_SoftFail();
  } else if (McTest_LogFatal == level) {
    McTest_Fail();
  }
}

/* Log some formatted output. */
void McTest_LogFormat(enum McTest_LogLevel level, const char *format, ...) {
  McTest_LogStream(level);
  va_list args;
  va_start(args, format);
  McTest_StreamVFormat(level, format, args);
  va_end(args);
  McTest_LogStream(level);
}

/* Log some formatted output. */
void McTest_LogVFormat(enum McTest_LogLevel level,
                       const char *format, va_list args) {
  McTest_LogStream(level);
  McTest_StreamVFormat(level, format, args);
  McTest_LogStream(level);
}

/* Override libc! */
int printf(const char *format, ...) {
  McTest_LogStream(McTest_LogInfo);
  va_list args;
  va_start(args, format);
  McTest_StreamVFormat(McTest_LogInfo, format, args);
  va_end(args);
  McTest_LogStream(McTest_LogInfo);
  return 0;
}

int fprintf(FILE *file, const char *format, ...) {
  enum McTest_LogLevel level = McTest_LogInfo;
  if (stderr == file) {
    level = McTest_LogDebug;
  } else if (stdout != file) {
    return 0;  /* TODO(pag): This is probably evil. */
  }

  McTest_LogStream(level);
  va_list args;
  va_start(args, format);
  McTest_StreamVFormat(level, format, args);
  va_end(args);
  McTest_LogStream(level);
  return 0;
}

MCTEST_END_EXTERN_C
