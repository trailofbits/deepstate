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

#include "deepstate/DeepState.h"

DEEPSTATE_BEGIN_EXTERN_C

/* Returns a printable string version of the log level. */
static const char *DeepState_LogLevelStr(enum DeepState_LogLevel level) {
  switch (level) {
    case DeepState_LogDebug:
      return "DEBUG";
    case DeepState_LogInfo:
      return "INFO";
    case DeepState_LogWarning:
      return "WARNING";
    case DeepState_LogError:
      return "ERROR";
    case DeepState_LogFatal:
      return "FATAL";
    default:
      return "UNKNOWN";
  }
}

enum {
  DeepState_LogBufSize = 4096
};

char DeepState_LogBuf[DeepState_LogBufSize + 1] = {};

/* Log a C string. */
void DeepState_Log(enum DeepState_LogLevel level, const char *str) {
  memset(DeepState_LogBuf, 0, DeepState_LogBufSize);
  snprintf(DeepState_LogBuf, DeepState_LogBufSize, "%s: %s",
           DeepState_LogLevelStr(level), str);
  fputs(DeepState_LogBuf, stderr);

  if (DeepState_LogError == level) {
    DeepState_SoftFail();
  } else if (DeepState_LogFatal == level) {
    DeepState_Fail();
  }
}

/* Log some formatted output. */
void DeepState_LogFormat(enum DeepState_LogLevel level, const char *format, ...) {
  DeepState_LogStream(level);
  va_list args;
  va_start(args, format);
  DeepState_StreamVFormat(level, format, args);
  va_end(args);
  DeepState_LogStream(level);
}

/* Log some formatted output. */
void DeepState_LogVFormat(enum DeepState_LogLevel level,
                       const char *format, va_list args) {
  DeepState_LogStream(level);
  DeepState_StreamVFormat(level, format, args);
  DeepState_LogStream(level);
}

/* Override libc! */
int printf(const char *format, ...) {
  DeepState_LogStream(DeepState_LogInfo);
  va_list args;
  va_start(args, format);
  DeepState_StreamVFormat(DeepState_LogInfo, format, args);
  va_end(args);
  DeepState_LogStream(DeepState_LogInfo);
  return 0;
}

int fprintf(FILE *file, const char *format, ...) {
  enum DeepState_LogLevel level = DeepState_LogInfo;
  if (stderr == file) {
    level = DeepState_LogDebug;
  } else if (stdout != file) {
    return 0;  /* TODO(pag): This is probably evil. */
  }

  DeepState_LogStream(level);
  va_list args;
  va_start(args, format);
  DeepState_StreamVFormat(level, format, args);
  va_end(args);
  DeepState_LogStream(level);
  return 0;
}

DEEPSTATE_END_EXTERN_C
