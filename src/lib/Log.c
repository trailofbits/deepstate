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

/* Helps to avoid conflicting declaration types of `__printf_chk`. */
#define printf printf_foo
#define vprintf vprintf_foo
#define fprintf fprintf_foo
#define vfprintf vfprintf_foo
#define __printf_chk __printf_chk_foo
#define __vprintf_chk __vprintf_chk_foo
#define __fprintf_chk __fprintf_chk_foo
#define __vfprintf_chk __vfprintf_chk_foo

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "deepstate/DeepState.h"
#include "deepstate/Log.h"

#undef printf
#undef vprintf
#undef fprintf
#undef vfprintf
#undef __printf_chk
#undef __vprintf_chk
#undef __fprintf_chk
#undef __vfprintf_chk

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
    case DeepState_LogExternal:
      return "EXTERNAL";
    case DeepState_LogFatal:
      return "FATAL";
    default:
      return "UNKNOWN";
  }
}

enum {
  DeepState_LogBufSize = 4096
};

int DeepState_UsingLibFuzzer = 0;

char DeepState_LogBuf[DeepState_LogBufSize + 1] = {};

/* Log a C string. */
DEEPSTATE_NOINLINE
void DeepState_Log(enum DeepState_LogLevel level, const char *str) {
  if (DeepState_UsingLibFuzzer && (level < DeepState_LogExternal)) {
    return;
  }
  memset(DeepState_LogBuf, 0, DeepState_LogBufSize);
  snprintf(DeepState_LogBuf, DeepState_LogBufSize, "%s: %s\n",
           DeepState_LogLevelStr(level), str);
  fputs(DeepState_LogBuf, stderr);

  if (DeepState_LogError == level) {
    DeepState_SoftFail();
  } else if (DeepState_LogFatal == level) {
    /* `DeepState_Fail()` calls `longjmp()`, so we need to make sure
     * we clean up the log buffer first. */
    DeepState_ClearStream(level);
    DeepState_Fail();
  }
}

/* Log some formatted output. */
DEEPSTATE_NOINLINE
void DeepState_LogVFormat(enum DeepState_LogLevel level,
                          const char *format, va_list args) {
  struct DeepState_VarArgs va;
  va_copy(va.args, args);
  if (DeepState_UsingLibFuzzer && (level < DeepState_LogExternal)) {
    return;
  }
  DeepState_LogStream(level);
  DeepState_StreamVFormat(level, format, va.args);
  DeepState_LogStream(level);
}

/* Log some formatted output. */
DEEPSTATE_NOINLINE
void DeepState_LogVFormatLLVM(enum DeepState_LogLevel level,
			      const char *format, va_list args) {
  struct DeepState_VarArgs va;
  va_copy(va.args, args);
  DeepState_LogStream(level);
  DeepState_StreamVFormat(level, format, va.args);
  DeepState_LogStream(level);
}

/* Log some formatted output. */
DEEPSTATE_NOINLINE
void DeepState_LogFormat(enum DeepState_LogLevel level,
                         const char *format, ...) {
  va_list args;
  va_start(args, format);
  DeepState_LogVFormat(level, format, args);
  va_end(args);
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunknown-warning-option"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpragmas"
#pragma GCC diagnostic ignored "-Wbuiltin-declaration-mismatch"

/* Override libc! */
DEEPSTATE_NOINLINE
int puts(const char *str) {
  DeepState_Log(DeepState_LogInfo, str);
  return 0;
}

DEEPSTATE_NOINLINE
int printf(const char *format, ...) {
  va_list args;
  va_start(args, format);
  DeepState_LogVFormat(DeepState_LogInfo, format, args);
  va_end(args);
  return 0;
}

DEEPSTATE_NOINLINE
int __printf_chk(int flag, const char *format, ...) {
  va_list args;
  va_start(args, format);
  DeepState_LogVFormat(DeepState_LogInfo, format, args);
  va_end(args);
  return 0;
}

DEEPSTATE_NOINLINE
int vprintf(const char *format, va_list args) {
  DeepState_LogVFormat(DeepState_LogInfo, format, args);
  return 0;
}

DEEPSTATE_NOINLINE
int __vprintf_chk(int flag, const char *format, va_list args) {
  DeepState_LogVFormat(DeepState_LogInfo, format, args);
  return 0;
}

DEEPSTATE_NOINLINE
int vfprintf(FILE *file, const char *format, va_list args) {
  if (stderr == file) {
    DeepState_LogVFormat(DeepState_LogDebug, format, args);
  } else if (stdout == file) {
    DeepState_LogVFormat(DeepState_LogInfo, format, args);
  } else {
    DeepState_LogVFormat(DeepState_LogExternal, format, args);
  }
  /*
    Old code.  Now let's just log everything with odd dest as "external."

    if (!DeepState_UsingLibFuzzer) {
      if (strstr(format, "INFO:") != NULL) {
	// Assume such a string to an nonstd target is libFuzzer
	DeepState_LogVFormat(DeepState_LogExternal, format, args);
      } else {
	DeepState_LogStream(DeepState_LogWarning);
	DeepState_Log(DeepState_LogWarning,
		      "vfprintf with non-stdout/stderr stream follows:");
	DeepState_LogVFormat(DeepState_LogInfo, format, args);
      }
    } else {
      DeepState_LogVFormat(DeepState_LogExternal, format, args);      
    }
  */
  return 0;
}

DEEPSTATE_NOINLINE
int fprintf(FILE *file, const char *format, ...) {
  va_list args;
  va_start(args, format);
  vfprintf(file, format, args);
  va_end(args);
  return 0;
}

DEEPSTATE_NOINLINE
int __fprintf_chk(int flag, FILE *file, const char *format, ...) {
  va_list args;
  va_start(args, format);
  vfprintf(file, format, args);
  va_end(args);
  return 0;
}

DEEPSTATE_NOINLINE
int __vfprintf_chk(int flag, FILE *file, const char *format, va_list args) {
  vfprintf(file, format, args);
  return 0;
}

#pragma GCC diagnostic pop
#pragma clang diagnostic pop

DEEPSTATE_END_EXTERN_C
