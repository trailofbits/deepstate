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

#ifndef SRC_INCLUDE_MCTEST_STREAM_H_
#define SRC_INCLUDE_MCTEST_STREAM_H_

#include <stdarg.h>
#include <stdint.h>

#include <mctest/Compiler.h>
#include <mctest/Log.h>

MCTEST_BEGIN_EXTERN_C

/* Flush the contents of the stream to a log. */
extern void McTest_LogStream(enum McTest_LogLevel level);

/* Stream a C string into the stream's message. */
extern void McTest_StreamCStr(enum McTest_LogLevel level, const char *begin);

/* TODO(pag): Implement `McTest_StreamWCStr` with `wchar_t`. */

/* Stream a some data in the inclusive range `[begin, end]` into the
 * stream's message. */
/*extern void McTest_StreamData(enum McTest_LogLevel level, const void *begin,
                              const void *end);*/

/* Stream some formatted input */
extern void McTest_StreamFormat(enum McTest_LogLevel level, const char *format,
                                ...);

/* Stream some formatted input */
extern void McTest_StreamVFormat(enum McTest_LogLevel level, const char *format,
                                 va_list args);

#define MCTEST_DECLARE_STREAMER(Type, type) \
    extern void McTest_Stream ## Type(enum McTest_LogLevel level, type val);

MCTEST_DECLARE_STREAMER(Double, double);
MCTEST_DECLARE_STREAMER(Pointer, void *);

MCTEST_DECLARE_STREAMER(UInt64, uint64_t)
MCTEST_DECLARE_STREAMER(Int64, int64_t)

MCTEST_DECLARE_STREAMER(UInt32, uint32_t)
MCTEST_DECLARE_STREAMER(Int32, int32_t)

MCTEST_DECLARE_STREAMER(UInt16, uint16_t)
MCTEST_DECLARE_STREAMER(Int16, int16_t)

MCTEST_DECLARE_STREAMER(UInt8, uint8_t)
MCTEST_DECLARE_STREAMER(Int8, int8_t)

#undef MCTEST_DECLARE_STREAMER

MCTEST_INLINE static void McTest_StreamFloat(enum McTest_LogLevel level,
                                             float val) {
  McTest_StreamDouble(level, (double) val);
}

/* Reset the formatting in a stream. */
extern void McTest_StreamResetFormatting(enum McTest_LogLevel level);

MCTEST_END_EXTERN_C

#endif  /* SRC_INCLUDE_MCTEST_STREAM_H_ */
