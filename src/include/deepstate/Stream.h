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

#ifndef SRC_INCLUDE_DEEPSTATE_STREAM_H_
#define SRC_INCLUDE_DEEPSTATE_STREAM_H_

#include <stdarg.h>
#include <stdint.h>

#include <deepstate/Compiler.h>
#include <deepstate/Log.h>

DEEPSTATE_BEGIN_EXTERN_C

/* Clear the contents of the stream and don't log it. */
extern void DeepState_ClearStream(enum DeepState_LogLevel level);

/* Flush the contents of the stream to a log. */
extern void DeepState_LogStream(enum DeepState_LogLevel level);

/* Stream a C string into the stream's message. */
extern void DeepState_StreamCStr(enum DeepState_LogLevel level,
                                 const char *begin);

/* TODO(pag): Implement `DeepState_StreamWCStr` with `wchar_t`. */

/* Stream a some data in the inclusive range `[begin, end]` into the
 * stream's message. */
/*extern void DeepState_StreamData(
    enum DeepState_LogLevel level, const void *begin, const void *end); */

/* Stream some formatted input */
extern void DeepState_StreamFormat(
    enum DeepState_LogLevel level, const char *format, ...);

/* Stream some formatted input */
extern void DeepState_StreamVFormat(
    enum DeepState_LogLevel level, const char *format, va_list args);

#define DEEPSTATE_DECLARE_STREAMER(Type, type) \
    extern void DeepState_Stream ## Type( \
        enum DeepState_LogLevel level, type val);

DEEPSTATE_DECLARE_STREAMER(Double, double);
DEEPSTATE_DECLARE_STREAMER(Pointer, void *);

DEEPSTATE_DECLARE_STREAMER(UInt64, uint64_t)
DEEPSTATE_DECLARE_STREAMER(Int64, int64_t)

DEEPSTATE_DECLARE_STREAMER(UInt32, uint32_t)
DEEPSTATE_DECLARE_STREAMER(Int32, int32_t)

DEEPSTATE_DECLARE_STREAMER(UInt16, uint16_t)
DEEPSTATE_DECLARE_STREAMER(Int16, int16_t)

DEEPSTATE_DECLARE_STREAMER(UInt8, uint8_t)
DEEPSTATE_DECLARE_STREAMER(Int8, int8_t)

#undef DEEPSTATE_DECLARE_STREAMER

DEEPSTATE_INLINE static void DeepState_StreamFloat(
    enum DeepState_LogLevel level, float val) {
  DeepState_StreamDouble(level, (double) val);
}

/* Reset the formatting in a stream. */
extern void DeepState_StreamResetFormatting(enum DeepState_LogLevel level);

DEEPSTATE_END_EXTERN_C

#endif  /* SRC_INCLUDE_DEEPSTATE_STREAM_H_ */
