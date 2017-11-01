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
#ifndef SRC_INCLUDE_MCTEST_STREAM_HPP_
#define SRC_INCLUDE_MCTEST_STREAM_HPP_

#include <mctest/McTest.h>
#include <mctest/Stream.h>

#include <cstddef>
#include <string>

namespace mctest {

/* Conditionally stream output to a log using the streaming APIs. */
class Stream {
 public:
  MCTEST_INLINE Stream(McTest_LogLevel level_, bool do_log_,
                       const char *file, unsigned line)
      : level(level_),
        do_log(McTest_IsTrue(do_log_)) {
    McTest_LogStream(level);
    if (do_log) {
      McTest_StreamFormat(level, "%s(%u): ", file, line);
    }
  }

  MCTEST_INLINE ~Stream(void) {
    if (do_log) {
      McTest_LogStream(level);
    }
  }

#define MCTEST_DEFINE_STREAMER(Type, type, expr) \
  MCTEST_INLINE const Stream &operator<<(type val) const { \
    if (do_log) { \
      McTest_Stream ## Type(level, expr); \
    } \
    return *this; \
  }

  MCTEST_DEFINE_STREAMER(UInt64, uint64_t, val)
  MCTEST_DEFINE_STREAMER(Int64, int64_t, val)

  MCTEST_DEFINE_STREAMER(UInt32, uint32_t, val)
  MCTEST_DEFINE_STREAMER(Int32, int32_t, val)

  MCTEST_DEFINE_STREAMER(UInt16, uint16_t, val)
  MCTEST_DEFINE_STREAMER(Int16, int16_t, val)

  MCTEST_DEFINE_STREAMER(UInt8, uint8_t, val)
  MCTEST_DEFINE_STREAMER(Int8, int8_t, val)

  MCTEST_DEFINE_STREAMER(Float, float, val)
  MCTEST_DEFINE_STREAMER(Double, double, val)

  MCTEST_DEFINE_STREAMER(CStr, const char *, val)
  MCTEST_DEFINE_STREAMER(CStr, char *, const_cast<const char *>(val))

  MCTEST_DEFINE_STREAMER(Pointer, nullptr_t, nullptr)

  template <typename T>
  MCTEST_DEFINE_STREAMER(Pointer, T *, val);

  template <typename T>
  MCTEST_DEFINE_STREAMER(Pointer, const T *, const_cast<T *>(val));

#undef MCTEST_DEFINE_INT_STREAMER

  MCTEST_INLINE const Stream &operator<<(const std::string &str) const {
    if (do_log && !str.empty()) {
      McTest_StreamCStr(level, str.c_str());
    }
    return *this;
  }

  // TODO(pag): Implement a `std::wstring` streamer.

 private:
  Stream(void) = delete;
  Stream(const Stream &) = delete;
  Stream &operator=(const Stream &) = delete;

  const McTest_LogLevel level;
  const int do_log;
};

}  // namespace mctest

#endif  // SRC_INCLUDE_MCTEST_STREAM_HPP_
