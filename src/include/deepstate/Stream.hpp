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
#ifndef SRC_INCLUDE_DEEPSTATE_STREAM_HPP_
#define SRC_INCLUDE_DEEPSTATE_STREAM_HPP_

#include <deepstate/DeepState.h>
#include <deepstate/Stream.h>

#include <cstddef>
#include <string>

namespace deepstate {

/* Conditionally stream output to a log using the streaming APIs. */
class Stream {
 public:
  DEEPSTATE_INLINE Stream(DeepState_LogLevel level_, bool do_log_,
                          const char *file, unsigned line)
      : level(level_),
        do_log(!!DeepState_IsTrue(do_log_)),
        has_something_to_log(false) {
    DeepState_LogStream(level);
    if (do_log) {
      DeepState_StreamFormat(level, "%s(%u): ", file, line);
    }
  }

  DEEPSTATE_INLINE ~Stream(void) {
    if (do_log) {
      if (has_something_to_log) {
        DeepState_LogStream(level);
      } else {
        DeepState_ClearStream(level);
      }
    }
  }

#define DEEPSTATE_DEFINE_STREAMER(Type, type, expr) \
  DEEPSTATE_INLINE const Stream &operator<<(type val) const { \
    if (do_log) { \
      DeepState_Stream ## Type(level, expr); \
      has_something_to_log = true; \
    } \
    return *this; \
  }

  DEEPSTATE_DEFINE_STREAMER(UInt64, uint64_t, val)
  DEEPSTATE_DEFINE_STREAMER(Int64, int64_t, val)

  DEEPSTATE_DEFINE_STREAMER(UInt32, uint32_t, val)
  DEEPSTATE_DEFINE_STREAMER(Int32, int32_t, val)

  DEEPSTATE_DEFINE_STREAMER(UInt16, uint16_t, val)
  DEEPSTATE_DEFINE_STREAMER(Int16, int16_t, val)

  DEEPSTATE_DEFINE_STREAMER(UInt8, uint8_t, val)
  DEEPSTATE_DEFINE_STREAMER(Int8, int8_t, val)

  DEEPSTATE_DEFINE_STREAMER(Float, float, val)
  DEEPSTATE_DEFINE_STREAMER(Double, double, val)

  DEEPSTATE_DEFINE_STREAMER(CStr, const char *, val)
  DEEPSTATE_DEFINE_STREAMER(CStr, char *, const_cast<const char *>(val))

  DEEPSTATE_DEFINE_STREAMER(Pointer, std::nullptr_t, nullptr)

  template <typename T>
  DEEPSTATE_DEFINE_STREAMER(Pointer, T *, val);

  template <typename T>
  DEEPSTATE_DEFINE_STREAMER(Pointer, const T *, const_cast<T *>(val));

#undef DEEPSTATE_DEFINE_INT_STREAMER

  DEEPSTATE_INLINE const Stream &operator<<(const std::string &str) const {
    if (do_log && !str.empty()) {
      DeepState_StreamCStr(level, str.c_str());
      has_something_to_log = true;
    }
    return *this;
  }

  // TODO(pag): Implement a `std::wstring` streamer.

 private:
  Stream(void) = delete;
  Stream(const Stream &) = delete;
  Stream &operator=(const Stream &) = delete;

  const DeepState_LogLevel level;
  const bool do_log;
  mutable bool has_something_to_log;
};

}  // namespace deepstate

#endif  // SRC_INCLUDE_DEEPSTATE_STREAM_HPP_
