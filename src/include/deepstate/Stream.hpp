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
#ifndef SRC_INCLUDE_DEEPSTATE_STREAM_HPP_
#define SRC_INCLUDE_DEEPSTATE_STREAM_HPP_

#include <deepstate/DeepState.h>
#include <deepstate/Stream.h>

#include <cstddef>
#include <string>
#include <type_traits>

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

  DEEPSTATE_INLINE ~Stream() {
    if (do_log) {
      if (!has_something_to_log) {
        DeepState_StreamCStr(level, "Checked condition");
      }
      DeepState_LogStream(level);
    }
  }

  // The issue being addressed here is that there is a many-to-one mapping from the C integral types
  // (note 1) to the DeepState integral types (note 2). To address this, we define a operator<< for
  // each C integral type which invokes a helper method overloaded on size and unsignedness.
  // This helper method then invokes the correct DeepState_StreamXXX method. Adding a level of
  // indirection allows us to deal with the many-to-one mapping problem without worrying about
  // multiply-defining a method or leaving one out. For example on many systems, because long
  // and long long have the same size, operator<<(long) and operator<<(long long) will both invoke
  // Stream_IntType_Helper(8, false, int64_t).
  //
  // Example:
  // On my system unsigned short has size 2 and is unsigned. So operator<<(unsigned short val) will call
  // Stream_IntType_Helper(IC<2>, IB<true>, uint16_t val)
  // where IC<2> is shorthand for std::integral_constant<size_t, 2> (operand has size 2)
  // and IB<true> is shorthand for std::integral_constant<bool, true> (operand is unsigned).
  // These strange-looking types are used for "dispatching on tag" so the compiler can pick the
  // correct overload of Stream_IntType_Helper at compile time.
  // Finally Stream_IntType_Helper(IC<2>, IB<true>, uint16_t val) will call
  // Deepstate_Stream_Uint16(level, val)
  //
  // Note 1: char, signed char, unsigned char (yes there are three), short, unsigned short,
  //   int, unsigned int, long, unsigned long, long long, unsigned long long.
  // Note2: int8_t, uint8_t, int16_t, uint16_t, int32_t, uint32_t, int64_t, uint64_t.

#define DEEPSTATE_DEFINE_CTYPE_STREAMER(CType) \
  DEEPSTATE_INLINE const Stream &operator<<(CType val) const { \
    if (do_log) { \
      auto sizeTag = std::integral_constant<size_t, sizeof(CType)>(); \
      auto unsignedTag = std::is_unsigned<CType>(); \
      Stream_IntType_Helper(sizeTag, unsignedTag, val); \
      has_something_to_log = true; \
    } \
    return *this; \
  } \
  static_assert(true, "") /* force caller to supply a final semicolon */

  DEEPSTATE_DEFINE_CTYPE_STREAMER(char);
  DEEPSTATE_DEFINE_CTYPE_STREAMER(signed char);
  DEEPSTATE_DEFINE_CTYPE_STREAMER(unsigned char);
  DEEPSTATE_DEFINE_CTYPE_STREAMER(short);
  DEEPSTATE_DEFINE_CTYPE_STREAMER(unsigned short);
  DEEPSTATE_DEFINE_CTYPE_STREAMER(int);
  DEEPSTATE_DEFINE_CTYPE_STREAMER(unsigned int);
  DEEPSTATE_DEFINE_CTYPE_STREAMER(long);
  DEEPSTATE_DEFINE_CTYPE_STREAMER(unsigned long);
  DEEPSTATE_DEFINE_CTYPE_STREAMER(long long);
  DEEPSTATE_DEFINE_CTYPE_STREAMER(unsigned long long);
#undef DEEPSTATE_DEFINE_CTYPE_STREAMER

private:
#define DEEPSTATE_DEFINE_INT_STREAMER_HELPER(CType, DSType) \
  void Stream_IntType_Helper(std::integral_constant<size_t, sizeof(CType)> /*size_tag*/, \
      std::integral_constant<bool, std::is_unsigned<CType>::value> /*unsigned_tag*/, \
      CType val) const { \
    DeepState_Stream ## DSType(level, val); \
  } \
  static_assert(true, "") /* force caller to supply a final semicolon */
  DEEPSTATE_DEFINE_INT_STREAMER_HELPER(int8_t, Int8);
  DEEPSTATE_DEFINE_INT_STREAMER_HELPER(uint8_t, UInt8);
  DEEPSTATE_DEFINE_INT_STREAMER_HELPER(int16_t, Int16);
  DEEPSTATE_DEFINE_INT_STREAMER_HELPER(uint16_t, UInt16);
  DEEPSTATE_DEFINE_INT_STREAMER_HELPER(int32_t, Int32);
  DEEPSTATE_DEFINE_INT_STREAMER_HELPER(uint32_t, UInt32);
  DEEPSTATE_DEFINE_INT_STREAMER_HELPER(int64_t, Int64);
  DEEPSTATE_DEFINE_INT_STREAMER_HELPER(uint64_t, UInt64);
#undef DEEPSTATE_DEFINE_INT_STREAMER_HELPER
public:

#define DEEPSTATE_DEFINE_STREAMER(Type, type, expr) \
  DEEPSTATE_INLINE const Stream &operator<<(type val) const { \
    if (do_log) { \
      DeepState_Stream ## Type(level, expr); \
      has_something_to_log = true; \
    } \
    return *this; \
  } \
  static_assert(true, "") /* force our user to supply a final semicolon */

  DEEPSTATE_DEFINE_STREAMER(Float, float, val);
  DEEPSTATE_DEFINE_STREAMER(Double, double, val);

  DEEPSTATE_DEFINE_STREAMER(CStr, const char *, val);

  DEEPSTATE_DEFINE_STREAMER(Pointer, std::nullptr_t, nullptr);

  template <typename T>
  DEEPSTATE_DEFINE_STREAMER(Pointer, const T *, val);

#undef DEEPSTATE_DEFINE_STREAMER

  DEEPSTATE_INLINE const Stream &operator<<(const std::string &str) const {
    if (do_log && !str.empty()) {
      DeepState_StreamCStr(level, str.c_str());
      has_something_to_log = true;
    }
    return *this;
  }

  // TODO(pag): Implement a `std::wstring` streamer.

 public:
  Stream() = delete;
  Stream(const Stream &) = delete;
  Stream &operator=(const Stream &) = delete;

private:
  const DeepState_LogLevel level;
  const bool do_log;
  mutable bool has_something_to_log;
};

}  // namespace deepstate

#endif  // SRC_INCLUDE_DEEPSTATE_STREAM_HPP_
