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

#ifndef INCLUDE_MCTEST_MCTEST_HPP_
#define INCLUDE_MCTEST_MCTEST_HPP_

#include <mctest/McTest.h>

#include <string>
#include <utility>
#include <vector>

namespace mctest {

inline static void *Malloc(size_t num_bytes) {
  return McTest_Malloc(num_bytes);
}

inline static void SymbolizeData(void *begin, void *end) {
  McTest_SymbolizeData(begin, end);
}

inline static bool Bool(void) {
  return static_cast<bool>(McTest_Bool());
}

inline static size_t Size(void) {
  return McTest_Size();
}

inline static uint64_t UInt64(void) {
  return McTest_UInt64();
}

inline static int64_t Int64(void) {
  return McTest_Int64();
}

inline static uint32_t UInt(void) {
  return McTest_UInt();
}

inline static int32_t Int(void) {
  return McTest_Int();
}

inline static uint16_t UShort(void) {
  return McTest_UShort();
}

inline static int16_t Short(void) {
  return McTest_Short();
}

inline static unsigned char UChar(void) {
  return McTest_UChar();
}

inline static char Char(void) {
  return McTest_Char();
}

inline static int IsSymbolic(uint64_t x) {
  return McTest_IsSymbolicUInt64(x);
}

inline static int IsSymbolic(int64_t x) {
  return McTest_IsSymbolicInt64(x);
}

inline static int IsSymbolic(uint32_t x) {
  return McTest_IsSymbolicUInt(x);
}

inline static int IsSymbolic(int32_t x) {
  return McTest_IsSymbolicInt(x);
}

inline static int IsSymbolic(uint16_t x) {
  return McTest_IsSymbolicUShort(x);
}

inline static int IsSymbolic(int16_t x) {
  return McTest_IsSymbolicShort(x);
}

inline static int IsSymbolic(unsigned char x) {
  return McTest_IsSymbolicUChar(x);
}

inline static int IsSymbolic(char x) {
  return McTest_IsSymbolicChar(x);
}

inline static int IsSymbolic(float x) {
  return McTest_IsSymbolicFloat(x);
}

inline static int IsSymbolic(double x) {
  return McTest_IsSymbolicDouble(x);
}

inline static int IsSymbolic(void *x) {
  return McTest_IsSymbolicPtr(x);
}

template <typename T>
class Symbolic {
 public:
  template <typename... Args>
  inline Symbolic(Args&& ...args)
      : value(std::forward<Args...>(args)...) {}

  inline Symbolic(void) {
    T *val_ptr = &value;
    McTest_SymbolizeData(val_ptr, &(val_ptr[1]));
  }

  inline operator T (void) const {
    return value;
  }

  T value;
};

template <T>
class SymbolicLinearContainer {
 public:
  inline explicit Symbolic(size_t len)
      : value(len) {
    if (len) {
      McTest_SymbolizeData(&(str.begin()), &(str.end()));
    }
  }

  inline operator T (void) const {
    return value;
  }

  T value;

 private:
  Symblic(void) = delete;
};

template <>
class Symbolic<std::string> : public SymbolicLinearContainer<std::string> {};

template <>
class Symbolic<std::wstring> : public SymbolicLinearContainer<std::wstring> {};

template <typename T>
class Symbolic<std::vector<T>> : 
    public SymbolicLinearContainer<std::vector<T>> {};

#define MAKE_SYMBOL_SPECIALIZATION(Tname, tname) \
    template <> \
    class Symbolic<tname> { \
     public: \
      inline Symbolic(void)
          : value(McTest_ ## Tname) {} \
      inline operator tname (void) const { \
        return value; \
      } \
      tname value; \
    };

MAKE_SYMBOL_SPECIALIZATION(UInt64, uint64_t)
MAKE_SYMBOL_SPECIALIZATION(Int64, int64_t)
MAKE_SYMBOL_SPECIALIZATION(UInt, uint32_t)
MAKE_SYMBOL_SPECIALIZATION(Int, int32_t)
MAKE_SYMBOL_SPECIALIZATION(UShort, uint16_t)
MAKE_SYMBOL_SPECIALIZATION(Short, int16_t)
MAKE_SYMBOL_SPECIALIZATION(UChar, uint8_t)
MAKE_SYMBOL_SPECIALIZATION(Char, int8_t)

#undef MAKE_SYMBOL_SPECIALIZATION

}  // namespace mctest

#endif  // INCLUDE_MCTEST_MCTEST_HPP_
