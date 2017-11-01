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

#ifndef SRC_INCLUDE_MCTEST_MCTEST_HPP_
#define SRC_INCLUDE_MCTEST_MCTEST_HPP_

#include <mctest/McTest.h>

#include <string>
#include <utility>
#include <vector>

namespace mctest {

MCTEST_INLINE static void *Malloc(size_t num_bytes) {
  return McTest_Malloc(num_bytes);
}

MCTEST_INLINE static void SymbolizeData(void *begin, void *end) {
  McTest_SymbolizeData(begin, end);
}

MCTEST_INLINE static bool Bool(void) {
  return static_cast<bool>(McTest_Bool());
}

MCTEST_INLINE static size_t Size(void) {
  return McTest_Size();
}

MCTEST_INLINE static uint64_t UInt64(void) {
  return McTest_UInt64();
}

MCTEST_INLINE static int64_t Int64(void) {
  return McTest_Int64();
}

MCTEST_INLINE static uint32_t UInt(void) {
  return McTest_UInt();
}

MCTEST_INLINE static int32_t Int(void) {
  return McTest_Int();
}

MCTEST_INLINE static uint16_t UShort(void) {
  return McTest_UShort();
}

MCTEST_INLINE static int16_t Short(void) {
  return McTest_Short();
}

MCTEST_INLINE static unsigned char UChar(void) {
  return McTest_UChar();
}

MCTEST_INLINE static char Char(void) {
  return McTest_Char();
}

MCTEST_INLINE static bool IsSymbolic(uint64_t x) {
  return McTest_IsSymbolicUInt64(x);
}

MCTEST_INLINE static int IsSymbolic(int64_t x) {
  return McTest_IsSymbolicInt64(x);
}

MCTEST_INLINE static bool IsSymbolic(uint32_t x) {
  return McTest_IsSymbolicUInt(x);
}

MCTEST_INLINE static bool IsSymbolic(int32_t x) {
  return McTest_IsSymbolicInt(x);
}

MCTEST_INLINE static int IsSymbolic(uint16_t x) {
  return McTest_IsSymbolicUShort(x);
}

MCTEST_INLINE static bool IsSymbolic(int16_t x) {
  return McTest_IsSymbolicShort(x);
}

MCTEST_INLINE static bool IsSymbolic(unsigned char x) {
  return McTest_IsSymbolicUChar(x);
}

MCTEST_INLINE static bool IsSymbolic(char x) {
  return McTest_IsSymbolicChar(x);
}

MCTEST_INLINE static bool IsSymbolic(float x) {
  return McTest_IsSymbolicFloat(x);
}

MCTEST_INLINE static bool IsSymbolic(double x) {
  return McTest_IsSymbolicDouble(x);
}

template <typename T>
class Symbolic {
 public:
  template <typename... Args>
  MCTEST_INLINE Symbolic(Args&& ...args)
      : value(std::forward<Args...>(args)...) {}

  MCTEST_INLINE Symbolic(void) {
    T *val_ptr = &value;
    McTest_SymbolizeData(val_ptr, &(val_ptr[1]));
  }

  MCTEST_INLINE operator T (void) const {
    return value;
  }

  T value;
};

template <typename T>
class SymbolicLinearContainer {
 public:
  MCTEST_INLINE explicit SymbolicLinearContainer(size_t len)
      : value(len) {
    if (!value.empty()) {
      McTest_SymbolizeData(&(value.front()), &(value.back()));
    }
  }

  MCTEST_INLINE SymbolicLinearContainer(void)
      : SymbolicLinearContainer(McTest_SizeInRange(0, 32)) {}

  MCTEST_INLINE operator T (void) const {
    return value;
  }

  T value;
};

template <>
class Symbolic<std::string> : public SymbolicLinearContainer<std::string> {
  using SymbolicLinearContainer::SymbolicLinearContainer;
};

template <>
class Symbolic<std::wstring> : public SymbolicLinearContainer<std::wstring> {
  using SymbolicLinearContainer::SymbolicLinearContainer;
};

template <typename T>
class Symbolic<std::vector<T>> : 
    public SymbolicLinearContainer<std::vector<T>> {};

#define MAKE_SYMBOL_SPECIALIZATION(Tname, tname) \
    template <> \
    class Symbolic<tname> { \
     public: \
      MCTEST_INLINE Symbolic(void) \
          : value(McTest_ ## Tname()) {} \
      MCTEST_INLINE operator tname (void) const { \
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

#endif  // SRC_INCLUDE_MCTEST_MCTEST_HPP_
