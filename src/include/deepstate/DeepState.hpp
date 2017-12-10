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

#ifndef SRC_INCLUDE_DEEPSTATE_DEEPSTATE_HPP_
#define SRC_INCLUDE_DEEPSTATE_DEEPSTATE_HPP_

#include <deepstate/DeepState.h>
#include <deepstate/Stream.hpp>

#include <functional>
#include <string>
#include <utility>
#include <vector>

namespace deepstate {

DEEPSTATE_INLINE static void *Malloc(size_t num_bytes) {
  return DeepState_Malloc(num_bytes);
}

DEEPSTATE_INLINE static void SymbolizeData(void *begin, void *end) {
  DeepState_SymbolizeData(begin, end);
}

DEEPSTATE_INLINE static bool Bool(void) {
  return static_cast<bool>(DeepState_Bool());
}

DEEPSTATE_INLINE static size_t Size(void) {
  return DeepState_Size();
}

DEEPSTATE_INLINE static uint64_t UInt64(void) {
  return DeepState_UInt64();
}

DEEPSTATE_INLINE static int64_t Int64(void) {
  return DeepState_Int64();
}

DEEPSTATE_INLINE static uint32_t UInt(void) {
  return DeepState_UInt();
}

DEEPSTATE_INLINE static int32_t Int(void) {
  return DeepState_Int();
}

DEEPSTATE_INLINE static uint16_t UShort(void) {
  return DeepState_UShort();
}

DEEPSTATE_INLINE static int16_t Short(void) {
  return DeepState_Short();
}

DEEPSTATE_INLINE static unsigned char UChar(void) {
  return DeepState_UChar();
}

DEEPSTATE_INLINE static char Char(void) {
  return DeepState_Char();
}

DEEPSTATE_INLINE static bool IsSymbolic(uint64_t x) {
  return DeepState_IsSymbolicUInt64(x);
}

DEEPSTATE_INLINE static int IsSymbolic(int64_t x) {
  return DeepState_IsSymbolicInt64(x);
}

DEEPSTATE_INLINE static bool IsSymbolic(uint32_t x) {
  return DeepState_IsSymbolicUInt(x);
}

DEEPSTATE_INLINE static bool IsSymbolic(int32_t x) {
  return DeepState_IsSymbolicInt(x);
}

DEEPSTATE_INLINE static int IsSymbolic(uint16_t x) {
  return DeepState_IsSymbolicUShort(x);
}

DEEPSTATE_INLINE static bool IsSymbolic(int16_t x) {
  return DeepState_IsSymbolicShort(x);
}

DEEPSTATE_INLINE static bool IsSymbolic(unsigned char x) {
  return DeepState_IsSymbolicUChar(x);
}

DEEPSTATE_INLINE static bool IsSymbolic(char x) {
  return DeepState_IsSymbolicChar(x);
}

DEEPSTATE_INLINE static bool IsSymbolic(float x) {
  return DeepState_IsSymbolicFloat(x);
}

DEEPSTATE_INLINE static bool IsSymbolic(double x) {
  return DeepState_IsSymbolicDouble(x);
}

// A test fixture.
class Test {
 public:
  Test(void) = default;
  ~Test(void) = default;
  inline void SetUp(void) {}
  inline void TearDown(void) {}

 private:
  Test(const Test &) = delete;
  Test(Test &&) = delete;
  Test &operator=(const Test &) = delete;
  Test &operator=(Test &&) = delete;
};

template <typename T>
class Symbolic {
 public:
  template <typename... Args>
  DEEPSTATE_INLINE Symbolic(Args&& ...args)
      : value(std::forward<Args...>(args)...) {}

  DEEPSTATE_INLINE Symbolic(void) {
    T *val_ptr = &value;
    DeepState_SymbolizeData(val_ptr, &(val_ptr[1]));
  }

  DEEPSTATE_INLINE operator T (void) const {
    return value;
  }

  T value;
};

template <typename T>
class SymbolicLinearContainer {
 public:
  DEEPSTATE_INLINE explicit SymbolicLinearContainer(size_t len)
      : value(len) {
    if (!value.empty()) {
      DeepState_SymbolizeData(&(value.front()), &(value.back()));
    }
  }

  DEEPSTATE_INLINE SymbolicLinearContainer(void)
      : SymbolicLinearContainer(DeepState_SizeInRange(0, 32)) {}

  DEEPSTATE_INLINE operator T (void) const {
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
      DEEPSTATE_INLINE Symbolic(void) \
          : value(DeepState_ ## Tname()) {} \
      DEEPSTATE_INLINE operator tname (void) const { \
        return value; \
      } \
      DEEPSTATE_INLINE tname operator+(const tname that) const { \
        return value + that; \
      } \
      DEEPSTATE_INLINE tname operator-(const tname that) const { \
        return value - that; \
      } \
      DEEPSTATE_INLINE tname operator*(const tname that) const { \
        return value * that; \
      } \
      DEEPSTATE_INLINE tname operator/(const tname that) const { \
        return value / that; \
      } \
      DEEPSTATE_INLINE tname operator|(const tname that) const { \
        return value | that; \
      } \
      DEEPSTATE_INLINE tname operator&(const tname that) const { \
        return value & that; \
      } \
      DEEPSTATE_INLINE tname operator^(const tname that) const { \
        return value ^ that; \
      } \
      DEEPSTATE_INLINE tname operator~(void) const { \
        return ~value; \
      } \
      DEEPSTATE_INLINE tname operator-(void) const { \
        return -value; \
      } \
      DEEPSTATE_INLINE tname operator>>(const tname that) const { \
        return value >> that; \
      } \
      DEEPSTATE_INLINE tname operator<<(const tname that) const { \
        return value << that; \
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


using symbolic_char = Symbolic<char>;
using symbolic_short = Symbolic<short>;
using symbolic_int = Symbolic<int>;
using symbolic_unsigned = Symbolic<unsigned>;
using symbolic_long = Symbolic<long>;

using symbolic_int8_t = Symbolic<int8_t>;
using symbolic_uint8_t = Symbolic<uint8_t>;
using symbolic_int16_t = Symbolic<int16_t>;
using symbolic_uint16_t = Symbolic<uint16_t>;
using symbolic_int32_t = Symbolic<int32_t>;
using symbolic_uint32_t = Symbolic<uint32_t>;
using symbolic_int64_t = Symbolic<int64_t>;
using symbolic_uint64_t = Symbolic<uint64_t>;

#undef MAKE_SYMBOL_SPECIALIZATION

#define MAKE_MINIMIZER(Type, type) \
    DEEPSTATE_INLINE static type Minimize(type val) { \
      return DeepState_Min ## Type(val); \
    } \
    DEEPSTATE_INLINE static type Maximize(type val) { \
      return DeepState_Max ## Type(val); \
    }

MAKE_MINIMIZER(UInt, uint32_t)
MAKE_MINIMIZER(Int, int32_t)
MAKE_MINIMIZER(UShort, uint16_t)
MAKE_MINIMIZER(Short, int16_t)
MAKE_MINIMIZER(UChar, uint8_t)
MAKE_MINIMIZER(Char, int8_t)

#undef MAKE_MINIMIZER

template <typename T>
static T Pump(T val, unsigned max=10) {
  if (!IsSymbolic(val)) {
    return val;
  }
  for (auto i = 0U; i < max; ++i) {
    T min_val = Minimize(val);
    if (val == min_val) {
      asm volatile ("" : : "m"(min_val) : "memory");
      return min_val;  // Force the concrete `min_val` to be returned,
                       // as opposed to compiler possibly choosing to
                       // return `val`.
    }
  }
  return Minimize(val);
}

template <typename... Args>
inline static void ForAll(void (*func)(Args...)) {
  func(Symbolic<Args>()...);
}

template <typename... Args, typename Closure>
inline static void ForAll(Closure func) {
  func(Symbolic<Args>()...);
}

template <typename... FuncTys>
inline static void OneOf(FuncTys&&... funcs) {
  std::function<void(void)> func_arr[sizeof...(FuncTys)] = {funcs...};
  func_arr[DeepState_SizeInRange(0, sizeof...(funcs))]();
}

}  // namespace deepstate

#define ONE_OF ::deepstate::OneOf

#define TEST(category, name) \
    DeepState_EntryPoint(category ## _ ## name)

#define _TEST_F(fixture_name, test_name, file, line) \
    class fixture_name ## _ ## test_name : public fixture_name { \
     public: \
      void DoRunTest(void); \
      static void RunTest(void) { \
        do { \
          fixture_name ## _ ## test_name self; \
          self.SetUp(); \
          self.DoRunTest(); \
          self.TearDown(); \
        } while (false); \
        DeepState_Pass(); \
      } \
      static struct DeepState_TestInfo kTestInfo; \
    }; \
    struct DeepState_TestInfo fixture_name ## _ ## test_name::kTestInfo = { \
      nullptr, \
      fixture_name ## _ ## test_name::RunTest, \
      DEEPSTATE_TO_STR(fixture_name ## _ ## test_name), \
      file, \
      line, \
    }; \
    DEEPSTATE_INITIALIZER(DeepState_Register_ ## test_name) { \
      fixture_name ## _ ## test_name::kTestInfo.prev = DeepState_LastTestInfo; \
      DeepState_LastTestInfo = &(fixture_name ## _ ## test_name::kTestInfo); \
    } \
    void fixture_name ## _ ## test_name :: DoRunTest(void)


#define TEST_F(fixture_name, test_name) \
    _TEST_F(fixture_name, test_name, __FILE__, __LINE__)

#define LOG_DEBUG(cond) \
    ::deepstate::Stream(DeepState_LogDebug, (cond), __FILE__, __LINE__)

#define LOG_INFO(cond) \
    ::deepstate::Stream(DeepState_LogInfo, (cond), __FILE__, __LINE__)

#define LOG_WARNING(cond) \
    ::deepstate::Stream(DeepState_LogWarning, (cond), __FILE__, __LINE__)

#define LOG_WARN(cond) \
    ::deepstate::Stream(DeepState_LogWarning, (cond), __FILE__, __LINE__)

#define LOG_ERROR(cond) \
    ::deepstate::Stream(DeepState_LogError, (cond), __FILE__, __LINE__)

#define LOG_FATAL(cond) \
    ::deepstate::Stream(DeepState_LogFatal, (cond), __FILE__, __LINE__)

#define LOG_CRITICAl(cond) \
    ::deepstate::Stream(DeepState_LogFatal, (cond), __FILE__, __LINE__)

#define LOG(LEVEL) LOG_ ## LEVEL(true)

#define LOG_IF(LEVEL, cond) LOG_ ## LEVEL(cond)

#define DEEPSTATE_LOG_BINOP(a, b, op, level) \
    ::deepstate::Stream( \
        level, !((a) op (b)), __FILE__, __LINE__)

#define ASSERT_EQ(a, b) DEEPSTATE_LOG_BINOP(a, b, ==, DeepState_LogFatal)
#define ASSERT_NE(a, b) DEEPSTATE_LOG_BINOP(a, b, !=, DeepState_LogFatal)
#define ASSERT_LT(a, b) DEEPSTATE_LOG_BINOP(a, b, <, DeepState_LogFatal)
#define ASSERT_LE(a, b) DEEPSTATE_LOG_BINOP(a, b, <=, DeepState_LogFatal)
#define ASSERT_GT(a, b) DEEPSTATE_LOG_BINOP(a, b, >, DeepState_LogFatal)
#define ASSERT_GE(a, b) DEEPSTATE_LOG_BINOP(a, b, >=, DeepState_LogFatal)

#define CHECK_EQ(a, b) DEEPSTATE_LOG_BINOP(a, b, ==, DeepState_LogError)
#define CHECK_NE(a, b) DEEPSTATE_LOG_BINOP(a, b, !=, DeepState_LogError)
#define CHECK_LT(a, b) DEEPSTATE_LOG_BINOP(a, b, <, DeepState_LogError)
#define CHECK_LE(a, b) DEEPSTATE_LOG_BINOP(a, b, <=, DeepState_LogError)
#define CHECK_GT(a, b) DEEPSTATE_LOG_BINOP(a, b, >, DeepState_LogError)
#define CHECK_GE(a, b) DEEPSTATE_LOG_BINOP(a, b, >=, DeepState_LogError)

#define ASSERT(expr) \
    ::deepstate::Stream( \
        DeepState_LogFatal, !(expr), __FILE__, __LINE__)

#define ASSERT_TRUE ASSERT
#define ASSERT_FALSE(expr) ASSERT(!(expr))

#define CHECK(expr) \
    ::deepstate::Stream( \
        DeepState_LogError, !(expr), __FILE__, __LINE__)

#define CHECK_TRUE CHECK
#define CHECK_FALSE(expr) CHECK(!(expr))

#define ASSUME(expr) \
    DeepState_Assume(expr), ::deepstate::Stream( \
        DeepState_LogInfo, true, __FILE__, __LINE__)

#define DEEPSTATE_ASSUME_BINOP(a, b, op) \
    DeepState_Assume(((a) op (b))), ::deepstate::Stream( \
        DeepState_LogInfo, true, __FILE__, __LINE__)

#define ASSUME_EQ(a, b) DEEPSTATE_ASSUME_BINOP(a, b, ==)
#define ASSUME_NE(a, b) DEEPSTATE_ASSUME_BINOP(a, b, !=)
#define ASSUME_LT(a, b) DEEPSTATE_ASSUME_BINOP(a, b, <)
#define ASSUME_LE(a, b) DEEPSTATE_ASSUME_BINOP(a, b, <=)
#define ASSUME_GT(a, b) DEEPSTATE_ASSUME_BINOP(a, b, >)
#define ASSUME_GE(a, b) DEEPSTATE_ASSUME_BINOP(a, b, >=)

#endif  // SRC_INCLUDE_DEEPSTATE_DEEPSTATE_HPP_
