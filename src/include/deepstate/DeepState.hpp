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

#ifndef SRC_INCLUDE_DEEPSTATE_DEEPSTATE_HPP_
#define SRC_INCLUDE_DEEPSTATE_DEEPSTATE_HPP_

#include <deepstate/DeepState.h>
#include <deepstate/Stream.hpp>

#include <functional>
#include <string>
#include <type_traits>
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
class Symbolic<T &> {};

template <typename T>
class SymbolicLinearContainer {
 public:
  DEEPSTATE_INLINE explicit SymbolicLinearContainer(size_t len)
      : value(len) {
    if (!value.empty()) {
      DeepState_SymbolizeData(&(value.front()), &(value.back()));
    }
  }

  DEEPSTATE_INLINE SymbolicLinearContainer(void) {
    value.reserve(32);
    value.resize(DeepState_SizeInRange(0, 32));  // Avoids symbolic `malloc`.
  }

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
      using SelfType = Symbolic<tname>; \
      \
      DEEPSTATE_INLINE Symbolic(void) \
          : value(DeepState_ ## Tname()) {} \
      \
      DEEPSTATE_INLINE Symbolic(tname that) \
          : value(that) {} \
      \
      DEEPSTATE_INLINE Symbolic(const SelfType &that) \
          : value(that.value) {} \
      \
      DEEPSTATE_INLINE Symbolic(SelfType &&that) \
          : value(std::move(that.value)) {} \
      \
      DEEPSTATE_INLINE operator tname (void) const { \
        return value; \
      } \
      SelfType &operator=(const SelfType &that) = default; \
      SelfType &operator=(SelfType &&that) = default; \
      SelfType &operator=(tname that) { \
        value = that; \
        return *this; \
      } \
      SelfType &operator+=(tname that) { \
        value += that; \
        return *this; \
      } \
      SelfType &operator-=(tname that) { \
        value -= that; \
        return *this; \
      } \
      SelfType &operator*=(tname that) { \
        value *= that; \
        return *this; \
      } \
      SelfType &operator/=(tname that) { \
        value /= that; \
        return *this; \
      } \
      SelfType &operator>>=(tname that) { \
        value >>= that; \
        return *this; \
      } \
      SelfType &operator<<=(tname that) { \
        value <<= that; \
        return *this; \
      } \
      tname &operator++(void) { \
        return ++value; \
      } \
      tname operator++(int) { \
        auto prev_value = value; \
        value++; \
        return prev_value; \
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
  if (!max) {
    DeepState_Abandon("Must have a positive maximum number of values to Pump");
  }
  for (auto i = 0U; i < max - 1; ++i) {
    T min_val = Minimize(val);
    if (val == min_val) {
      DEEPSTATE_USED(min_val);  // Force the concrete `min_val` to be returned,
                                // as opposed to compiler possibly choosing to
                                // return `val`.
      return min_val;
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

#define PureSwarmOneOf(...) _SwarmOneOf(__FILE__, __LINE__, DeepState_SwarmTypePure, __VA_ARGS__)
#define MixedSwarmOneOf(...) _SwarmOneOf(__FILE__, __LINE__, DeepState_SwarmTypeMixed, __VA_ARGS__)
#define ProbSwarmOneOf(...) _SwarmOneOf(__FILE__, __LINE__, DeepState_SwarmTypeProb, __VA_ARGS__)

#ifndef DEEPSTATE_PURE_SWARM
#ifndef DEEPSTATE_MIXED_SWARM
#ifndef DEEPSTATE_PROB_SWARM
#define OneOf(...) NoSwarmOneOf(__VA_ARGS__)
#endif
#endif
#endif

#ifdef DEEPSTATE_PURE_SWARM
#define OneOf(...) _SwarmOneOf(__FILE__, __LINE__, DeepState_SwarmTypePure, __VA_ARGS__)
#endif

#ifdef DEEPSTATE_MIXED_SWARM
#define OneOf(...) _SwarmOneOf(__FILE__, __LINE__, DeepState_SwarmTypeMixed, __VA_ARGS__)
#endif

#ifdef DEEPSTATE_PROB_SWARM
#define OneOf(...) _SwarmOneOf(__FILE__, __LINE__, DeepState_SwarmTypeProb, __VA_ARGS__)
#endif

template <typename... FuncTys>
inline static void OneOfP(double probs[], FuncTys&&... funcs) {
  if (FLAGS_verbose_reads) {
    printf("STARTING OneOf CALL\n");
  }
  std::function<void(void)> func_arr[sizeof...(FuncTys)] = {funcs...};
  double P = DeepState_DoubleInRange(0.0, 1.0);
  unsigned index = 0;
  while (P < probs[index]) {
    index++;
  }
  func_arr[index]();
  if (FLAGS_verbose_reads) {
    printf("FINISHED OneOf CALL\n");
  }
}

template <typename... FuncTys>
inline static void NoSwarmOneOf(FuncTys&&... funcs) {
  if (FLAGS_verbose_reads) {
    printf("STARTING OneOf CALL\n");
  }
  std::function<void(void)> func_arr[sizeof...(FuncTys)] = {funcs...};
  unsigned index = DeepState_UIntInRange(
      0U, static_cast<unsigned>(sizeof...(funcs))-1);
  func_arr[Pump(index, sizeof...(funcs))]();
  if (FLAGS_verbose_reads) {
    printf("FINISHED OneOf CALL\n");
  }
}

template <typename... FuncTys>
inline static void _SwarmOneOf(const char* file, unsigned line, enum DeepState_SwarmType stype,
			       FuncTys&&... funcs) {
  unsigned fcount = static_cast<unsigned>(sizeof...(funcs));
  std::function<void(void)> func_arr[sizeof...(FuncTys)] = {funcs...};
  struct DeepState_SwarmConfig* sc = DeepState_GetSwarmConfig(fcount, file, line, stype);
  if (FLAGS_verbose_reads) {
    printf("STARTING OneOf CALL\n");
  }
  unsigned index = DeepState_UIntInRange(0U, sc->fcount-1);
  func_arr[sc->fmap[Pump(index, sc->fcount)]]();
  if (FLAGS_verbose_reads) {
    printf("FINISHED OneOf CALL\n");
  }
}

inline static char NoSwarmOneOf(const char *str) {
  if (!str || !str[0]) {
    DeepState_Abandon("NULL or empty string passed to OneOf");
  }
  return str[DeepState_IntInRange(0, strlen(str) - 1)];
}

inline static char _SwarmOneOf(const char* file, unsigned line, enum DeepState_SwarmType stype, const char *str) {
  if (!str || !str[0]) {
    DeepState_Abandon("NULL or empty string passed to OneOf");
  }
  unsigned fcount = strlen(str);
  struct DeepState_SwarmConfig* sc = DeepState_GetSwarmConfig(fcount, file, line, stype);
  unsigned index = sc->fmap[DeepState_UIntInRange(0U, sc->fcount-1)];
  return str[index];
}

template <typename T>
inline static const T &NoSwarmOneOf(const std::vector<T> &arr) {
  if (arr.empty()) {
    DeepState_Abandon("Empty vector passed to OneOf");
  }
  return arr[DeepState_IntInRange(0, arr.size() - 1)];
}

template <typename T>
inline static const T &_SwarmOneOf(const char* file, unsigned line, enum DeepState_SwarmType stype, const std::vector<T> &arr) {
  if (arr.empty()) {
    DeepState_Abandon("Empty vector passed to OneOf");
  }
  unsigned fcount = arr.size();
  struct DeepState_SwarmConfig* sc = DeepState_GetSwarmConfig(fcount, file, line, stype);
  unsigned index = sc->fmap[DeepState_UIntInRange(0U, sc->fcount-1)];
  return arr[index];
}

template <typename T, int len>
inline static const T &NoSwarmOneOf(T (&arr)[len]) {
  if (!len) {
    DeepState_Abandon("Empty array passed to OneOf");
  }
  return arr[DeepState_IntInRange(0, len - 1)];
}

template <typename T, int len>
inline static const T &_SwarmOneOf(const char* file, unsigned line, enum DeepState_SwarmType stype, T (&arr)[len]) {
  if (!len) {
    DeepState_Abandon("Empty array passed to OneOf");
  }
  struct DeepState_SwarmConfig*	sc = DeepState_GetSwarmConfig(len, file, line, stype);
  unsigned index = sc->fmap[DeepState_UIntInRange(0U, sc->fcount-1)];
  return arr[index];
}


template <typename T, int k=sizeof(T) * 8>
struct ExpandedCompareIntegral {
  template <typename C>
  static DEEPSTATE_INLINE bool Compare(T a, T b, C cmp) {
    if (cmp((a & 0xFF), (b & 0xFF))) {
      return ExpandedCompareIntegral<T, k - 8>::Compare(a >> 8, b >> 8, cmp);
    }
    return DeepState_ZeroSink(k);  // Also false.
  }
};

template <typename T>
struct ExpandedCompareIntegral<T, 0> {
  template <typename C>
  static DEEPSTATE_INLINE bool Compare(T a, T b, C cmp) {
    if (cmp((a & 0xFF), (b & 0xFF))) {
      return DeepState_ZeroSink(0);
    } else {
      return DeepState_ZeroSink(100);
    }
  }
};

template <typename T>
struct DeclType {
  using Type = T;
};

template <typename T>
struct DeclType<T &> : public DeclType<T> {};

template <typename T>
struct DeclType<Symbolic<T>> : public DeclType<T> {};

template <typename T>
struct DeclType<Symbolic<T> &> : public DeclType<T> {};

template <typename T>
struct IsIntegral : public std::is_integral<T> {};

template <typename T>
struct IsIntegral<T &> : public IsIntegral<T> {};

template <typename T>
struct IsIntegral<Symbolic<T>> : public IsIntegral<T> {};

template <typename T>
struct IsSigned : public std::is_signed<T> {};

template <typename T>
struct IsSigned<T &> : public IsSigned<T> {};

template <typename T>
struct IsSigned<Symbolic<T>> : public IsSigned<T> {};

template <typename T>
struct IsUnsigned : public std::is_unsigned<T> {};

template <typename T>
struct IsUnsigned<T &> : public IsUnsigned<T> {};

template <typename T>
struct IsUnsigned<Symbolic<T>> : public std::is_unsigned<T> {};

template <typename A, typename B>
struct BestType {

  // type alias for bools, since std::make_unsigned<bool> returns unexpected behavior
  using _A = typename std::conditional<std::is_same<A, bool>::value, unsigned int, A>::type;
  using _B = typename std::conditional<std::is_same<B, bool>::value, unsigned int, B>::type;

  using UA = typename std::conditional<
      IsUnsigned<B>::value,
      typename std::make_unsigned<_A>::type, A>::type;

  using UB = typename std::conditional<
      IsUnsigned<A>::value,
      typename std::make_unsigned<_B>::type, B>::type;

  using Type = typename std::conditional<(sizeof(UA) > sizeof(UB)),
                                         UA, UB>::type;
};

template <typename A, typename B>
struct Comparer {
  static constexpr bool kIsIntegral = IsIntegral<A>() && IsIntegral<B>();
  static constexpr bool IsBool = std::is_same<A, bool>::value && std::is_same<B, bool>::value;

  struct tag_int {};
  struct tag_not_int {};

  using tag = typename std::conditional<kIsIntegral,tag_int,tag_not_int>::type;

  template <typename C>
  static DEEPSTATE_INLINE bool Do(const A &a, const B &b, C cmp, tag_not_int) {
    return cmp(a, b);
  }

  template <typename C>
  static DEEPSTATE_INLINE bool Do(A a, B b, C cmp, tag_int) {
    using T = typename ::deepstate::BestType<A, B>::Type;
    if (cmp(a, b)) {
      return true;
    }
    DEEPSTATE_USED(a);  // These make the compiler forget everything it knew
    DEEPSTATE_USED(b);  // about `a` and `b`.
    return ::deepstate::ExpandedCompareIntegral<T>::Compare(a, b, cmp);
  }

  template <typename C>
  static DEEPSTATE_INLINE bool Do(const A &a, const B &b, C cmp) {

    // IsIntegral returns true for booleans, so we override to basic overloaded method
    // if we have boolean template parameters passed to prevent error in ASSERT_EQ
    if (IsBool) {
      return Do(a, b, cmp, tag_not_int());
    }
    return Do(a, b, cmp, tag());
  }

};

#define DeepState_PureSwarmAssignCStr(...) _DeepState_SwarmAssignCStr(__FILE__, __LINE__, DeepState_SwarmTypePure, __VA_ARGS__)
#define DeepState_MixedSwarmAssignCStr(...) _DeepState_SwarmAssignCStr(__FILE__, __LINE__, DeepState_SwarmTypeMixed, __VA_ARGS__)
#define DeepState_ProbSwarmAssignCStr(...) _DeepState_SwarmAssignCStr(__FILE__, __LINE__, DeepState_SwarmTypeProb, __VA_ARGS__)

#define DeepState_PureSwarmAssignCStrUpToLen(...) _DeepState_SwarmAssignCStr(__FILE__, __LINE__, DeepState_SwarmTypePure, __VA_ARGS__)
#define DeepState_MixedSwarmAssignCStrUpToLen(...) _DeepState_SwarmAssignCStr(__FILE__, __LINE__, DeepState_SwarmTypeMixed, __VA_ARGS__)
#define DeepState_ProbSwarmAssignCStrUpToLen(...) _DeepState_SwarmAssignCStr(__FILE__, __LINE__, DeepState_SwarmTypeProb, __VA_ARGS__)

#define DeepState_PureSwarmCStr(...) _DeepState_SwarmCStr(__FILE__, __LINE__, DeepState_SwarmTypePure, __VA_ARGS__)
#define DeepState_MixedSwarmCStr(...) _DeepState_SwarmCStr(__FILE__, __LINE__, DeepState_SwarmTypeMixed, __VA_ARGS__)
#define DeepState_ProbSwarmCStr(...) _DeepState_SwarmCStr(__FILE__, __LINE__, DeepState_SwarmTypeProb, __VA_ARGS__)

#define DeepState_PureSwarmCStrUpToLen(...) _DeepState_SwarmCStr(__FILE__, __LINE__, DeepState_SwarmTypePure, __VA_ARGS__)
#define DeepState_MixedSwarmCStrUpToLen(...) _DeepState_SwarmCStr(__FILE__, __LINE__, DeepState_SwarmTypeMixed, __VA_ARGS__)
#define DeepState_ProbSwarmCStrUpToLen(...) _DeepState_SwarmCStr(__FILE__, __LINE__, DeepState_SwarmTypeProb, __VA_ARGS__)

#define DeepState_PureSwarmSymbolizeCStr(...) _DeepState_SwarmSymbolizeCStr(__FILE__, __LINE__, DeepState_SwarmTypePure, __VA_ARGS__)
#define DeepState_MixedSwarmSymbolizeCStr(...) _DeepState_SwarmSymbolizeCStr(__FILE__, __LINE__, DeepState_SwarmTypeMixed, __VA_ARGS__)
#define DeepState_ProbSwarmSymbolizeCStr(...) _DeepState_SwarmSymbolizeCStr(__FILE__, __LINE__, DeepState_SwarmTypeProb, __VA_ARGS__)

#ifndef DEEPSTATE_PURE_SWARM
#ifndef DEEPSTATE_MIXED_SWARM
#ifndef DEEPSTATE_PROB_SWARM
#define DeepState_AssignCStr(...) DeepState_NoSwarmAssignCStr(__VA_ARGS__)
#define DeepState_AssignCStrUpToLen(...) DeepState_NoSwarmAssignCStrUpToLen(__VA_ARGS__)
#define DeepState_CStr(...) DeepState_NoSwarmCStr(__VA_ARGS__)
#define DeepState_CStrUpToLen(...) DeepState_NoSwarmCStrUpToLen(__VA_ARGS__)
#define DeepState_SymbolizeCStr(...) DeepState_NoSwarmSymbolizeCStr(__VA_ARGS__)
#endif
#endif
#endif


#ifdef DEEPSTATE_PURE_SWARM
#define DeepState_AssignCStr(...) _DeepState_SwarmAssignCStr(__FILE__, __LINE__, DeepState_SwarmTypePure, __VA_ARGS__)
#define DeepState_AssignCStrUpToLen(...) _DeepState_SwarmAssignCStrUpToLen(__FILE__, __LINE__, DeepState_SwarmTypePure, __VA_ARGS__)
#define DeepState_CStr(...) _DeepState_SwarmCStr(__FILE__, __LINE__, DeepState_SwarmTypePure, __VA_ARGS__)
#define DeepState_CStrUpToLen(...) _DeepState_SwarmCStrUpToLen(__FILE__, __LINE__, DeepState_SwarmTypePure, __VA_ARGS__)
#define DeepState_SymbolizeCStr(...) _DeepState_SwarmSymbolizeCStr(__FILE__, __LINE__, DeepState_SwarmTypePure, __VA_ARGS__)
#endif

#ifdef DEEPSTATE_MIXED_SWARM
#define DeepState_AssignCStr(...) _DeepState_SwarmAssignCStr(__FILE__, __LINE__, DeepState_SwarmTypeMixed, __VA_ARGS__)
#define DeepState_AssignCStrUpToLen(...) _DeepState_SwarmAssignCStrUpToLen(__FILE__, __LINE__, DeepState_SwarmTypeMixed, __VA_ARGS__)
#define DeepState_CStr(...) _DeepState_SwarmCStr(__FILE__, __LINE__, DeepState_SwarmTypeMixed, __VA_ARGS__)
#define DeepState_CStrUpToLen(...) _DeepState_SwarmCStrUpToLen(__FILE__, __LINE__, DeepState_SwarmTypeMixed, __VA_ARGS__)
#define DeepState_SymbolizeCStr(...) _DeepState_SwarmSymbolizeCStr(__FILE__, __LINE__, DeepState_SwarmTypeMixed, __VA_ARGS__)
#endif

#ifdef DEEPSTATE_PROB_SWARM
#define DeepState_AssignCStr(...) _DeepState_SwarmAssignCStr(__FILE__, __LINE__, DeepState_SwarmTypeProb, __VA_ARGS__)
#define DeepState_AssignCStrUpToLen(...) _DeepState_SwarmAssignCStrUpToLen(__FILE__, __LINE__, DeepState_SwarmTypeProb, __VA_ARGS__)
#define DeepState_CStr(...) _DeepState_SwarmCStr(__FILE__, __LINE__, DeepState_SwarmTypeProb, __VA_ARGS__)
#define DeepState_CStrUpToLen(...) _DeepState_SwarmCStrUpToLen(__FILE__, __LINE__, DeepState_SwarmTypeProb, __VA_ARGS__)
#define DeepState_SymbolizeCStr(...) _DeepState_SwarmSymbolizeCStr(__FILE__, __LINE__, DeepState_SwarmTypeProb, __VA_ARGS__)
#endif

/* Like DeepState_AssignCStr_C, but fills in a null `allowed` value. */
inline static void DeepState_NoSwarmAssignCStr(char* str, size_t len,
					       const char* allowed = 0) {
  DeepState_AssignCStr_C(str, len, allowed);
}

inline static void _DeepState_SwarmAssignCStr(const char* file, unsigned line, enum DeepState_SwarmType stype,
					      char* str, size_t len,
					      const char* allowed = 0) {
  DeepState_SwarmAssignCStr_C(file, line, stype, str, len, allowed);
}

/* Like DeepState_AssignCStr, but Pumps through possible string sizes. */
inline static void DeepState_NoSwarmAssignCStrUpToLen(char* str, size_t max_len,
						      const char* allowed = 0) {
  uint32_t len = DeepState_UIntInRange(0, max_len);
  DeepState_AssignCStr_C(str, Pump(len, max_len+1), allowed);
}

inline static void _DeepState_SwarmAssignCStrUpToLen(const char* file, unsigned line, enum DeepState_SwarmType stype,
						     char* str, size_t max_len,
						     const char* allowed = 0) {
  uint32_t len = DeepState_UIntInRange(0, max_len);
  DeepState_SwarmAssignCStr_C(file, line, stype, str, Pump(len, max_len+1), allowed);
}

/* Like DeepState_CStr_C, but fills in a null `allowed` value. */
inline static char* DeepState_NoSwarmCStr(size_t len, const char* allowed = 0) {
  return DeepState_CStr_C(len, allowed);
}

inline static char* _DeepState_SwarmCStr(const char* file, unsigned line, enum DeepState_SwarmType stype,
					size_t len, const char* allowed = 0) {
  return DeepState_SwarmCStr_C(file, line, stype, len, allowed);
}

/* Like DeepState_CStr, but Pumps through possible string sizes. */
inline static char* DeepState_NoSwarmCStrUpToLen(size_t max_len, const char* allowed = 0) {
  uint32_t len = DeepState_UIntInRange(0, max_len);
  return DeepState_CStr_C(Pump(len, max_len+1), allowed);
}

inline static char* _DeepState_SwarmCStrUpToLen(const char* file, unsigned line, enum DeepState_SwarmType stype,
					       size_t max_len, const char* allowed = 0) {
  uint32_t len = DeepState_UIntInRange(0, max_len);
  return DeepState_SwarmCStr_C(file, line, stype, Pump(len, max_len+1), allowed);
}

/* Like DeepState_Symbolize_CStr, but fills in null `allowed` value. */
inline static void DeepState_NoSwarmSymbolizeCStr(char *begin, const char* allowed = 0) {
  DeepState_SymbolizeCStr_C(begin, allowed);
}

inline static void _DeepState_SwarmSymbolizeCStr(const char* file, unsigned line, enum DeepState_SwarmType stype,
						char *begin, const char* allowed = 0) {
  DeepState_SwarmSymbolizeCStr_C(file, line, stype, begin, allowed);
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


#define _EXPAND_COMPARE(a, b, op) \
  ([] (decltype(a) __a0, decltype(b) __b0) -> bool { \
    using __A = typename ::deepstate::DeclType<decltype(__a0)>::Type; \
    using __B = typename ::deepstate::DeclType<decltype(__b0)>::Type; \
    auto __cmp = [] (__A __a4, __B __b4) { return __a4 op __b4; }; \
    return ::deepstate::Comparer<__A, __B>::Do(__a0, __b0, __cmp); \
  })((a), (b))

#define TEST_F(fixture_name, test_name) \
    _TEST_F(fixture_name, test_name, __FILE__, __LINE__)

#define LOG_DEBUG(cond) \
    ::deepstate::Stream(DeepState_LogDebug, (cond), __FILE__, __LINE__)

#define LOG_TRACE(cond) \
    ::deepstate::Stream(DeepState_LogTrace, (cond), __FILE__, __LINE__)

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

#define LOG_CRITICAL(cond) \
    ::deepstate::Stream(DeepState_LogFatal, (cond), __FILE__, __LINE__)

#define LOG(LEVEL) LOG_ ## LEVEL(true)

#define LOG_IF(LEVEL, cond) LOG_ ## LEVEL(cond)

#define DEEPSTATE_LOG_EQNE(a, b, op, level) \
    ::deepstate::Stream( \
        level, !(_EXPAND_COMPARE(a, b, op)), __FILE__, __LINE__)

#define DEEPSTATE_LOG_BINOP(a, b, op, level) \
    ::deepstate::Stream( \
        level, !(a op b), __FILE__, __LINE__)

#define ASSERT_EQ(a, b) DEEPSTATE_LOG_EQNE(a, b, ==, DeepState_LogFatal)
#define ASSERT_NE(a, b) DEEPSTATE_LOG_EQNE(a, b, !=, DeepState_LogFatal)
#define ASSERT_LT(a, b) DEEPSTATE_LOG_BINOP(a, b, <, DeepState_LogFatal)
#define ASSERT_LE(a, b) DEEPSTATE_LOG_BINOP(a, b, <=, DeepState_LogFatal)
#define ASSERT_GT(a, b) DEEPSTATE_LOG_BINOP(a, b, >, DeepState_LogFatal)
#define ASSERT_GE(a, b) DEEPSTATE_LOG_BINOP(a, b, >=, DeepState_LogFatal)

#define CHECK_EQ(a, b) DEEPSTATE_LOG_EQNE(a, b, ==, DeepState_LogError)
#define CHECK_NE(a, b) DEEPSTATE_LOG_EQNE(a, b, !=, DeepState_LogError)
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
        DeepState_LogTrace, true, __FILE__, __LINE__)

#define DEEPSTATE_ASSUME_BINOP(a, b, op) \
    DeepState_Assume((a op b)), ::deepstate::Stream( \
        DeepState_LogTrace, true, __FILE__, __LINE__)

#define ASSUME_EQ(a, b) DEEPSTATE_ASSUME_BINOP(a, b, ==)
#define ASSUME_NE(a, b) DEEPSTATE_ASSUME_BINOP(a, b, !=)
#define ASSUME_LT(a, b) DEEPSTATE_ASSUME_BINOP(a, b, <)
#define ASSUME_LE(a, b) DEEPSTATE_ASSUME_BINOP(a, b, <=)
#define ASSUME_GT(a, b) DEEPSTATE_ASSUME_BINOP(a, b, >)
#define ASSUME_GE(a, b) DEEPSTATE_ASSUME_BINOP(a, b, >=)

#endif  // SRC_INCLUDE_DEEPSTATE_DEEPSTATE_HPP_
