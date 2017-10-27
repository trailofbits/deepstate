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

#ifndef INCLUDE_MCTEST_MCTEST_H_
#define INCLUDE_MCTEST_MCTEST_H_

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif  /* __cplusplus */

/* Symbolize the data in the range `[begin, end)`. */
extern void McTest_SymbolizeData(void *begin, void *end);

inline static void *McTest_Malloc(size_t num_bytes) {
  void *data = malloc(num_bytes);
  uintptr_t data_end = ((uintptr_t) data) + num_bytes;
  McTest_SymbolizeData(data, (void *) data_end);
  return data;
}

#define MCTEST_MAKE_SYMBOLIC_ARRAY(Tname, tname) \
    inline static tname *McTest_Symbolic ## Tname ## Array(size_t num_elms) { \
      tname *arr = (tname *) malloc(sizeof(tname) * num_elms); \
      McTest_SymbolizeData(arr, &(arr[num_elms])); \
      return arr; \
    }

MCTEST_MAKE_SYMBOLIC_ARRAY(Int64, int64_t)
MCTEST_MAKE_SYMBOLIC_ARRAY(UInt64, uint64_t)
MCTEST_MAKE_SYMBOLIC_ARRAY(Int, int)
MCTEST_MAKE_SYMBOLIC_ARRAY(UInt, uint32_t)
MCTEST_MAKE_SYMBOLIC_ARRAY(Short, int16_t)
MCTEST_MAKE_SYMBOLIC_ARRAY(UShort, uint16_t)
MCTEST_MAKE_SYMBOLIC_ARRAY(Char, char)
MCTEST_MAKE_SYMBOLIC_ARRAY(UChar, unsigned char)

#undef MCTEST_MAKE_SYMBOLIC_ARRAY

/* Return a symbolic C string. */
inline static char *McTest_CStr(size_t len) {
  char *str = (char *) malloc(sizeof(char) * len);
  if (len) {
    McTest_SymbolizeData(str, &(str[len - 1]));
    str[len - 1] = '\0';
  }
  return str;
}

/* Creates an assumption about a symbolic value. Returns `1` if the assumption
 * can hold and was asserted. */
extern int McTest_Assume(int expr);

/* Asserts that `expr` must hold. */
inline static void McTest_Assert(int expr) {
  if (McTest_Assume(!expr)) {
    abort();
  }
}

/* Return a symbolic value of a given type. */
extern int McTest_Bool(void);
extern size_t McTest_Size(void);
extern uint64_t McTest_UInt64(void);
extern uint32_t McTest_UInt(void);

inline static int64_t McTest_Int64(void) {
  return (int64_t) McTest_UInt64();
}

inline static int32_t McTest_Int(void) {
  return (int32_t) McTest_UInt();
}

inline static uint16_t McTest_UShort(void) {
  return (uint16_t) McTest_UInt();
}

inline static int16_t McTest_Short(void) {
  return (int16_t) McTest_UInt();
}

inline static unsigned char McTest_UChar(void) {
  return (unsigned char) McTest_UInt();
}

inline static char McTest_Char(void) {
  return (char) McTest_UInt();
}

/* Return a symbolic value in a the range `[low_inc, high_inc]`. */
#define MCTEST_MAKE_SYMBOLIC_RANGE(Tname, tname) \
    inline static tname McTest_ ## Tname ## InRange( \
        tname low, tname high) { \
      tname x = McTest_ ## Tname(); \
      (void) McTest_Assume(low <= x && x <= high); \
      return x; \
    }

MCTEST_MAKE_SYMBOLIC_RANGE(Int64, int64_t)
MCTEST_MAKE_SYMBOLIC_RANGE(UInt64, uint64_t)
MCTEST_MAKE_SYMBOLIC_RANGE(Int, int)
MCTEST_MAKE_SYMBOLIC_RANGE(UInt, uint32_t)
MCTEST_MAKE_SYMBOLIC_RANGE(Short, int16_t)
MCTEST_MAKE_SYMBOLIC_RANGE(UShort, uint16_t)
MCTEST_MAKE_SYMBOLIC_RANGE(Char, char)
MCTEST_MAKE_SYMBOLIC_RANGE(UChar, unsigned char)

#undef MCTEST_MAKE_SYMBOLIC_RANGE


/* Return a symbolic value of a given type. */
extern int McTest_Bool(void);
extern size_t McTest_Size(void);
extern uint64_t McTest_UInt64(void);
extern int64_t McTest_Int64(void);
extern uint32_t McTest_UInt(void);
extern int32_t McTest_Int(void);
extern uint16_t McTest_UShort(void);
extern int16_t McTest_Short(void);
extern unsigned char McTest_UChar(void);
extern char McTest_Char(void);

/* Predicates to check whether or not a particular value is symbolic */
extern int McTest_IsSymbolicUInt(uint32_t x);

inline static int McTest_IsSymbolicInt(int x) {
  return McTest_IsSymbolicUInt((uint32_t) x);
}

inline static int McTest_IsSymbolicUShort(uint16_t x) {
  return McTest_IsSymbolicUInt((uint32_t) x);
}

inline static int McTest_IsSymbolicShort(int16_t x) {
  return McTest_IsSymbolicUInt((uint32_t) (uint16_t) x);
}

inline static int McTest_IsSymbolicUChar(unsigned char x) {
  return McTest_IsSymbolicUInt((uint32_t) x);
}

inline static int McTest_IsSymbolicChar(char x) {
  return McTest_IsSymbolicUInt((uint32_t) (unsigned char) x);
}

inline static int McTest_IsSymbolicUInt64(uint64_t x) {
  return McTest_IsSymbolicUInt((uint32_t) x) ||
         McTest_IsSymbolicUInt((uint32_t) (x >> 32U));
}

inline static int McTest_IsSymbolicInt64(int64_t x) {
  return McTest_IsSymbolicUInt64((uint64_t) x);
}

inline static int McTest_IsSymbolicBool(int x) {
  return McTest_IsSymbolicInt(x);
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpointer-to-int-cast"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-to-int-cast"

inline static int McTest_IsSymbolicPtr(void *x) {
  if (sizeof(void *) == 8) {
    return McTest_IsSymbolicUInt64((uint64_t) x);
  } else {
    return McTest_IsSymbolicUInt((uint32_t) x);
  }
}

#pragma GCC diagnostic pop
#pragma clang diagnostic pop

inline static int McTest_IsSymbolicFloat(float x) {
  return McTest_IsSymbolicUInt(*((uint32_t *) &x));
}

inline static int McTest_IsSymbolicDouble(double x) {
  return McTest_IsSymbolicUInt64(*((uint64_t *) &x));
}

#define _MCTEST_TO_STR(a) __MCTEST_TO_STR(a)
#define __MCTEST_TO_STR(a) #a

#ifdef __cplusplus
# define MCTEST_EXTERN_C extern "C"
#else
# define MCTEST_EXTERN_C
#endif

#define McTest_EntryPoint(test_name) \
    _McTest_EntryPoint(test_name, __FILE__, __LINE__)

#define _McTest_EntryPoint(test_name, file, line) \
    static void McTest_Run_ ## test_name (void); \
    __attribute__((noinline, used)) \
    MCTEST_EXTERN_C void McTest_Register_ ## test_name (void) { \
      __asm__ __volatile__ ( \
        ".pushsection .mctest_strtab,\"a\" \n" \
        "1: \n" \
        ".asciz \"" _MCTEST_TO_STR(test_name) "\" \n" \
        "2: \n" \
        ".asciz \"" file "\" \n" \
        ".popsection \n" \
        ".pushsection .mctest_entrypoints,\"a\" \n" \
        ".balign 16 \n" \
        ".quad %p0 \n" \
        ".quad 1b \n" \
        ".quad 2b \n" \
        ".quad " _MCTEST_TO_STR(line) " \n" \
        ".popsection \n" \
        : \
        : "i"(McTest_Run_ ## test_name) \
      ); \
    } \
    void McTest_Run_ ## test_name(void)


#ifdef __cplusplus
}  /* extern C */
#endif  /* __cplusplus */
#endif  /* INCLUDE_MCTEST_MCTEST_H_ */
