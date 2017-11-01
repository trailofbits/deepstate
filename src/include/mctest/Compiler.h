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

#ifndef SRC_INCLUDE_MCTEST_COMPILER_H_
#define SRC_INCLUDE_MCTEST_COMPILER_H_

#include <stdio.h>
#include <stdlib.h>

/* Stringify a macro parameter. */
#define MCTEST_TO_STR(a) _MCTEST_TO_STR(a)
#define _MCTEST_TO_STR(a) __MCTEST_TO_STR(a)
#define __MCTEST_TO_STR(a) #a

/* Mark a function as not returning. */
#if defined(_MSC_VER)
# define MCTEST_NORETURN __declspec(noreturn)
#else
# define MCTEST_NORETURN __attribute__((noreturn))
#endif

/* Mark a function for inlining. */
#if defined(_MSC_VER)
# define MCTEST_INLINE __forceinline
# define MCTEST_NOINLINE __declspec(noinline)
#else
# define MCTEST_INLINE inline __attribute__((always_inline))
# define MCTEST_NOINLINE __attribute__((noinline))
#endif

/* Introduce a trap instruction to halt execution. */
#if defined(_MSC_VER)
# include <intrin.h>
# define McTest_Trap __debugbreak
#else
# define McTest_Trap __builtin_trap
#endif

/* Wrap a block of code in `extern "C"` if we are compiling with a C++
 * compiler. */
#ifdef __cplusplus
# define MCTEST_BEGIN_EXTERN_C extern "C" {
# define MCTEST_END_EXTERN_C }
#else
# define MCTEST_BEGIN_EXTERN_C
# define MCTEST_END_EXTERN_C
#endif

/* Initializer/finalizer sample for MSVC and GCC/Clang.
 * 2010-2016 Joe Lowe. Released into the public domain.
 *
 * See: https://stackoverflow.com/a/2390626/247591 */
#ifdef __cplusplus
# define MCTEST_INITIALIZER(f) \
    static void f(void); \
    struct f ##_t_ { \
      f##_t_(void) { \
        f(); \
      } \
    }; \
    static f##_t_ f##_; \
    static void f(void)

#elif defined(_MSC_VER)
# pragma section(".CRT$XCU",read)
# define MCTEST_INITIALIZER2_(f, p) \
    static void f(void); \
    __declspec(allocate(".CRT$XCU")) void (*f##_)(void) = f; \
    __pragma(comment(linker,"/include:" p #f "_")) \
    static void f(void)

# ifdef _WIN64
#   define MCTEST_INITIALIZER(f) MCTEST_INITIALIZER2_(f,"")
# else
#   define MCTEST_INITIALIZER(f) MCTEST_INITIALIZER2_(f,"_")
#  endif
#else
# define MCTEST_INITIALIZER(f) \
    static void f(void) __attribute__((constructor)); \
    static void f(void)
#endif

#endif  /* SRC_INCLUDE_MCTEST_COMPILER_H_ */
