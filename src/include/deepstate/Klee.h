/*
 * Copyright (c) 2018 Trail of Bits, Inc.
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

#ifndef SRC_INCLUDE_DEEPSTATE_KLEE_H_
#define SRC_INCLUDE_DEEPSTATE_KLEE_H_

#include <deepstate/DeepState.h>

#define KLEE_GET_VALUE(suffix, type) type klee_get_value ## suffix(type expr)

DEEPSTATE_BEGIN_EXTERN_C

/* TODO(joe): Implement */
static void klee_define_fixed_object(void *addr, size_t nbytes);

static void klee_make_symbolic(void *addr, size_t nbytes, const char *name) {
  DeepState_SymbolizeData(addr, addr + nbytes);
}

/* TODO(joe): Implement */
static int klee_range(int begin, int end, const char *name);

/* TODO(joe): Implement */
static int klee_int(const char *name);

DEEPSTATE_NORETURN static void klee_silent_exit(int status) {
  exit(status);
}

/* TODO(joe): Implement */
static size_t klee_get_obj_size(void *ptr);

/* TODO(joe): Implement */
static void klee_print_expr(const char *msg, ...);

/* TODO(joe): Implement */
static uintptr_t klee_choose(uintptr_t n);

/* TODO(joe): Implement */
static unsigned klee_is_symbolic(uintptr_t n);

/* TODO(joe): Implement */
static void klee_assume(uintptr_t condition);

static void klee_warning(const char *message) {
  DeepState_Log(DeepState_LogWarning, message);
}

static void klee_warning_once(const char *message) {
  DeepState_Log(DeepState_LogWarning, message);
}

static void klee_prefer_cex(void *object, uintptr_t condition) {
  /* KLEE engine command, no DeepState equivalent. */
}

static void klee_posix_prefer_cex(void *object, uintptr_t condition) {
  /* KLEE engine command, no DeepState equivalent. */
}

/* TODO(joe): Implement */
static void klee_mark_global(void *object);

/* TODO(joe): Implement */
static KLEE_GET_VALUE(f, float);

/* TODO(joe): Implement */
static KLEE_GET_VALUE(d, double);

/* TODO(joe): Implement */
static KLEE_GET_VALUE(l, long);

/* TODO(joe): Implement */
static KLEE_GET_VALUE(ll, long long);

/* TODO(joe): Implement */
static KLEE_GET_VALUE(_i32, int32_t);

/* TODO(joe): Implement */
static KLEE_GET_VALUE(_i64, int64_t);

/* TODO(joe): Implement */
static void klee_check_memory_access(const void *address, size_t size);

static void klee_set_forking(unsigned enable) {
  /* KLEE engine command, no DeepState equivalent. */
}

/* TODO(joe): Implement */
static void klee_alias_function(const char *fn_name, const char *new_fn_name);

/* TODO(joe): Implement */
static void klee_stack_trace(void);

/* TODO(joe): Implement */
static void klee_print_range(const char *name, int arg);

static void klee_open_merge(void) {
  /* KLEE engine command, no DeepState equivalent. */
}

static void klee_close_merge(void) {
  /* KLEE engine command, no DeepState equivalent. */
}

DEEPSTATE_END_EXTERN_C

#endif  /* SRC_INCLUDE_DEEPSTATE_KLEE_H_ */
