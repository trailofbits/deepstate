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

#ifndef SRC_INCLUDE_DEEPSTATE_OPTION_H_
#define SRC_INCLUDE_DEEPSTATE_OPTION_H_

#include "deepstate/Compiler.h"

#include <stdint.h>

#define DEEPSTATE_FLAG_NAME(name) FLAGS_ ## name
#define DEEPSTATE_HAS_DEEPSTATE_FLAG_NAME(name) HAS_FLAG_ ## name

#define DEEPSTATE_REGISTER_OPTION(name, group, parser, docstring) \
  static struct DeepState_Option DeepState_Option_ ## name = { \
      NULL, \
      DEEPSTATE_TO_STR(name), \
      DEEPSTATE_TO_STR(no_ ## name), \
      group, \
      &parser, \
      (void *) &DEEPSTATE_FLAG_NAME(name), \
      &DEEPSTATE_HAS_DEEPSTATE_FLAG_NAME(name), \
      docstring, \
  }; \
  DEEPSTATE_INITIALIZER(DeepState_AddOption_ ## name) { \
    DeepState_AddOption(&(DeepState_Option_ ## name)); \
  }

#define DEFINE_string(name, group, default_value, docstring) \
  DECLARE_string(name); \
  DEEPSTATE_REGISTER_OPTION(name, group, DeepState_ParseStringOption, docstring) \
  int DEEPSTATE_HAS_DEEPSTATE_FLAG_NAME(name) = 0; \
  const char *DEEPSTATE_FLAG_NAME(name) = default_value

#define DECLARE_string(name) \
  extern int DEEPSTATE_HAS_DEEPSTATE_FLAG_NAME(name); \
  extern const char *DEEPSTATE_FLAG_NAME(name)

#define DEFINE_bool(name, group, default_value, docstring) \
  DECLARE_bool(name); \
  DEEPSTATE_REGISTER_OPTION(name, group, DeepState_ParseBoolOption, docstring) \
  int DEEPSTATE_HAS_DEEPSTATE_FLAG_NAME(name) = 0; \
  int DEEPSTATE_FLAG_NAME(name) = default_value

#define DECLARE_bool(name) \
  extern int DEEPSTATE_HAS_DEEPSTATE_FLAG_NAME(name); \
  extern int DEEPSTATE_FLAG_NAME(name)

#define DEFINE_int(name, group, default_value, docstring) \
  DECLARE_int(name); \
  DEEPSTATE_REGISTER_OPTION(name, group, DeepState_ParseIntOption, docstring) \
  int DEEPSTATE_HAS_DEEPSTATE_FLAG_NAME(name) = 0; \
  int DEEPSTATE_FLAG_NAME(name) = default_value

#define DECLARE_int(name) \
  extern int DEEPSTATE_HAS_DEEPSTATE_FLAG_NAME(name); \
  extern int DEEPSTATE_FLAG_NAME(name)

#define DEFINE_uint(name, group, default_value, docstring) \
  DECLARE_uint(name); \
  DEEPSTATE_REGISTER_OPTION(name, group, DeepState_ParseUIntOption, docstring) \
  int DEEPSTATE_HAS_DEEPSTATE_FLAG_NAME(name) = 0; \
  unsigned DEEPSTATE_FLAG_NAME(name) = default_value

#define DECLARE_uint(name) \
  extern int DEEPSTATE_HAS_DEEPSTATE_FLAG_NAME(name); \
  extern unsigned DEEPSTATE_FLAG_NAME(name)
DEEPSTATE_BEGIN_EXTERN_C

/* Enum for defining command-line groups that options can reside under */
typedef enum {
  InputOutputGroup,
  AnalysisGroup,
  ExecutionGroup,
  TestSelectionGroup,
  MiscGroup,
} DeepState_OptGroup;

/* Backing structure for describing command-line options to DeepState. */
struct DeepState_Option {
  struct DeepState_Option *next;
  const char * const name;
  const char * const alt_name;  /* Only used for booleans. */
  DeepState_OptGroup group;
  void (* const parse)(struct DeepState_Option *);
  void * const value;
  int * const has_value;
  const char * const docstring;
};

extern int DeepState_OptionsAreInitialized;

/* Initialize the options from the command-line arguments. */
void DeepState_InitOptions(int argc, ... /* const char **argv */);

/* Works for `--help` option: print out each options along with
 * their documentation. */
void DeepState_PrintAllOptions(const char *prog_name);

/* Initialize an option. */
void DeepState_AddOption(struct DeepState_Option *option);

/* Parse an option that is a string. */
void DeepState_ParseStringOption(struct DeepState_Option *option);

/* Parse an option that will be interpreted as a boolean value. */
void DeepState_ParseBoolOption(struct DeepState_Option *option);

/* Parse an option that will be interpreted as an integer. */
void DeepState_ParseIntOption(struct DeepState_Option *option);

/* Parse an option that will be interpreted as an unsigned integer. */
void DeepState_ParseUIntOption(struct DeepState_Option *option);

DEEPSTATE_END_EXTERN_C

#endif  /* SRC_INCLUDE_DEEPSTATE_OPTION_H_ */
