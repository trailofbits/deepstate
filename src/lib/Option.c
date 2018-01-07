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

#include "deepstate/DeepState.h"
#include "deepstate/Option.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

enum {
  kMaxNumOptions = 32,
  kMaxOptionLength = 1024 - 1
};

/* Linked list of registered options. */
static struct DeepState_Option *DeepState_Options = NULL;
int DeepState_OptionsAreInitialized = 0;

static const char DeepState_FakeSpace = ' ' | 0x80;

/* Copy of the option string. */
static int DeepState_OptionStringLength = 0;
static char DeepState_OptionString[kMaxOptionLength + 1] = {'\0'};
static const char *DeepState_OptionNames[kMaxNumOptions] = {NULL};
static const char *DeepState_OptionValues[kMaxNumOptions] = {NULL};

/* Copy a substring into the main options string. */
static int CopyStringIntoOptions(int offset, const char *string,
                                 int replace_spaces) {
  for (; offset < kMaxOptionLength && *string; ++string) {
    char ch = *string;
    if (' ' == ch && replace_spaces) {
      ch = DeepState_FakeSpace;
    }
    DeepState_OptionString[offset++] = ch;
  }
  return offset;
}

/* Finalize the option string. */
static void TerminateOptionString(int length) {
  if (kMaxOptionLength <= length) {
    DeepState_Abandon("Option string is too long.");
  }
  DeepState_OptionString[length] = '\0';
  DeepState_OptionStringLength = length;
}

/* Check that a character is a valid option character. */
static int IsValidOptionChar(char ch) {
  return ('a' <= ch && ch <= 'z') ||
         ('A' <= ch && ch <= 'Z') ||
         ('_' == ch);
}

/* Check that a character is a valid option character. */
static int IsValidValueChar(char ch) {
  return (' ' < ch && ch <= '~') || ch == DeepState_FakeSpace;
}

/* Format an option string into a more amenable internal format. This is a sort
 * of pre-processing step to distinguish options from values. */
static void ProcessOptionString(void) {
  char *ch = &DeepState_OptionString[0];
  char * const max_ch = &DeepState_OptionString[DeepState_OptionStringLength];
  unsigned num_options = 0;

  enum OptionLexState {
    kInOption,
    kInValue,
    kSeenEqual,
    kSeenSpace,
    kSeenDash,
    kElsewhere
  } state = kElsewhere;

  for (; ch < max_ch; ++ch) {
    switch (state) {
      case kInOption: {
        const char ch_val = *ch;

        /* Terminate the option name. */
        if (!IsValidOptionChar(ch_val)) {
          *ch = '\0';

          /* We've seen an equal, which mean's we're moving into the
           * beginning of a value. */
          if ('=' == ch_val) {
            state = kSeenEqual;
          } else if (' ' == ch_val || DeepState_FakeSpace == ch_val) {
            state = kSeenSpace;
          } else {
            state = kElsewhere;
          }
        }
        break;
      }

      case kInValue:
        if (!IsValidValueChar(*ch)) {
          state = kElsewhere;
          *ch = '\0';
        } else if (DeepState_FakeSpace == *ch) {
          *ch = ' ';  /* Convert back to a space. */
        }
        break;

      case kSeenSpace:
        if (' ' == *ch || DeepState_FakeSpace == *ch) {
          *ch = '\0';
          state = kSeenSpace;

        } else if (IsValidValueChar(*ch)) {  /* E.g. `--tools bbcount`. */
          state = kInValue;
          DeepState_OptionValues[num_options - 1] = ch;

        } else {
          state = kElsewhere;
        }
        break;

      case kSeenEqual:
        if (IsValidValueChar(*ch)) {  /* E.g. `--tools=bbcount`. */
          state = kInValue;
          DeepState_OptionValues[num_options - 1] = ch;
        } else {  /* E.g. `--tools=`. */
          state = kElsewhere;
        }
        break;

      case kSeenDash:
        if ('-' == *ch) {
          state = kInOption;  /* Default to positional. */
          if (kMaxNumOptions <= num_options) {
            DeepState_Abandon("Parsed too many options!");
          }
          DeepState_OptionValues[num_options] = "";
          DeepState_OptionNames[num_options++] = ch + 1;
        } else {
          state = kElsewhere;
        }
        *ch = '\0';
        break;

      case kElsewhere:
        if ('-' == *ch) {
          state = kSeenDash;
        }
        *ch = '\0';
        break;
    }
  }
}

/* Returns a pointer to the value for an option name, or a NULL if the option
 * name was not found (or if it was specified but had no value). */
static const char *FindValueForName(const char *name) {
  for (int i = 0; i < kMaxNumOptions && DeepState_OptionNames[i]; ++i) {
    if (!strcmp(DeepState_OptionNames[i], name)) {
      return DeepState_OptionValues[i];
    }
  }
  return NULL;
}

/* Process the pending options.. */
static void ProcessPendingOptions(void) {
  struct DeepState_Option *option = DeepState_Options;
  struct DeepState_Option *next_option = NULL;
  for (; option != NULL; option = next_option) {
    next_option = option->next;
    option->parse(option);
  }
}

/* Initialize the options from the command-line arguments. */
void DeepState_InitOptions(int argc, ...) {
  va_list args;
  va_start(args, argc);
  const char **argv = va_arg(args, const char **);
  va_end(args);

  int offset = 0;
  int arg = 1;
  for (const char *sep = ""; arg < argc; ++arg, sep = " ") {
    offset = CopyStringIntoOptions(offset, sep, 0);
    offset = CopyStringIntoOptions(offset, argv[arg], 1);
  }
  TerminateOptionString(offset);
  ProcessOptionString();
  DeepState_OptionsAreInitialized = 1;
  ProcessPendingOptions();
}

enum {
  kLineLength = 80,
  kTabLength = 8,
  kBufferMaxLength = kLineLength - kTabLength
};

/* Perform line buffering of the document string. */
static const char *BufferDocString(char *buff, const char *docstring) {
  char *last_stop = buff;
  const char *docstring_last_stop = docstring;
  const char *docstring_stop = docstring + kBufferMaxLength;
  for (; docstring < docstring_stop && *docstring; ) {
    if (' ' == *docstring) {
      last_stop = buff;
      docstring_last_stop = docstring + 1;
    } else if ('\n' == *docstring) {
      last_stop = buff;
      docstring_last_stop = docstring + 1;
      break;
    }
    *buff++ = *docstring++;
  }
  if (docstring < docstring_stop && !*docstring) {
    *buff = '\0';
    return docstring;
  } else {
    *last_stop = '\0';
    return docstring_last_stop;
  }
}

/* Works for --help option: print out each options along with their document. */
void DeepState_PrintAllOptions(const char *prog_name) {
  fprintf(stderr, "Usage: %s <options>\n\n", prog_name);

  char line_buff[kLineLength];
  struct DeepState_Option *option = DeepState_Options;
  struct DeepState_Option *next_option = NULL;
  for (; option != NULL; option = next_option) {
    next_option = option->next;

    fprintf(stderr, "--%s", option->name);
    const char *docstring = option->docstring;
    do {
      docstring = BufferDocString(line_buff, docstring);
      fprintf(stderr, "\n        %s", line_buff);
    } while (*docstring);
    fprintf(stderr, "\n\n");
  }
}


/* Initialize an option. */
void DeepState_AddOption(struct DeepState_Option *option) {
  if (DeepState_OptionsAreInitialized) {
    option->parse(option);  /* Added late? */
  }
  if (!option->next) {
    option->next = DeepState_Options;
    DeepState_Options = option;
  }
}

/* Parse an option that is a string. */
void DeepState_ParseStringOption(struct DeepState_Option *option) {
  const char *value = FindValueForName(option->name);
  if (value != NULL) {
    *(option->has_value) = 1;
    *((const char **) (option->value)) = value;
  }
}

/* Parse an option that will be interpreted as a boolean value. */
void DeepState_ParseBoolOption(struct DeepState_Option *option) {
  const char *value = FindValueForName(option->name);
  if (value != NULL) {
    switch (*value) {
      case '1': case 'y': case 'Y': case 't': case 'T':
      case '\0':  /* Treat the presence of the option as truth. */
        *(option->has_value) = 1;
        *((int *) (option->value)) = 1;
        break;
      case '0': case 'n': case 'N': case 'f': case 'F':
        *(option->has_value) = 1;
        *((int *) (option->value)) = 0;
        break;
      default:
        break;
    }

  /* Alternative name, e.g. `--foo` vs. `--no_foo`. */
  } else {
    const char *alt_value = FindValueForName(option->alt_name);
    if (alt_value != NULL) {
      if ('\0' != alt_value[0]) {
        DeepState_Abandon("Got an option value for a negated boolean option.");
      }
      *(option->has_value) = 1;
      *((int *) (option->value)) = 0;
    }
  }
}


/* Parse an option that will be interpreted as an unsigned integer. */
void DeepState_ParseIntOption(struct DeepState_Option *option) {
  const char *value = FindValueForName(option->name);
  if (value != NULL) {
    int int_value = 0;
    if (sscanf(value, "%d", &int_value)) {
      *(option->has_value) = 1;
      *((int *) (option->value)) = int_value;
    }
  }
}

/* Parse an option that will be interpreted as an unsigned integer. */
void DeepState_ParseUIntOption(struct DeepState_Option *option) {
  const char *value = FindValueForName(option->name);
  if (value != NULL) {
    unsigned uint_value = 0;
    if (sscanf(value, "%u", &uint_value)) {
      *(option->has_value) = 1;
      *((unsigned *) (option->value)) = uint_value;
    }
  }
}
