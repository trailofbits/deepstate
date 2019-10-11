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

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "deepstate/DeepState.h"
#include "deepstate/Log.h"

DEEPSTATE_BEGIN_EXTERN_C

enum {
  DeepState_StreamSize = 4096
};

/* Formatting options availale to the streaming API. */
struct DeepState_StreamFormatOptions {
  /* int radix; */
  int hex;
  int oct;
  int show_base;
  /*int width; */
  int left_justify;
  int add_sign;
  char fill;
};

/* Stream type that accumulates formatted data to be printed. This loosely
 * mirrors C++ I/O streams, not because I/O streams are good, but instead
 * because the ability to stream in data to things like the C++-backed
 * `ASSERT` and `CHECK` macros is really nice. */ 
struct DeepState_Stream {
  int size;
  struct DeepState_StreamFormatOptions options;
  char message[DeepState_StreamSize + 2];
  char staging[32];
  char format[32];
  char unpack[32];
  union {
    uint64_t as_uint64;
    double as_fp64;
  } value;
};

/* Hard-coded streams for each log level. */
static struct DeepState_Stream DeepState_Streams[DeepState_LogFatal + 1] = {};

/* Endian specifier for Python's `struct.pack` and `struct.unpack`.
 *    =  Native endian
 *    <  Little endian
 *    >  Big endian
 */
static char DeepState_EndianSpecifier = '=';

/* Figure out what the Python `struct` endianness specifier should be. */
DEEPSTATE_INITIALIZER(DetectEndianness) {
  static const int one = 1;
  if ((const char *) &one) {
    DeepState_EndianSpecifier = '<';  /* Little endian. */
  } else {
    DeepState_EndianSpecifier = '>';  /* Big endian. */
  }
}

/* Fills the `stream->unpack` character buffer with a Python `struct.unpack`-
 * compatible format specifier. */
static void DeepState_StreamUnpack(struct DeepState_Stream *stream, char type) {
  stream->unpack[0] = DeepState_EndianSpecifier;
  stream->unpack[1] = type;
  stream->unpack[2] = '\0';
}

/* Fill in the format for when we want to stream an integer. */
static void DeepState_StreamIntFormat(struct DeepState_Stream *stream,
                                      size_t val_size, int is_unsigned) {
  char *format = stream->format;
  int i = 0;

  format[i++] = '%';
  if(stream->options.left_justify) {
    format[i++] = '-';
  }

  if(stream->options.add_sign) {
    format[i++] = '+';
  }

  if (stream->options.fill) {
    format[i++] = stream->options.fill;
  }

  if (stream->options.show_base) {
    format[i++] = '#';  /* Show the radix. */
  }

  if (8 == val_size) {
    format[i++] = 'l';
    format[i++] = 'l';

  } else if (2 == val_size) {
    format[i++] = 'h';

  } else if (1 == val_size) {
    if (is_unsigned) {
      format[i++] = 'h';
      format[i++] = 'h';
    }
  }

  if (stream->options.hex) {
    format[i++] = 'x';
  } else if (stream->options.oct) {
    format[i++] = 'o';
  } else if (is_unsigned) {
    format[i++] = 'u';
  } else {
    if (1 == val_size) {
      format[i++] = 'c';
    } else {
      format[i++] = 'd';
    }
  }

  format[i++] = '\0';
}

/* Make sure that we don't exceed our formatting capacity when running. */
static void CheckCapacity(struct DeepState_Stream *stream,
                          int num_chars_to_add) {
  if (0 > num_chars_to_add) {
    DeepState_Abandon("Can't add a negative number of characters to a stream.");
  } else if ((stream->size + num_chars_to_add) >= DeepState_StreamSize) {
    DeepState_Abandon("Exceeded capacity of stream buffer.");
  }
}

/* Stream an integer into the stream's message. This function is designed to
 * be hooked by the symbolic executor, so that it can easily pull out the
 * relevant data from `*val`, which may be symbolic, and defer the actual
 * formatting until later. */
DEEPSTATE_NOINLINE
void _DeepState_StreamInt(enum DeepState_LogLevel level, const char *format,
                       const char *unpack, uint64_t *val) {
  struct DeepState_Stream *stream = &(DeepState_Streams[level]);
  int size = 0;
  int remaining_size = DeepState_StreamSize - stream->size;
  if (unpack[1] == 'Q' || unpack[1] == 'q') {
    size = snprintf(&(stream->message[stream->size]),
                    remaining_size, format, *val);
  } else {
    size = snprintf(&(stream->message[stream->size]),
                    remaining_size, format, (uint32_t) *val);
  }
  CheckCapacity(stream, size);
  stream->size += size;
}

/* Format a streamed-in float. This gets hooked. */
DEEPSTATE_NOINLINE
void _DeepState_StreamFloat(enum DeepState_LogLevel level, const char *format,
                         const char *unpack, double *val) {
  struct DeepState_Stream *stream = &(DeepState_Streams[level]);
  int remaining_size = DeepState_StreamSize - stream->size;
  int size = snprintf(&(stream->message[stream->size]),
                      remaining_size, format, *val);
  CheckCapacity(stream, size);
  stream->size += size;
}

/* Format a streamed-in NUL-terminated string. This gets hooked. */
DEEPSTATE_NOINLINE
void _DeepState_StreamString(enum DeepState_LogLevel level, const char *format,
                          const char *str) {
  struct DeepState_Stream *stream = &(DeepState_Streams[level]);
  int remaining_size = DeepState_StreamSize - stream->size;
  int size = snprintf(&(stream->message[stream->size]),
                      remaining_size, format, str);
  CheckCapacity(stream, size);
  stream->size += size;
}

void DeepState_StreamPointer(enum DeepState_LogLevel level, void *val) {
  struct DeepState_Stream *stream = &(DeepState_Streams[level]);
  stream->format[0] = '0';
  stream->format[1] = 'x';
  stream->format[2] = '%';
  stream->format[3] = '0';
  if (sizeof(void *) == 4) {
    stream->format[4] = '8';
    stream->format[5] = 'x';
    stream->format[6] = '\0';
  } else {
    stream->format[4] = '1';
    stream->format[5] = '6';
    stream->format[6] = 'x';
    stream->format[7] = '\0';
  }
  DeepState_StreamUnpack(stream, (sizeof(void *) == 8 ? 'Q' : 'I'));
  stream->value.as_uint64 = (uintptr_t) val;
  _DeepState_StreamInt(level, stream->format, stream->unpack,
                       &(stream->value.as_uint64));
}

#define MAKE_INT_STREAMER(Type, type, is_unsigned, pack_kind) \
    void DeepState_Stream ## Type(enum DeepState_LogLevel level, type val) { \
      struct DeepState_Stream *stream = &(DeepState_Streams[level]); \
      DeepState_StreamIntFormat(stream, sizeof(val), is_unsigned); \
      DeepState_StreamUnpack(stream, pack_kind); \
      stream->value.as_uint64 = (uint64_t) val; \
      _DeepState_StreamInt(level, stream->format, stream->unpack, \
                           &(stream->value.as_uint64)); \
    }

MAKE_INT_STREAMER(UInt64, uint64_t, 1, 'Q')
MAKE_INT_STREAMER(Int64, int64_t, 0, 'q')

MAKE_INT_STREAMER(UInt32, uint32_t, 1, 'I')
MAKE_INT_STREAMER(Int32, int32_t, 0, 'i')

MAKE_INT_STREAMER(UInt16, uint16_t, 1, 'h')
MAKE_INT_STREAMER(Int16, int16_t, 0, 'H')

MAKE_INT_STREAMER(UInt8, uint8_t, 1, 'B')
MAKE_INT_STREAMER(Int8, int8_t, 0, 'c')

#undef MAKE_INT_STREAMER

/* Stream a C string into the stream's message. */
void DeepState_StreamCStr(enum DeepState_LogLevel level, const char *begin) {
  _DeepState_StreamString(level, "%s", begin);
}

/* Stream a some data in the inclusive range `[begin, end]` into the
 * stream's message. */
/*void DeepState_StreamData(enum DeepState_LogLevel level, const void *begin,
                       const void *end) {
  struct DeepState_Stream *stream = &(DeepState_Streams[level]);
  int remaining_size = DeepState_StreamSize - stream->size;
  int input_size = (int) ((uintptr_t) end - (uintptr_t) begin) + 1;
  CheckCapacity(stream, input_size);
  memcpy(&(stream->message[stream->size]), begin, (size_t) input_size);
  stream->size += input_size;
}*/

/* Stream a `double` into the stream's message. This function is designed to
 * be hooked by the symbolic executor, so that it can easily pull out the
 * relevant data from `*val`, which may be symbolic, and defer the actual
 * formatting until later. */
void DeepState_StreamDouble(enum DeepState_LogLevel level, double val) {
  struct DeepState_Stream *stream = &(DeepState_Streams[level]);
  const char *format = "%f";  /* TODO(pag): Support more? */
  stream->value.as_fp64 = val;
  DeepState_StreamUnpack(stream, 'd');
  _DeepState_StreamFloat(level, format, stream->unpack, &(stream->value.as_fp64));
}

/* Clear the contents of the stream and don't log it. */
void DeepState_ClearStream(enum DeepState_LogLevel level) {
  struct DeepState_Stream *stream = &(DeepState_Streams[level]);
  if (stream->size) {
    memset(stream->message, 0, DeepState_StreamSize);
    stream->size = 0;
  }
}

/* Flush the contents of the stream to a log. */
void DeepState_LogStream(enum DeepState_LogLevel level) {
  struct DeepState_Stream *stream = &(DeepState_Streams[level]);
  if (stream->size) {
    stream->message[stream->size] = '\0';
    stream->message[DeepState_StreamSize] = '\0';
    DeepState_Log(level, stream->message);
    DeepState_ClearStream(level);
  }
}

/* Reset the formatting in a stream. */
void DeepState_StreamResetFormatting(enum DeepState_LogLevel level) {
  struct DeepState_Stream *stream = &(DeepState_Streams[level]);
  memset(&(stream->options), 0, sizeof(stream->options));
}

static int DeepState_NumLsInt64BitFormat = 2;

/* `PRId64` will be "ld" or "lld" */
DEEPSTATE_INITIALIZER(DeepState_NumLsFor64BitFormat) {
  DeepState_NumLsInt64BitFormat = (PRId64)[1] == 'd' ? 1 : 2;
}

/* Approximately do string format parsing and convert it into calls into our
 * streaming API. */
DEEPSTATE_NOINLINE
static int DeepState_StreamFormatValue(enum DeepState_LogLevel level,
                                       const char *format,
                                       struct DeepState_VarArgs *va) {
  struct DeepState_Stream *stream = &(DeepState_Streams[level]);
  char format_buf[32] = {'\0'};
  int i = 0;
  int k = 0;
  int length = 4;
  char ch = '\0';
  int is_string = 0;
  int is_unsigned = 0;
  int is_float = 0;
  int long_double = 0;
  int num_ls = 0;
  char extract = '\0';

#define READ_FORMAT_CHAR \
  ch = format[i]; \
  format_buf[i - k] = ch; \
  format_buf[i - k + 1] = '\0'; \
  i++

  READ_FORMAT_CHAR;  /* Read the '%' */

  if ('%' != ch) {
    DeepState_Abandon("Invalid format.");
    return 0;
  }

  /* Flags */
get_flag_char:
  READ_FORMAT_CHAR;
  switch (ch) {
    case '\0':
      DeepState_Abandon("Incomplete format (flags).");
      return 0;
    case '-':
    case '+':
    case ' ':
    case '#':
    case '0':
      goto get_flag_char;
    default:
      break;
  }

  /* Width */
get_width_char:
  switch (ch) {
    case '\0':
      DeepState_Abandon("Incomplete format (width).");
      return 0;
    case '*':
      DeepState_Abandon("Variable width printing not supported.");
      return 0;
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
      READ_FORMAT_CHAR;
      goto get_width_char;
    default:
      break;
  }

  /* Precision */
  if ('.' == ch) {
  get_precision_char:
    READ_FORMAT_CHAR;
    switch (ch) {
      case '\0':
        DeepState_Abandon("Incomplete format (precision).");
        return 0;
      case '*':
        DeepState_Abandon("Variable precision printing not supported.");
        break;
      case '0':
      case '1':
      case '2':
      case '3':
      case '4':
      case '5':
      case '6':
      case '7':
      case '8':
      case '9':
        goto get_precision_char;
      default:
        break;
    }
  }

  /* Length */
get_length_char:
  switch (ch) {
    case '\0':
      DeepState_Abandon("Incomplete format (length).");
      return 0;
    case 'L':
      long_double = 1;
      k += 1;  /* Overwrite the `L`. */
      READ_FORMAT_CHAR;
      break;
    case 'h':
      length /= 2;
      READ_FORMAT_CHAR;
      goto get_length_char;
    case 'l':
      num_ls += 1;
      READ_FORMAT_CHAR;
      goto get_length_char;
    case 'j':
      length = (int) sizeof(intmax_t);
      READ_FORMAT_CHAR;
      break;
    case 'z':
      length = (int) sizeof(size_t);
      READ_FORMAT_CHAR;
      break;
    case 't':
      length = (int) sizeof(ptrdiff_t);
      READ_FORMAT_CHAR;
      break;
    default:
      break;
  }

  if (!length) {
    length = 1;
  } else if (num_ls >= DeepState_NumLsInt64BitFormat) {
    length = 8;
  }

  format_buf[i] = '\0';

  /* Specifier */
  switch(ch) {
    case '\0':
      DeepState_Abandon("Incomplete format (specifier).");
      return 0;

    case 'n':
      return i;  /* Nothing printed. */

    /* Print a character. */
    case 'c':
      stream->value.as_uint64 = (uint64_t) (char) va_arg(va->args, int);
      extract = 'c';
      goto common_stream_int;

    /* Signed integer. */
    case 'd':
    case 'i':
      if (1 == length) {
        stream->value.as_uint64 = (uint64_t) (int8_t) va_arg(va->args, int);
        extract = 'b';
      } else if (2 == length) {
        stream->value.as_uint64 = (uint64_t) (int16_t) va_arg(va->args, int);
        extract = 'h';
      } else if (4 == length) {
        stream->value.as_uint64 = (uint64_t) (int32_t) va_arg(va->args, int);
        extract = 'i';
      } else if (8 == length) {
        stream->value.as_uint64 = (uint64_t) va_arg(va->args, int64_t);
        extract = 'q';
      } else {
        DeepState_Abandon("Unsupported integer length.");
      }
      goto common_stream_int;

    /* Pointer. */
    case 'p':
      length = (int) sizeof(void *);
      format_buf[i - k - 1] = 'x';
      /* Note: Falls through. */

    /* Unsigned, hex, octal */
    case 'u':
    case 'o':
    case 'x':
    case 'X':
      if (1 == length) {
        stream->value.as_uint64 = (uint64_t) (uint8_t) va_arg(va->args, int);
        extract = 'B';
      } else if (2 == length) {
        stream->value.as_uint64 = (uint64_t) (uint16_t) va_arg(va->args, int);
        extract = 'H';
      } else if (4 == length) {
        stream->value.as_uint64 = (uint64_t) (uint32_t) va_arg(va->args, int);
        extract = 'I';
      } else if (8 == length) {
        stream->value.as_uint64 = (uint64_t) va_arg(va->args, uint64_t);
        extract = 'Q';
      } else {
        DeepState_Abandon("Unsupported integer length.");
      }

    common_stream_int:
      DeepState_StreamUnpack(stream, extract);
      _DeepState_StreamInt(level, format_buf, stream->unpack,
                           &(stream->value.as_uint64));
      goto done;

    /* Floating point, scientific notation, etc. */
    case 'f':
    case 'F':
    case 'e':
    case 'E':
    case 'g':
    case 'G':
    case 'a':
    case 'A':
      if (long_double) {
        stream->value.as_fp64 = (double) va_arg(va->args, long double);
      } else {
        stream->value.as_fp64 = va_arg(va->args, double);
      }
      DeepState_StreamUnpack(stream, 'd');
      _DeepState_StreamFloat(level, format_buf, stream->unpack,
                             &(stream->value.as_fp64));
      goto done;

    case 's': {
      const char *str = va_arg(va->args, const char *);
      _DeepState_StreamString(level, format_buf, str);
      goto done;
    }

    default:
      DeepState_Abandon("Unsupported format specifier.");
      return 0;
  }
done:
  if (!i) {
    DeepState_Abandon("Made no progress.");
  }
  return i;
}

/* Holding buffer for a format string. If we have something like `foo%dbar`
 * then we want to be able to pull out the `%d`, and so having the format
 * string in a mutable buffer lets us conveniently NUL-out the `b` of `bar`
 * following the `%d`. */
static char DeepState_Format[DeepState_StreamSize + 1];

/* Stream some formatted input. This converts a `printf`-style format string
 * into a */
void DeepState_StreamVFormat(enum DeepState_LogLevel level,
                             const char *format_, va_list args) {
  struct DeepState_VarArgs va;
  va_copy(va.args, args);

  char *begin = NULL;
  char *end = NULL;
  char *format = &(DeepState_Format[0]);
  int i = 0;
  char ch = '\0';
  char next_ch = '\0';
  size_t len = strlen(format_);

  if (len >= DeepState_StreamSize) {
    DeepState_Abandon("Format string is too long.");
  }

  /* Concretize the string format. */
  memcpy(format, format_, len);
  format[len] = '\0';
  DeepState_ConcretizeCStr(format);

  for (i = 0; '\0' != (ch = format[i]); ) {
    if (!begin) {
      begin = &(format[i]);
    }

    if ('%' == ch) {
      if ('%' == format[i + 1]) {
        end = &(format[i]);
        next_ch = end[1];
        end[1] = '\0';
        DeepState_StreamCStr(level, begin);
        end[1] = next_ch;
        begin = NULL;
        end = NULL;
        i += 2;

      } else {
        if (end) {
          next_ch = end[1];
          end[1] = '\0';
          DeepState_StreamCStr(level, begin);
          end[1] = next_ch;
        }
        begin = NULL;
        end = NULL;
        i += DeepState_StreamFormatValue(level, &(format[i]), &va);
      }
    } else {
      end = &(format[i]);
      i += 1;
    }
  }

  if (begin && begin[0]) {
    DeepState_StreamCStr(level, begin);
  }
}

/* Stream some formatted input */
void DeepState_StreamFormat(enum DeepState_LogLevel level,
                            const char *format, ...) {
  va_list args;
  va_start(args, format);
  DeepState_StreamVFormat(level, format, args);
  va_end(args);
}

DEEPSTATE_END_EXTERN_C
