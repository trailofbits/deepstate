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

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <mctest/Compiler.h>
#include <mctest/McTest.h>

MCTEST_BEGIN_EXTERN_C

enum {
  McTest_StreamSize = 4096
};

/* Formatting options availale to the streaming API. */
struct McTest_StreamFormatOptions {
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
struct McTest_Stream {
  int size;
  struct McTest_StreamFormatOptions options;
  char message[McTest_StreamSize + 2];
  char staging[32];
  char format[32];
  char unpack[32];
  union {
    uint64_t as_uint64;
    double as_fp64;
  } value;
};

/* Hard-coded streams for each log level. */
static struct McTest_Stream McTest_Streams[McTest_LogFatal + 1] = {};

static char McTest_EndianSpecifier = '=';

/* Figure out what the Python `struct` endianness specifier should be. */
MCTEST_INITIALIZER(DetectEndianness) {
  static const int one = 1;
  if ((const char *) &one) {
    McTest_EndianSpecifier = '<';  /* Little endian. */
  } else {
    McTest_EndianSpecifier = '>';  /* Big endian. */
  }
}

static void McTest_StreamUnpack(struct McTest_Stream *stream, char type) {
  stream->unpack[0] = McTest_EndianSpecifier;
  stream->unpack[1] = type;
  stream->unpack[2] = '\0';
}

/* Fill in the format for when we want to stream an integer. */
static void McTest_StreamIntFormat(struct McTest_Stream *stream,
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

static void CheckCapacity(struct McTest_Stream *stream, int num_chars_to_add) {
  if (0 > num_chars_to_add) {
    McTest_Abandon("Can't add a negative number of characters to a stream.");
  } else if ((stream->size + num_chars_to_add) >= McTest_StreamSize) {
    McTest_Abandon("Exceeded capacity of stream buffer.");
  }
}

/* Stream an integer into the stream's message. This function is designed to
 * be hooked by the symbolic executor, so that it can easily pull out the
 * relevant data from `*val`, which may be symbolic, and defer the actual
 * formatting until later. */
MCTEST_NOINLINE
void _McTest_StreamInt(enum McTest_LogLevel level, const char *format,
                       const char *unpack, uint64_t *val) {
  struct McTest_Stream *stream = &(McTest_Streams[level]);
  int size = 0;
  int remaining_size = McTest_StreamSize - stream->size;
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

MCTEST_NOINLINE
void _McTest_StreamFloat(enum McTest_LogLevel level, const char *format,
                         const char *unpack, double *val) {
  struct McTest_Stream *stream = &(McTest_Streams[level]);
  int remaining_size = McTest_StreamSize - stream->size;
  int size = snprintf(&(stream->message[stream->size]),
                      remaining_size, format, *val);
  CheckCapacity(stream, size);
  stream->size += size;
}

MCTEST_NOINLINE
void _McTest_StreamString(enum McTest_LogLevel level, const char *format,
                          const char *str) {
  struct McTest_Stream *stream = &(McTest_Streams[level]);
  int remaining_size = McTest_StreamSize - stream->size;
  int size = snprintf(&(stream->message[stream->size]),
                      remaining_size, format, str);
  CheckCapacity(stream, size);
  stream->size += size;
}

#define MAKE_INT_STREAMER(Type, type, is_unsigned, pack_kind) \
    void McTest_Stream ## Type(enum McTest_LogLevel level, type val) { \
      struct McTest_Stream *stream = &(McTest_Streams[level]); \
      McTest_StreamIntFormat(stream, sizeof(val), is_unsigned); \
      McTest_StreamUnpack(stream, pack_kind); \
      stream->value.as_uint64 = (uint64_t) val; \
      _McTest_StreamInt(level, stream->format, stream->unpack, \
                        &(stream->value.as_uint64)); \
    }

MAKE_INT_STREAMER(Pointer, void *, 1, (sizeof(void *) == 8 ? 'Q' : 'I'))

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
void McTest_StreamCStr(enum McTest_LogLevel level, const char *begin) {
  _McTest_StreamString(level, "%s", begin);
}

/* Stream a some data in the inclusive range `[begin, end]` into the
 * stream's message. */
/*void McTest_StreamData(enum McTest_LogLevel level, const void *begin,
                       const void *end) {
  struct McTest_Stream *stream = &(McTest_Streams[level]);
  int remaining_size = McTest_StreamSize - stream->size;
  int input_size = (int) ((uintptr_t) end - (uintptr_t) begin) + 1;
  CheckCapacity(stream, input_size);
  memcpy(&(stream->message[stream->size]), begin, (size_t) input_size);
  stream->size += input_size;
}*/

/* Stream a `double` into the stream's message. This function is designed to
 * be hooked by the symbolic executor, so that it can easily pull out the
 * relevant data from `*val`, which may be symbolic, and defer the actual
 * formatting until later. */
void McTest_StreamDouble(enum McTest_LogLevel level, double val) {
  struct McTest_Stream *stream = &(McTest_Streams[level]);
  const char *format = "%f";  /* TODO(pag): Support more? */
  stream->value.as_fp64 = val;
  McTest_StreamUnpack(stream, 'd');
  _McTest_StreamFloat(level, format, stream->unpack, &(stream->value.as_fp64));
}

/* Flush the contents of the stream to a log. */
void McTest_LogStream(enum McTest_LogLevel level) {
  struct McTest_Stream *stream = &(McTest_Streams[level]);
  if (stream->size) {
    stream->message[stream->size] = '\n';
    stream->message[stream->size + 1] = '\0';
    stream->message[McTest_StreamSize] = '\0';
    McTest_Log(level, stream->message);
    memset(stream->message, 0, McTest_StreamSize);
    stream->size = 0;
  }
}

/* Reset the formatting in a stream. */
void McTest_StreamResetFormatting(enum McTest_LogLevel level) {
  struct McTest_Stream *stream = &(McTest_Streams[level]);
  memset(&(stream->options), 0, sizeof(stream->options));
}

/* Approximately do string format parsing and convert it into calls into our
 * streaming API. */
static int McTest_StreamFormatValue(enum McTest_LogLevel level,
                                    const char *format, va_list args) {
  struct McTest_Stream *stream = &(McTest_Streams[level]);
  char format_buf[32] = {'\0'};
  int i = 0;
  int k = 0;
  int length = 4;
  char ch = '\0';
  int is_string = 0;
  int is_unsigned = 0;
  int is_float = 0;
  int long_double = 0;
  char extract = '\0';

#define READ_FORMAT_CHAR \
  ch = format[i]; \
  format_buf[i - k] = ch; \
  i++

  READ_FORMAT_CHAR;  /* Read the '%' */

  if ('%' != ch) {
    McTest_Abandon("Invalid format.");
    return 0;
  }

  /* Flags */
get_flag_char:
  READ_FORMAT_CHAR;
  switch (ch) {
    case '\0':
      McTest_Abandon("Incomplete format (flags).");
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
      McTest_Abandon("Incomplete format (width).");
      return 0;
    case '*':
      McTest_Abandon("Variable width printing not supported.");
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
        McTest_Abandon("Incomplete format (precision).");
        return 0;
      case '*':
        McTest_Abandon("Variable precision printing not supported.");
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
      McTest_Abandon("Incomplete format (length).");
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
      length *= 2;
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
  } else if (8 < length) {
    length = 8;
  }

  format_buf[i] = '\0';

  /* Specifier */
  switch(ch) {
    case '\0':
      McTest_Abandon("Incomplete format (specifier).");
      return 0;

    case 'n':
      return i;  /* Nothing printed. */

    /* Print a character. */
    case 'c':
      stream->value.as_uint64 = (uint64_t) (char) va_arg(args, int);
      extract = 'c';
      goto common_stream_int;

    /* Signed integer. */
    case 'd':
    case 'i':
      if (1 == length) {
        stream->value.as_uint64 = (uint64_t) (int8_t) va_arg(args, int);
        extract = 'b';
      } else if (2 == length) {
        stream->value.as_uint64 = (uint64_t) (int16_t) va_arg(args, int);
        extract = 'h';
      } else if (4 == length) {
        stream->value.as_uint64 = (uint64_t) (int32_t) va_arg(args, int);
        extract = 'i';
      } else if (8 == length) {
        stream->value.as_uint64 = (uint64_t) va_arg(args, int64_t);
        extract = 'q';
      } else {
        McTest_Abandon("Unsupported integer length.");
      }
      goto common_stream_int;

    /* Pointer. */
    case 'p':
      length = (int) sizeof(void *);
      format_buf[i - 1] = 'x';
      /* Note: Falls through. */

    /* Unsigned, hex, octal */
    case 'u':
    case 'o':
    case 'x':
    case 'X':
      if (1 == length) {
        stream->value.as_uint64 = (uint64_t) (uint8_t) va_arg(args, int);
        extract = 'B';
      } else if (2 == length) {
        stream->value.as_uint64 = (uint64_t) (uint16_t) va_arg(args, int);
        extract = 'H';
      } else if (4 == length) {
        stream->value.as_uint64 = (uint64_t) (uint32_t) va_arg(args, int);
        extract = 'I';
      } else if (8 == length) {
        stream->value.as_uint64 = (uint64_t) va_arg(args, uint64_t);
        extract = 'Q';
      } else {
        McTest_Abandon("Unsupported integer length.");
      }

    common_stream_int:
      McTest_StreamUnpack(stream, extract);
      _McTest_StreamInt(level, format_buf, stream->unpack,
                        &(stream->value.as_uint64));
      break;

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
        stream->value.as_fp64 = (double) va_arg(args, long double);
      } else {
        stream->value.as_fp64 = va_arg(args, double);
      }
      McTest_StreamUnpack(stream, 'd');
      break;

    case 's':
      _McTest_StreamString(level, format_buf, va_arg(args, const char *));
      break;

    default:
      McTest_Abandon("Unsupported format specifier.");
      return 0;
  }

  return i;
}

static char McTest_Format[McTest_StreamSize + 1];

/* Stream some formatted input */
void McTest_StreamVFormat(enum McTest_LogLevel level, const char *format_,
                          va_list args) {
  char *begin = NULL;
  char *end = NULL;
  char *format = McTest_Format;
  int i = 0;
  char ch = '\0';
  char next_ch = '\0';

  strncpy(format, format_, McTest_StreamSize);
  format[McTest_StreamSize] = '\0';

  McTest_ConcretizeCStr(format);

  for (i = 0; '\0' != (ch = format[i]); ) {
    if (!begin) {
      begin = &(format[i]);
    }

    if ('%' == ch) {
      if ('%' == format[i + 1]) {
        end = &(format[i]);
        next_ch = end[1];
        end[1] = '\0';
        McTest_StreamCStr(level, begin);
        end[1] = next_ch;
        begin = NULL;
        end = NULL;
        i += 2;

      } else {
        if (end) {
          next_ch = end[1];
          end[1] = '\0';
          McTest_StreamCStr(level, begin);
          end[1] = next_ch;
        }
        begin = NULL;
        end = NULL;
        i += McTest_StreamFormatValue(level, &(format[i]), args);
      }
    } else {
      end = &(format[i]);
      i += 1;
    }
  }

  if (begin && begin[0]) {
    McTest_StreamCStr(level, begin);
  }
}

/* Stream some formatted input */
void McTest_StreamFormat(enum McTest_LogLevel level, const char *format, ...) {
  va_list args;
  va_start(args, format);
  McTest_StreamVFormat(level, format, args);
  va_end(args);
}

MCTEST_END_EXTERN_C
