# Copyright (c) 2017 Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import collections
import logging
import struct

# Represents a TestInfo data structure (the information we know about a test.)
TestInfo = collections.namedtuple(
    'TestInfo', 'ea name file_name line_number')


LOG_LEVEL_DEBUG = 0
LOG_LEVEL_INFO = 1
LOG_LEVEL_WARNING = 2
LOG_LEVEL_ERROR = 3
LOG_LEVEL_FATAL = 4


LOGGER = logging.getLogger("deepstate")
LOGGER.setLevel(logging.DEBUG)


LOG_LEVEL_TO_LOGGER = {
  LOG_LEVEL_DEBUG: LOGGER.debug,
  LOG_LEVEL_INFO: LOGGER.info,
  LOG_LEVEL_WARNING: LOGGER.warning,
  LOG_LEVEL_ERROR: LOGGER.error,
  LOG_LEVEL_FATAL: LOGGER.critical
}


class Stream(object):
  def __init__(self, entries):
    self.entries = entries


class DeepState(object):
  """Wrapper around a symbolic executor for making it easy to do common DeepState-
  specific things."""
  def __init__(self):
    pass

  def get_context(self):
    raise NotImplementedError("Must be implemented by engine.")

  def create_symbol(self, name, size_in_bits):
    raise NotImplementedError("Must be implemented by engine.")

  def is_symbolic(self, val):
    raise NotImplementedError("Must be implemented by engine.")

  def read_uintptr_t(self, ea, concretize=True, constrain=False):
    raise NotImplementedError("Must be implemented by engine.")

  def read_uint64_t(self, ea, concretize=True, constrain=False):
    raise NotImplementedError("Must be implemented by engine.")

  def read_uint32_t(self, ea, concretize=True, constrain=False):
    raise NotImplementedError("Must be implemented by engine.")

  def read_uint8_t(self, ea, concretize=True, constrain=False):
    raise NotImplementedError("Must be implemented by engine.")

  def write_uint8_t(self, ea, val):
    raise NotImplementedError("Must be implemented by engine.")

  def concretize(self, val, constrain=False):
    raise NotImplementedError("Must be implemented by engine.")

  def concretize_min(self, val, constrain=False):
    raise NotImplementedError("Must be implemented by engine.")

  def concretize_many(self, val, max_num):
    raise NotImplementedError("Must be implemented by engine.")

  def add_constraint(self, expr):
    raise NotImplementedError("Must be implemented by engine.")

  @property
  def context(self):
    """Gives convenient property-based access to a dictionary holding state-
    local varaibles."""
    return self.get_context()

  def read_c_string(self, ea, concretize=True, constrain=False):
    """Read a NUL-terminated string from `ea`."""
    assert isinstance(ea, (int, long))
    chars = []
    i = 0
    while True:
      b, ea = self.read_uint8_t(ea, concretize=concretize, constrain=constrain)
      if self.is_symbolic(b):
        b_maybe_nul = self.concretize_min(b)
        if not b_maybe_nul:
          break  # Stop at the first possible NUL byte.
      else:
        # Concretize if it's not symbolic; we might have a concrete bitvector.
        b = self.concretize(b)
        if not b:
          break
      chars.append(b)

    next_ea = ea + len(chars) + 1
    if concretize:
      return "".join(chr(b) for b in chars), next_ea
    else:
      return chars, next_ea

  def read_test_info(self, ea):
    """Read in a `DeepState_TestInfo` info structure from memory."""
    prev_test_ea, ea = self.read_uintptr_t(ea)
    test_func_ea, ea = self.read_uintptr_t(ea)
    test_name_ea, ea = self.read_uintptr_t(ea)
    file_name_ea, ea = self.read_uintptr_t(ea)
    file_line_num, _ = self.read_uint32_t(ea)

    if not test_func_ea or \
       not test_name_ea or \
       not file_name_ea or \
       not file_line_num:  # `__LINE__` in C always starts at `1` ;-)
      return None, prev_test_ea

    test_name, _ = self.read_c_string(test_name_ea)
    file_name, _ = self.read_c_string(file_name_ea)
    info = TestInfo(test_func_ea, test_name, file_name, file_line_num)
    return info, prev_test_ea

  def find_test_cases(self):
    """Find the test case descriptors."""
    tests = []
    info_ea, _ = self.read_uintptr_t(self.context['apis']['LastTestInfo'])
    while info_ea:
      test, info_ea = self.read_test_info(info_ea)
      if test:
        tests.append(test)
    tests.sort(key=lambda t: (t.file_name, t.line_number))
    return tests

  def read_api_table(self, ea):
    """Reads in the API table."""
    apis = {}
    while True:
      api_name_ea, ea = self.read_uintptr_t(ea)
      api_ea, ea = self.read_uintptr_t(ea)
      if not api_name_ea or not api_ea:
        break
      api_name, _ = self.read_c_string(api_name_ea)
      apis[api_name] = api_ea
    self.context['apis'] = apis
    return apis

  def begin_test(self, info):
    """Begin processing the test associated with `info`."""
    self.context['failed'] = False
    self.context['abandoned'] = False
    self.context['log'] = []
    for level in LOG_LEVEL_TO_LOGGER:
      self.context['stream_{}'.format(level)] = []
    
    self.context['info'] = info
    self.log_message(LOG_LEVEL_INFO, "Running {} from {}({})".format(
        info.name, info.file_name, info.line_number))

    apis = self.context['apis']
    symbols = []
    for i, ea in enumerate(xrange(apis['InputBegin'], apis['InputEnd'])):
      symbol = self.create_symbol('DEEP_INPUT_{}'.format(i), 8)
      self.write_uint8_t(ea, symbol)
      symbols.append(symbol)

    self.context['symbols'] = symbols

  def log_message(self, level, message):
    """Add `message` to the `level`-specific log as a `Stream` object for
    deferred logging (at the end of the state)."""
    assert level in LOG_LEVEL_TO_LOGGER
    log = list(self.context['log'])  # Make a shallow copy (needed for Angr).

    if isinstance(message, (str, list, tuple)):
      log.append((level, Stream([(str, "%s", None, message)])))
    else:
      assert isinstance(message, Stream)
      log.append((level, message))

    self.context['log'] = log

  def _concretize_bytes(self, byte_str):
    """Concretize the bytes of `byte_str`."""
    new_bytes = []
    for b in byte_str:
      if isinstance(b, str):
        assert len(b) == 1
        new_bytes.append(ord(b))
      elif isinstance(b, (int, long)):
        new_bytes.append(b)
      else:
        new_bytes.append(self.concretize(b, constrain=True))
    return new_bytes

  def _stream_to_message(self, stream):
    """Convert a `Stream` object into a single string message representing
    the concatenation of all formatted stream entries."""
    assert isinstance(stream, Stream)
    message = []
    for val_type, format_str, unpack_str, val_bytes in stream.entries:
      val_bytes = self._concretize_bytes(val_bytes)
      if val_type == str:
        val = "".join(chr(b) for b in val_bytes)
      elif val_type == float:
        data = struct.pack('BBBBBBBB', *val_bytes)
        val = struct.unpack(unpack_str, data)[0]
      else:
        assert val_type == int
        
        # TODO(pag): I am pretty sure that this is wrong for big-endian.
        data = struct.pack('BBBBBBBB', *val_bytes)
        val = struct.unpack(unpack_str, data[:struct.calcsize(unpack_str)])[0]

        # Remove length specifiers that are not supported.
        format_str = format_str.replace('l', '')
        format_str = format_str.replace('h', '')
        format_str = format_str.replace('z', '')
        format_str = format_str.replace('t', '')

      message.extend(format_str % val)

    return "".join(message)

  def report(self):
    """Report on the pass/fail status of a test case, and dump its log."""
    info = self.context['info']
    apis = self.context['apis']
    input_length, _ = self.read_uint32_t(apis['InputIndex'])
    symbols = self.context['symbols']
    input_bytes = []
    for i in xrange(input_length):
      b = self.concretize(symbols[i], constrain=True)
      input_bytes.append("{:02x}".format(b))

    for level, stream in self.context['log']:
      logger = LOG_LEVEL_TO_LOGGER[level]
      logger(self._stream_to_message(stream))

    LOGGER.info("Input: {}".format(" ".join(input_bytes)))

  def pass_test(self):
    """Notify the symbolic executor that this test has passed and stop
    executing the current state."""
    pass

  def fail_test(self):
    """Notify the symbolic executor that this test has failed and stop
    executing the current state."""
    self.context['failed'] = True

  def abandon_test(self):
    """Notify the symbolic executor that this test has been abandoned due to
    some critical error and stop executing the current state."""
    self.context['abandoned'] = True

  def api_is_symbolic_uint(self, arg):
    """Implements the `DeepState_IsSymbolicUInt` API, which returns whether or
    not a given value is symbolic."""
    solutions = self.concretize_many(arg, 2)
    if not solutions:
      return 0
    elif 1 == len(solutions):
      if self.is_symbolic(arg):
        self.add_constraint(arg == solutions[0])
      return 0
    else:
      return 1

  def api_assume(self, arg):
    """Implements the `DeepState_Assume` API function, which injects a
    constraint into the solver."""
    constraint = arg != 0
    if not self.add_constraint(constraint):
      self.log_message(LOG_LEVEL_FATAL,
                       "Failed to add assumption {}".format(constraint))
      self.abandon_test()

  def api_concretize_data(self, begin_ea, end_ea):
    """Implements the `Deeptate_ConcretizeData` API function, which lets the
    programmer concretize some data in the exclusive range
    `[begin_ea, end_ea)`."""
    begin_ea = self.concretize(begin_ea, constrain=True)
    end_ea = self.concretize(end_ea, constrain=True)
    if end_ea < begin_ea:
      self.log_message(
          LOG_LEVEL_FATAL,
          "Invalid range [{:x}, {:x}) to McTest_Concretize".format(
              begin_ea, end_ea))
      self.abandon_test()

    for i in xrange(end_ea - begin_ea):
      val, _ = self.read_uint8_t(begin_ea + i, concretize=True, constrain=True)
      _ = self.write_uint8_t(begin_ea + i, val)

    return begin_ea

  def api_concretize_cstr(self, begin_ea):
    """Implements the `Deeptate_ConcretizeCStr` API function, which lets the
    programmer concretize a NUL-terminated string starting at `begin_ea`."""
    begin_ea = self.concretize(begin_ea, constrain=True)
    str_bytes, end_ea = self.read_c_string(begin_ea, concretize=False)
    next_ea = begin_ea
    for i, b in enumerate(str_bytes):
      b = self.concretize_min(b, constrain=True)
      next_ea = self.write_uint8_t(begin_ea + i, b)
    self.write_uint8_t(next_ea, 0)
    return begin_ea

  def api_pass(self):
    """Implements the `DeepState_Pass` API function, which marks this test as
    having passed, and stops further execution."""
    if self.context['failed']:
      self.api_fail()
    else:
      info = self.context['info']
      self.log_message(LOG_LEVEL_INFO, "Passed: {}".format(info.name))
      self.pass_test()

  def api_fail(self):
    """Implements the `DeepState_Fail` API function, which marks this test as
    having failed, and stops further execution."""
    self.context['failed'] = True
    info = self.context['info']
    self.log_message(LOG_LEVEL_ERROR, "Failed: {}".format(info.name))
    self.fail_test()

  def api_soft_fail(self):
    """Implements the `DeepState_SoftFail` API function, which marks this test
    as having failed, but lets execution continue."""
    self.context['failed'] = True

  def api_abandon(self, arg):
    """Implements the `DeepState_Abandon` API function, which marks this test
    as having aborted due to some unrecoverable error."""
    info = self.context['info']
    ea = self.concretize(arg, constrain=True)
    self.log_message(LOG_LEVEL_FATAL, self.read_c_string(ea)[0])
    self.log_message(LOG_LEVEL_FATAL, "Abandoned: {}".format(info.name))
    self.abandon_test()

  def api_log(self, level, ea):
    """Implements the `DeepState_Log` API function, which prints a C string
    to a specific log level."""
    self.api_log_stream(level)

    level = self.concretize(level, constrain=True)
    ea = self.concretize(ea, constrain=True)
    assert level in LOG_LEVEL_TO_LOGGER
    self.log_message(level, self.read_c_string(ea, concretize=False))
    
    if level == LOG_LEVEL_FATAL:
      self.api_fail()
    elif level == LOG_LEVEL_ERROR:
      self.api_soft_fail()

  def _api_stream_int_float(self, level, format_ea, unpack_ea, uint64_ea,
                            val_type):
    """Read the format information and int or float value data from memory
    and record it into a stream."""
    level = self.concretize(level, constrain=True)
    assert level in LOG_LEVEL_TO_LOGGER

    format_ea = self.concretize(format_ea, constrain=True)
    unpack_ea = self.concretize(unpack_ea, constrain=True)
    uint64_ea = self.concretize(uint64_ea, constrain=True)

    format_str, _ = self.read_c_string(format_ea)
    unpack_str, _ = self.read_c_string(unpack_ea)
    uint64_bytes = []
    for i in xrange(8):
      b, _ = self.read_uint8_t(uint64_ea + i, concretize=False)
      uint64_bytes.append(b)

    stream_id = 'stream_{}'.format(level)
    stream = list(self.context[stream_id])
    stream.append((val_type, format_str, unpack_str, uint64_bytes))
    self.context[stream_id] = stream

  def api_stream_int(self, level, format_ea, unpack_ea, uint64_ea):
    """Implements the `_DeepState_StreamInt`, which streams an integer into a
    holding buffer for the log."""
    return self._api_stream_int_float(level, format_ea, unpack_ea,
                                      uint64_ea, int)

  def api_stream_float(self, level, format_ea, unpack_ea, double_ea):
    """Implements the `_DeepState_StreamFloat`, which streams an integer into a
    holding buffer for the log."""
    return self._api_stream_int_float(level, format_ea, unpack_ea,
                                      double_ea, float)

  def api_stream_string(self, level, format_ea, str_ea):
    """Implements the `_DeepState_StreamString`, which streams a C-string into a
    holding buffer for the log."""
    level = self.concretize(level, constrain=True)
    assert level in LOG_LEVEL_TO_LOGGER

    format_ea = self.concretize(format_ea, constrain=True)
    str_ea = self.concretize(str_ea, constrain=True)
    format_str, _ = self.read_c_string(format_ea)
    print_str, _ = self.read_c_string(str_ea, concretize=False)
    
    stream_id = 'stream_{}'.format(level)
    stream = list(self.context[stream_id])
    stream.append((str, format_str, None, print_str))
    self.context[stream_id] = stream

  def api_log_stream(self, level):
    """Implements DeepState_LogStream, which converts the contents of a stream
    for level `level` into a log for level `level`."""
    level = self.concretize(level, constrain=True)
    assert level in LOG_LEVEL_TO_LOGGER
    stream_id = 'stream_{}'.format(level)
    stream = self.context[stream_id]
    if len(stream):
      self.context[stream_id] = []
      self.log_message(level, Stream(stream))

      if level == LOG_LEVEL_FATAL:
        self.api_fail()
      elif level == LOG_LEVEL_ERROR:
        self.api_soft_fail()
