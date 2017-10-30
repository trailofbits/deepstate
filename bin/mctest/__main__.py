#!/usr/bin/env python
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


import argparse
import collections
import logging
import manticore
import multiprocessing
import sys
import traceback

from manticore.core.state import TerminateState
from manticore.utils.helpers import issymbolic


L = logging.getLogger("mctest")
L.setLevel(logging.INFO)


def read_c_string(state, ea):
  """Read a concrete NUL-terminated string from `ea`."""
  return state.cpu.read_string(ea)


def read_uintptr_t(state, ea):
  """Read a uintptr_t value from memory."""
  addr_size_bits = state.cpu.address_bit_size
  next_ea = ea + (addr_size_bits // 8)
  val = state.cpu.read_int(ea, size=addr_size_bits)
  if issymbolic(val):
    val = state.solve_one(val)
  return val, next_ea


def read_uint32_t(state, ea):
  """Read a uint32_t value from memory."""
  next_ea = ea + 4
  val = state.cpu.read_int(ea, size=32)
  if issymbolic(val):
    val = state.solve_one(val)
  return val, next_ea


TestInfo = collections.namedtuple(
    'TestInfo', 'ea name file_name line_number')


def read_test_info(state, ea):
  """Read in a `McTest_TestInfo` info structure from memory."""
  prev_test_ea, ea = read_uintptr_t(state, ea)
  test_func_ea, ea = read_uintptr_t(state, ea)
  test_name_ea, ea = read_uintptr_t(state, ea)
  file_name_ea, ea = read_uintptr_t(state, ea)
  file_line_num, _ = read_uint32_t(state, ea)

  if not test_func_ea or \
     not test_name_ea or \
     not file_name_ea or \
     not file_line_num:  # `__LINE__` in C always starts at `1` ;-)
    return None, prev_test_ea

  test_name = read_c_string(state, test_name_ea)
  file_name = read_c_string(state, file_name_ea)
  info = TestInfo(test_func_ea, test_name, file_name, file_line_num)
  return info, prev_test_ea


def find_test_cases(state, info_ea):
  """Find the test case descriptors."""
  tests = []
  info_ea, _ = read_uintptr_t(state, info_ea)
  while info_ea:
    test, info_ea = read_test_info(state, info_ea)
    if test:
      tests.append(test)
  tests.sort(key=lambda t: (t.file_name, t.line_number))
  return tests


def read_api_table(state, ea):
  """Reads in the API table."""
  apis = {}
  while True:
    api_name_ea, ea = read_uintptr_t(state, ea)
    api_ea, ea = read_uintptr_t(state, ea)
    if not api_name_ea or not api_ea:
      break
    api_name = read_c_string(state, api_name_ea)
    apis[api_name] = api_ea
  return apis


def make_symbolic_input(state, input_begin_ea, input_end_ea):
  """Fill in the input data array with symbolic data."""
  input_size = input_end_ea - input_begin_ea
  data = []
  for i in xrange(input_end_ea - input_begin_ea):
    input_byte = state.new_symbolic_value(8, "MCTEST_INPUT_{}".format(i))
    data.append(input_byte)
    state.cpu.write_int(input_begin_ea + i, input_byte, 8)

  return data


def hook_IsSymbolicUInt(state, arg):
  """Implements McTest_IsSymblicUInt, which returns 1 if its input argument
  has more then one solutions, and zero otherwise."""
  solutions = state.solve_n(arg, 2)
  if not solutions:
    return 0
  elif 1 == len(solutions):
    if issymbolic(arg):
      state.constrain(arg == solutions[0])
    return 0
  else:
    return 1


def hook_Assume(state, arg):
  """Implements _McTest_Assume, which tries to inject a constraint."""
  constraint = arg != 0
  if issymbolic(constraint):
    state.constrain(constraint)


OUR_TERMINATION_REASON = "I McTest'd it"


def report_state(state):
  test = state.context['test']
  if state.context['failed']:
    message = (3, "Failed: {}".format(test.name))
  else:
    message = (1, "Passed: {}".format(test.name))
  state.context['log_messages'].append(message)
  raise TerminateState(OUR_TERMINATION_REASON, testcase=False)


def hook_Pass(state):
  """Implements McTest_Pass, which notifies us of a passing test."""
  report_state(state)


def hook_Fail(state):
  """Implements McTest_Fail, which notifies us of a passing test."""
  state.context['failed'] = 1
  report_state(state)


def hook_SoftFail(state):
  """Implements McTest_Fail, which notifies us of a passing test."""
  state.context['failed'] = 1


LEVEL_TO_LOGGER = {
  0: L.debug,
  1: L.info,
  2: L.warning,
  3: L.error,
  4: L.critical
}


def hook_Log(state, level, begin_ea, end_ea):
  """Implements McTest_Log, which lets Manticore intercept and handle the
  printing of log messages from the simulated tests."""
  level = state.solve_one(level)
  assert level in LEVEL_TO_LOGGER

  begin_ea = state.solve_one(begin_ea)
  end_ea = state.solve_one(end_ea)
  assert begin_ea <= end_ea

  message_bytes = []
  for i in xrange(end_ea - begin_ea):
    message_bytes.append(state.cpu.memory[begin_ea + i])
  
  state.context['log_messages'].append((level, message_bytes))


def hook(func):
  return lambda state: state.invoke_model(func)


def done_test(_, state, state_id, reason):
  """Called when a state is terminated."""
  if OUR_TERMINATION_REASON not in reason:
    L.error("State {} terminated for unknown reason: {}".format(
        state_id, reason))
    return

  test = state.context['test']
  input_length, _ = read_uint32_t(state, state.context['InputIndex'])
  
  # Dump out any pending log messages reported by `McTest_Log`.
  for level, message_bytes in state.context['log_messages']:
    message = []
    for b in message_bytes:
      if issymbolic(b):
        b_ord = state.solve_one(b)
        state.constrain(b == b_ord)
        message.append(chr(b_ord))
      elif isinstance(b, (int, long)):
        message.append(chr(b))
      else:
        message.append(b)

    LEVEL_TO_LOGGER[level]("".join(message))

  max_length = state.context['InputEnd'] - state.context['InputBegin']
  if input_length > max_length:
    L.critical("Test used too many input bytes ({} vs. {})".format(
        input_length, max_length))
    return

  # Solve for the input bytes.
  output = []
  for i in xrange(input_length):
    b = state.cpu.read_int(state.context['InputBegin'] + i, 8)
    if issymbolic(b):
      b = state.solve_one(b)
    output.append("{:2x}".format(b))

  L.info("Input: {}".format(" ".join(output)))


def do_run_test(state, apis, test):
  """Run an individual test case."""
  state.cpu.PC = test.ea
  m = manticore.Manticore(state, sys.argv[1:])
  m.verbosity(1)

  state = m.initial_state
  messages = [(1, "Running {} from {}:{}".format(
      test.name, test.file_name, test.line_number))]

  state.context['InputBegin'] = apis['InputBegin']
  state.context['InputEnd'] = apis['InputEnd']
  state.context['InputIndex'] = apis['InputIndex']
  state.context['test'] = test
  state.context['failed'] = 0
  state.context['log_messages'] = messages
  
  make_symbolic_input(state, apis['InputBegin'], apis['InputEnd'])

  m.add_hook(apis['IsSymbolicUInt'], hook(hook_IsSymbolicUInt))
  m.add_hook(apis['Assume'], hook(hook_Assume))
  m.add_hook(apis['Pass'], hook(hook_Pass))
  m.add_hook(apis['Fail'], hook(hook_Fail))
  m.add_hook(apis['SoftFail'], hook(hook_SoftFail))
  m.add_hook(apis['Log'], hook(hook_Log))
  m.subscribe('will_terminate_state', done_test)
  m.run()


def run_test(state, apis, test):
  try:
    do_run_test(state, apis, test)
  except:
    L.error("Uncaught exception: {}\n{}".format(
        sys.exc_info()[0], traceback.format_exc()))


def run_tests(args, state, apis):
  """Run all of the test cases."""
  pool = multiprocessing.Pool(processes=max(1, args.num_workers))
  results = []
  tests = find_test_cases(state, apis['LastTestInfo'])
  for test in tests:
    res = pool.apply_async(run_test, (state, apis, test))
    results.append(res)

  pool.close()
  pool.join()

  exit(0)


def main():
  parser = argparse.ArgumentParser(
      description="Symbolically execute unit tests with Manticore")

  parser.add_argument(
      "--num_workers", default=1, type=int,
      help="Number of workers to spawn for testing and test generation.")

  parser.add_argument(
      "binary", type=str, help="Path to the test binary to run.")

  args = parser.parse_args()

  m = manticore.Manticore(sys.argv[1], sys.argv[1:])
  m.verbosity(1)

  # Hack to get around current broken _get_symbol_address 
  m._binary_type = 'not elf'
  m._binary_obj = m._initial_state.platform.elf

  setup_ea = m._get_symbol_address('McTest_Setup')
  setup_state = m._initial_state

  ea_of_api_table = m._get_symbol_address('McTest_API')
  apis = read_api_table(setup_state, ea_of_api_table)

  m.add_hook(setup_ea, lambda state: run_tests(args, state, apis))
  m.run()


if "__main__" == __name__:
  exit(main())
