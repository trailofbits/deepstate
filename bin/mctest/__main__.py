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
  data = state.new_symbolic_buffer(nbytes=input_size, name='MCTEST_INPUT')
  state.cpu.write_bytes(input_begin_ea, data)  
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


def hook_Pass(state):
  """Implements McTest_Pass, which notifies us of a passing test."""
  L.info("Passed test case")
  if state.context['failed']:
    raise TerminateState("Got to end of failing test case.")
  else:
    raise TerminateState("Passed test case")


def hook_Fail(state):
  """Implements McTest_Fail, which notifies us of a passing test."""
  L.error("Failed test case")
  state.context['failed'] = 1
  raise TerminateState("Failed test case")


def hook_SoftFail(state):
  """Implements McTest_Fail, which notifies us of a passing test."""
  L.error("Soft failure in test case, continuing")
  state.context['failed'] = 1


LEVEL_TO_LOGGER = {
  0: L.debug,
  1: L.info,
  2: L.warning,
  3: L.error,
  4: L.critical
}


def hook_Log(state):
  """Implements McTest_Log, which lets Manticore intercept and handle the
  printing of log messages from the simulated tests."""
  pass

def hook(func):
  return lambda state: state.invoke_model(func)


def run_test(state, apis, test):
  """Run an individual test case."""
  state.cpu.PC = test.ea
  m = manticore.Manticore(state, sys.argv[1:])

  state = m.initial_state
  state.context['failed'] = 0
  state.context['log_messages'] = []
  state.context['input'] = make_symbolic_input(
      state, apis['InputBegin'], apis['InputEnd'])

  m.add_hook(apis['IsSymbolicUInt'], hook(hook_IsSymbolicUInt))
  m.add_hook(apis['Assume'], hook(hook_Assume))
  m.add_hook(apis['Pass'], hook(hook_Pass))
  m.add_hook(apis['Fail'], hook(hook_Fail))
  m.add_hook(apis['SoftFail'], hook(hook_SoftFail))
  m.run()


def run_tests(args, state, apis):
  """Run all of the test cases."""
  pool = multiprocessing.Pool(processes=max(1, args.num_workers))
  results = []
  tests = find_test_cases(state, apis['LastTestInfo'])
  for test in tests:
    print "Found test", test.name
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
