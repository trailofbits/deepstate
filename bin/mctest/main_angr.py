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

from __future__ import absolute_import

import angr
import argparse
import collections
import logging
import multiprocessing
import sys
import traceback


L = logging.getLogger("mctest")
L.setLevel(logging.INFO)


def hook_function(project, ea, cls):
  """Hook the function `ea` with the SimProcedure `cls`."""
  project.hook(ea, cls(project=project))


def read_c_string(state, ea):
  """Read a concrete NUL-terminated string from `ea`."""
  assert isinstance(ea, (int, long))
  chars = []
  i = 0
  while True:
    char = state.mem[ea + i].char.resolved
    char = state.solver.eval(char, cast_to=str)
    if not ord(char[0]):
      break
    chars.append(char)
    i += 1
  return "".join(chars)


def read_uintptr_t(state, ea):
  """Read a uintptr_t value from memory."""
  next_ea = ea + (state.arch.bits // 8)
  val = state.solver.eval(state.mem[ea].uintptr_t.resolved, cast_to=int)
  return val, next_ea


def read_uint32_t(state, ea):
  """Read a uint32_t value from memory."""
  next_ea = ea + 4
  val = state.solver.eval(state.mem[ea].uint32_t.resolved, cast_to=int)
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
  data = state.se.Unconstrained('MCTEST_INPUT', input_size * 8)
  state.memory.store(input_begin_ea, data)
  return data


class IsSymbolicUInt(angr.SimProcedure):
  """Implements McTest_IsSymblicUInt, which returns 1 if its input argument
  has more then one solutions, and zero otherwise."""
  def run(self, arg):
    solutions = self.state.solver.eval_upto(arg, 2)
    if not solutions:
      return 0
    elif 1 == len(solutions):
      if self.state.se.symbolic(arg):
        self.state.solver.add(arg == solutions[0])
      return 0
    else:
      return 1


class Assume(angr.SimProcedure):
  """Implements _McTest_Assume, which tries to inject a constraint."""
  def run(self, arg):
    constraint = arg != 0
    self.state.solver.add(constraint)
    if not self.state.solver.satisfiable():
      L.error("Failed to assert assumption {}".format(constraint))
      self.exit(2)


def report_state(state):
  test = state.globals['test']
  if state.globals['failed']:
    message = (3, "Failed: {}".format(test.name))
  else:
    message = (1, "Passed: {}".format(test.name))
  state.globals['log_messages'].append(message)


class Pass(angr.SimProcedure):
  """Implements McTest_Pass, which notifies us of a passing test."""
  def run(self):
    report_state(self.state)
    self.exit(self.state.globals['failed'])


class Fail(angr.SimProcedure):
  """Implements McTest_Fail, which notifies us of a passing test."""
  def run(self):
    self.state.globals['failed'] = 1
    report_state(self.state)
    self.exit(1)


class SoftFail(angr.SimProcedure):
  """Implements McTest_SoftFail, which notifies us of a passing test."""
  def run(self):
    self.state.globals['failed'] = 1


LEVEL_TO_LOGGER = {
  0: L.debug,
  1: L.info,
  2: L.warning,
  3: L.error,
  4: L.critical
}


class Log(angr.SimProcedure):
  """Implements McTest_Log, which lets Angr intercept and handle the
  printing of log messages from the simulated tests."""
  def run(self, level, begin_ea_):
    level = self.state.solver.eval(level, cast_to=int)
    assert level in LEVEL_TO_LOGGER

    begin_ea = self.state.solver.eval(begin_ea_, cast_to=int)
    if self.state.se.symbolic(begin_ea_):
      self.state.solver.add(begin_ea_ == begin_ea)

    data = []
    for i in xrange(4096):
      b = self.state.memory.load(begin_ea + i, size=1)
      solutions = self.state.solver.eval_upto(b, 2, cast_to=int)
      if 1 == len(solutions) and solutions[0] == 0:
        break
      data.append(b)

    self.state.globals['log_messages'].append((level, data))

    if 3 == level:
      self.state.globals['failed'] = 1  # Soft failure on an error log message.
    elif 4 == level:
      self.state.globals['failed'] = 1
      report_state(self.state)
      self.exit(1)


def done_test(state):
  test = state.globals['test']
  input_length, _ = read_uint32_t(state, state.globals['InputIndex'])
  
  # Dump out any pending log messages reported by `McTest_Log`.
  for level, message in state.globals['log_messages']:
    data = []
    for b in message:
      if not isinstance(b, str):
        b = state.solver.eval(b, cast_to=str)
      if not ord(b):
        break
      data.append(b)

    LEVEL_TO_LOGGER[level]("".join(data))

  max_length = state.globals['InputEnd'] - state.globals['InputBegin']
  if input_length > max_length:
    L.critical("Test used too many input bytes ({} vs. {})".format(
        input_length, max_length))
    return

  # Solve for the input bytes.
  output = []
  data = state.memory.load(state.globals['InputBegin'], size=input_length)
  data = state.solver.eval(data, cast_to=str)
  for i in xrange(input_length):
    output.append("{:2x}".format(ord(data[i])))

  L.info("Input: {}".format(" ".join(output)))


def do_run_test(project, test, apis, run_state):
  """Symbolically executes a single test function."""

  test_state = project.factory.call_state(
      test.ea,
      base_state=run_state)

  messages = [(1, "Running {} from {}({})".format(
      test.name, test.file_name, test.line_number))]

  test_state.globals['InputBegin'] = apis['InputBegin']
  test_state.globals['InputEnd'] = apis['InputEnd']
  test_state.globals['InputIndex'] = apis['InputIndex']
  test_state.globals['test'] = test
  test_state.globals['failed'] = 0
  test_state.globals['log_messages'] = messages
  
  make_symbolic_input(test_state, apis['InputBegin'], apis['InputEnd'])

  errored = []
  test_manager = angr.SimulationManager(
      project=project,
      active_states=[test_state],
      errored=errored)

  try:
    test_manager.run()
  except Exception as e:
    L.error("Uncaught exception: {}\n{}".format(
        sys.exc_info()[0], traceback.format_exc()))

  for state in test_manager.deadended:
    done_test(state)


def run_test(project, test, apis, run_state):
  """Symbolically executes a single test function."""
  try:
    do_run_test(project, test, apis, run_state)
  except Exception as e:
    L.error("Uncaught exception: {}\n{}".format(
        sys.exc_info()[0], traceback.format_exc()))


def main():
  """Run McTest."""

  parser = argparse.ArgumentParser(
      description="Symbolically execute unit tests with Angr")

  parser.add_argument(
      "--num_workers", default=1, type=int,
      help="Number of workers to spawn for testing and test generation.")

  parser.add_argument(
      "binary", type=str, help="Path to the test binary to run.")

  args = parser.parse_args()

  project = angr.Project(
      args.binary,
      use_sim_procedures=True,
      translation_cache=True,
      support_selfmodifying_code=False,
      auto_load_libs=True)

  entry_state = project.factory.entry_state(
      add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                   angr.options.STRICT_PAGE_ACCESS})

  addr_size_bits = entry_state.arch.bits

  # Concretely execute up until `McTest_InjectAngr`.
  concrete_manager = angr.SimulationManager(
        project=project,
        active_states=[entry_state])
  setup_ea = project.kb.labels.lookup('McTest_Setup')
  concrete_manager.explore(find=setup_ea)
  run_state = concrete_manager.found[0]
    
  # Read the API table, which will tell us about the location of various
  # symbols. Technically we can look these up with the `labels.lookup` API,
  # but we have the API table for Manticore-compatibility, so we may as well
  # use it. 
  ea_of_api_table = project.kb.labels.lookup('McTest_API')
  apis = read_api_table(run_state, ea_of_api_table)

  # Hook various functions.
  hook_function(project, apis['IsSymbolicUInt'], IsSymbolicUInt)
  hook_function(project, apis['Assume'], Assume)
  hook_function(project, apis['Pass'], Pass)
  hook_function(project, apis['Fail'], Fail)
  hook_function(project, apis['SoftFail'], SoftFail)
  hook_function(project, apis['Log'], Log)

  # Find the test cases that we want to run.
  tests = find_test_cases(run_state, apis['LastTestInfo'])

  L.info("Running {} tests across {} workers".format(
      len(tests), args.num_workers))

  pool = multiprocessing.Pool(processes=max(1, args.num_workers))
  results = []

  # For each test, create a simulation manager whose initial state calls into
  # the test case function.
  test_managers = []
  for test in tests:
    res = pool.apply_async(run_test, (project, test, apis, run_state))
    results.append(res)

  pool.close()
  pool.join()

  return 0

if "__main__" == __name__:
  exit(main())
