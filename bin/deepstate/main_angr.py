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

import angr
import argparse
import collections
import logging
import multiprocessing
import sys
import traceback
from .common import DeepState

L = logging.getLogger("deepstate.angr")
L.setLevel(logging.INFO)


class AngrTest(DeepState):
  def __init__(self, state=None, procedure=None):
    super(AngrTest, self).__init__()
    if procedure:
      self.procedure = procedure
      self.state = procedure.state
    elif state:
      self.procedure = None
      self.state = state

  def __del__(self):
    self.procedure = None
    self.state = None

  def get_context(self):
    return self.state.globals

  def is_symbolic(self, val):
    if isinstance(val, (int, long)):
      return False
    return self.state.se.symbolic(val)

  def read_uintptr_t(self, ea, concretize=True, constrain=False):
    next_ea = ea + (self.state.arch.bits // 8)
    val = self.state.mem[ea].uintptr_t.resolved
    if concretize:
      val = self.concretize(val, constrain=constrain)
    return val, next_ea

  def read_uint64_t(self, ea, concretize=True, constrain=False):
    val = self.state.mem[ea].uint64_t.resolved
    if concretize:
      val = self.concretize(val, constrain=constrain)
    return val, ea + 8

  def read_uint32_t(self, ea, concretize=True, constrain=False):
    val = self.state.mem[ea].uint32_t.resolved
    if concretize:
      val = self.concretize(val, constrain=constrain)
    return val, ea + 4

  def read_uint8_t(self, ea, concretize=True, constrain=False):
    val = self.state.mem[ea].uint8_t.resolved
    if concretize:
      val = self.concretize(val, constrain=constrain)
    if isinstance(val, str):
      assert len(val) == 1
      val = ord(val)
    return val, ea + 1

  def write_uint8_t(self, ea, val):
    self.state.mem[ea].uint8_t = val
    return ea + 1

  def concretize(self, val, constrain=False):
    if isinstance(val, (int, long)):
      return val
    elif isinstance(val, str):
      assert len(val) == 1
      return ord(val[0])

    concrete_val = self.state.solver.eval(val, cast_to=int)
    if constrain:
      self.add_constraint(val == concrete_val)

    return concrete_val

  def concretize_min(self, val, constrain=False):
    if isinstance(val, (int, long)):
      return val
    concrete_val = self.state.solver.min(val, cast_to=int)
    if constrain:
      self.add_constraint(val == concrete_val)
    return concrete_val

  def concretize_many(self, val, max_num):
    assert 0 < max_num
    if isinstance(val, (int, long)):
      return [val]
    return self.state.solver.eval_upto(val, max_num, cast_to=int)

  def add_constraint(self, expr):
    if self.is_symbolic(expr):
      self.state.solver.add(expr)
      return self.state.solver.satisfiable()
    else:
      return True

  def pass_test(self):
    super(AngrTest, self).pass_test()
    self.procedure.exit(0)

  def fail_test(self):
    super(AngrTest, self).fail_test()
    self.procedure.exit(1)

  def abandon_test(self):
    super(AngrTest, self).abandon_test()
    self.procedure.exit(1)


def hook_function(project, ea, cls):
  """Hook the function `ea` with the SimProcedure `cls`."""
  project.hook(ea, cls(project=project))


def make_symbolic_input(state, input_begin_ea, input_end_ea):
  """Fill in the input data array with symbolic data."""
  input_size = input_end_ea - input_begin_ea
  data = state.se.Unconstrained('DEEPSTATE_INPUT', input_size * 8)
  state.memory.store(input_begin_ea, data)
  return data


class IsSymbolicUInt(angr.SimProcedure):
  """Implements DeepState_IsSymblicUInt, which returns 1 if its input argument
  has more then one solutions, and zero otherwise."""
  def run(self, arg):
    return AngrTest(procedure=self).api_is_symbolic_uint(arg)


class Assume(angr.SimProcedure):
  """Implements _DeepState_Assume, which tries to inject a constraint."""
  def run(self, arg):
    AngrTest(procedure=self).api_assume(arg)


class Pass(angr.SimProcedure):
  """Implements DeepState_Pass, which notifies us of a passing test."""
  def run(self):
    AngrTest(procedure=self).api_pass()


class Fail(angr.SimProcedure):
  """Implements DeepState_Fail, which notifies us of a failing test."""
  def run(self):
    AngrTest(procedure=self).api_fail()


class Abandon(angr.SimProcedure):
  """Implements DeepState_Fail, which notifies us of a failing test."""
  def run(self, reason):
    AngrTest(procedure=self).api_abandon(reason)


class SoftFail(angr.SimProcedure):
  """Implements DeepState_SoftFail, which notifies us of a failing test."""
  def run(self):
    AngrTest(procedure=self).api_soft_fail()


class ConcretizeData(angr.SimProcedure):
  """Implements the `Deeptate_ConcretizeData` API function, which lets the
  programmer concretize some data in the exclusive range
  `[begin_ea, end_ea)`."""
  def run(self, begin_ea, end_ea):
    return AngrTest(procedure=self).api_concretize_data(begin_ea, end_ea)


class ConcretizeCStr(angr.SimProcedure):
  """Implements the `Deeptate_ConcretizeCStr` API function, which lets the
    programmer concretize a NUL-terminated string starting at `begin_ea`."""
  def run(self, begin_ea):
    return AngrTest(procedure=self).api_concretize_cstr(begin_ea)


class StreamInt(angr.SimProcedure):
  """Implements _DeepState_StreamInt, which gives us an integer to stream, and
  the format to use for streaming."""
  def run(self, level, format_ea, unpack_ea, uint64_ea):
    AngrTest(procedure=self).api_stream_int(level, format_ea, unpack_ea,
                                            uint64_ea)

class StreamFloat(angr.SimProcedure):
  """Implements _DeepState_StreamFloat, which gives us an double to stream, and
  the format to use for streaming."""
  def run(self, level, format_ea, unpack_ea, double_ea):
    AngrTest(procedure=self).api_stream_float(level, format_ea, unpack_ea,
                                              double_ea)


class StreamString(angr.SimProcedure):
  """Implements _DeepState_StreamString, which gives us an double to stream, and
  the format to use for streaming."""
  def run(self, level, format_ea, str_ea):
    AngrTest(procedure=self).api_stream_string(level, format_ea, str_ea)


class LogStream(angr.SimProcedure):
  """Implements DeepState_LogStream, which converts the contents of a stream for
  level `level` into a log for level `level`."""
  def run(self, level):
    AngrTest(procedure=self).api_log_stream(level)


class Log(angr.SimProcedure):
  """Implements DeepState_Log, which lets Angr intercept and handle the
  printing of log messages from the simulated tests."""
  def run(self, level, ea):
    AngrTest(procedure=self).api_log(level, ea)


def do_run_test(project, test, apis, run_state):
  """Symbolically executes a single test function."""

  test_state = project.factory.call_state(
      test.ea,
      base_state=run_state)

  mc = AngrTest(state=test_state)
  mc.begin_test(test)
  del mc
  
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
    AngrTest(state=state).report()

  for error in test_manager.errored:
    print "Error", error.error
    error.debug()

def run_test(project, test, apis, run_state):
  """Symbolically executes a single test function."""
  try:
    do_run_test(project, test, apis, run_state)
  except Exception as e:
    L.error("Uncaught exception: {}\n{}".format(
        sys.exc_info()[0], traceback.format_exc()))


def main():
  """Run DeepState."""
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
      auto_load_libs=True,
      exclude_sim_procedures_list=['printf', '__printf_chk',
                                   'vprintf', '__vprintf_chk',
                                   'fprintf', '__fprintf_chk',
                                   'vfprintf', '__vfprintf_chk'])

  entry_state = project.factory.entry_state(
      add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                   angr.options.STRICT_PAGE_ACCESS})

  addr_size_bits = entry_state.arch.bits

  # Concretely execute up until `DeepState_InjectAngr`.
  concrete_manager = angr.SimulationManager(
        project=project,
        active_states=[entry_state])
  setup_ea = project.kb.labels.lookup('DeepState_Setup')
  concrete_manager.explore(find=setup_ea)
  run_state = concrete_manager.found[0]

  # Read the API table, which will tell us about the location of various
  # symbols. Technically we can look these up with the `labels.lookup` API,
  # but we have the API table for Manticore-compatibility, so we may as well
  # use it. 
  ea_of_api_table = project.kb.labels.lookup('DeepState_API')

  mc = AngrTest(state=run_state)
  apis = mc.read_api_table(ea_of_api_table)

  # Hook various functions.
  hook_function(project, apis['IsSymbolicUInt'], IsSymbolicUInt)
  hook_function(project, apis['ConcretizeData'], ConcretizeData)
  hook_function(project, apis['ConcretizeCStr'], ConcretizeCStr)
  hook_function(project, apis['Assume'], Assume)
  hook_function(project, apis['Pass'], Pass)
  hook_function(project, apis['Fail'], Fail)
  hook_function(project, apis['Abandon'], Abandon)
  hook_function(project, apis['SoftFail'], SoftFail)
  hook_function(project, apis['Log'], Log)
  hook_function(project, apis['StreamInt'], StreamInt)
  hook_function(project, apis['StreamFloat'], StreamFloat)
  hook_function(project, apis['StreamString'], StreamString)
  hook_function(project, apis['LogStream'], LogStream)

  # Find the test cases that we want to run.
  tests = mc.find_test_cases()
  del mc

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
