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
import collections
import logging
import multiprocessing
import sys
import traceback
from .common import DeepState

L = logging.getLogger("deepstate.angr")
L.setLevel(logging.INFO)


class DeepAngr(DeepState):
  def __init__(self, state=None, procedure=None):
    super(DeepAngr, self).__init__()
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

  def create_symbol(self, name, size_in_bits):
    return self.state.se.Unconstrained('name', size_in_bits)

  def read_uintptr_t(self, ea, concretize=True, constrain=False):
    addr_size_bytes = self.state.arch.bits // 8
    endness = self.state.arch.memory_endness
    next_ea = ea + addr_size_bytes
    val = self.state.memory.load(ea, size=addr_size_bytes, endness=endness)
    if concretize:
      val = self.concretize(val, constrain=constrain)
    return val, next_ea

  def read_uint64_t(self, ea, concretize=True, constrain=False):
    endness = self.state.arch.memory_endness
    val = self.state.memory.load(ea, size=8, endness=endness)
    if concretize:
      val = self.concretize(val, constrain=constrain)
    return val, ea + 8

  def read_uint32_t(self, ea, concretize=True, constrain=False):
    endness = self.state.arch.memory_endness
    val = self.state.memory.load(ea, size=4, endness=endness)
    if concretize:
      val = self.concretize(val, constrain=constrain)
    return val, ea + 4

  def read_uint8_t(self, ea, concretize=True, constrain=False):
    val = self.state.memory.load(ea, size=1)
    if concretize:
      val = self.concretize(val, constrain=constrain)
    if isinstance(val, str):
      assert len(val) == 1
      val = ord(val)
    return val, ea + 1

  def write_uint8_t(self, ea, val):
    self.state.memory.store(ea, val, size=1)
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
    concrete_val = self.state.solver.min(val)
    if constrain:
      self.add_constraint(val == concrete_val)
    return concrete_val

  def concretize_max(self, val, constrain=False):
    if isinstance(val, (int, long)):
      return val
    concrete_val = self.state.solver.max(val)
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
    super(DeepAngr, self).pass_test()
    self.procedure.exit(0)

  def fail_test(self):
    super(DeepAngr, self).fail_test()
    self.procedure.exit(1)

  def abandon_test(self):
    super(DeepAngr, self).abandon_test()
    self.procedure.exit(1)


def hook_function(project, ea, cls):
  """Hook the function `ea` with the SimProcedure `cls`."""
  project.hook(ea, cls(project=project))


class IsSymbolicUInt(angr.SimProcedure):
  """Implements DeepState_IsSymblicUInt, which returns 1 if its input argument
  has more then one solutions, and zero otherwise."""
  def run(self, arg):
    return DeepAngr(procedure=self).api_is_symbolic_uint(arg)


class Assume(angr.SimProcedure):
  """Implements _DeepState_Assume, which tries to inject a constraint."""
  def run(self, arg, expr_ea, file_ea, line):
    DeepAngr(procedure=self).api_assume(arg, expr_ea, file_ea, line)


class Pass(angr.SimProcedure):
  """Implements DeepState_Pass, which notifies us of a passing test."""
  def run(self):
    DeepAngr(procedure=self).api_pass()


class Crash(angr.SimProcedure):
  """Implements DeepState_Crash, which notifies us of a crashing test."""
  def run(self):
    DeepAngr(procedure=self).api_crash()


class Fail(angr.SimProcedure):
  """Implements DeepState_Fail, which notifies us of a failing test."""
  def run(self):
    DeepAngr(procedure=self).api_fail()


class Abandon(angr.SimProcedure):
  """Implements DeepState_Fail, which notifies us of a failing test."""
  def run(self, reason):
    DeepAngr(procedure=self).api_abandon(reason)


class SoftFail(angr.SimProcedure):
  """Implements DeepState_SoftFail, which notifies us of a failing test."""
  def run(self):
    DeepAngr(procedure=self).api_soft_fail()


class ConcretizeData(angr.SimProcedure):
  """Implements the `Deeptate_ConcretizeData` API function, which lets the
  programmer concretize some data in the exclusive range
  `[begin_ea, end_ea)`."""
  def run(self, begin_ea, end_ea):
    return DeepAngr(procedure=self).api_concretize_data(begin_ea, end_ea)


class ConcretizeCStr(angr.SimProcedure):
  """Implements the `Deeptate_ConcretizeCStr` API function, which lets the
    programmer concretize a NUL-terminated string starting at `begin_ea`."""
  def run(self, begin_ea):
    return DeepAngr(procedure=self).api_concretize_cstr(begin_ea)


class MinUInt(angr.SimProcedure):
  """Implements the `Deeptate_MinUInt` API function, which lets the
    programmer ask for the minimum satisfiable value of an unsigned integer."""
  def run(self, val):
    return DeepAngr(procedure=self).api_min_uint(val)


class MaxUInt(angr.SimProcedure):
  """Implements the `Deeptate_MaxUInt` API function, which lets the
    programmer ask for the minimum satisfiable value of a signed integer."""
  def run(self, val):
    return DeepAngr(procedure=self).api_max_uint(val)


class StreamInt(angr.SimProcedure):
  """Implements _DeepState_StreamInt, which gives us an integer to stream, and
  the format to use for streaming."""
  def run(self, level, format_ea, unpack_ea, uint64_ea):
    DeepAngr(procedure=self).api_stream_int(level, format_ea, unpack_ea,
                                            uint64_ea)

class StreamFloat(angr.SimProcedure):
  """Implements _DeepState_StreamFloat, which gives us an double to stream, and
  the format to use for streaming."""
  def run(self, level, format_ea, unpack_ea, double_ea):
    DeepAngr(procedure=self).api_stream_float(level, format_ea, unpack_ea,
                                              double_ea)


class StreamString(angr.SimProcedure):
  """Implements _DeepState_StreamString, which gives us an double to stream, and
  the format to use for streaming."""
  def run(self, level, format_ea, str_ea):
    DeepAngr(procedure=self).api_stream_string(level, format_ea, str_ea)


class ClearStream(angr.SimProcedure):
  """Implements DeepState_ClearStream, which clears the contents of a stream for
  level `level`."""
  def run(self, level):
    DeepAngr(procedure=self).api_clear_stream(level)


class LogStream(angr.SimProcedure):
  """Implements DeepState_LogStream, which converts the contents of a stream for
  level `level` into a log for level `level`."""
  def run(self, level):
    DeepAngr(procedure=self).api_log_stream(level)


class Log(angr.SimProcedure):
  """Implements DeepState_Log, which lets Angr intercept and handle the
  printing of log messages from the simulated tests."""
  def run(self, level, ea):
    DeepAngr(procedure=self).api_log(level, ea)


def do_run_test(project, test, apis, run_state):
  """Symbolically executes a single test function."""

  test_state = project.factory.call_state(
      test.ea,
      base_state=run_state)

  mc = DeepAngr(state=test_state)
  mc.begin_test(test)
  del mc

  errored = []
  test_manager = angr.SimulationManager(
      project=project,
      active_states=[test_state],
      errored=errored)

  try:
    test_manager.run()
  except Exception as e:
    L.error("Uncaught exception: {}\n{}".format(e, traceback.format_exc()))

  for state in test_manager.deadended:
    DeepAngr(state=state).report()

  for error in test_manager.errored:
    da = DeepAngr(state=error.state)
    da.crash_test()
    da.report()

def run_test(project, test, apis, run_state):
  """Symbolically executes a single test function."""
  try:
    do_run_test(project, test, apis, run_state)
  except Exception as e:
    L.error("Uncaught exception: {}\n{}".format(e, traceback.format_exc()))


def find_symbol_ea(project, name):
  try:
    ea = project.kb.labels.lookup(name)
    if ea:
      return ea
  except:
    pass

  try:
    return project.kb.labels.lookup("_{}".format(name))
  except:
    pass

  return 0

def main():
  """Run DeepState."""
  args = DeepAngr.parse_args()

  try:
    project = angr.Project(
        args.binary,
        use_sim_procedures=True,
        translation_cache=True,
        support_selfmodifying_code=False,
        auto_load_libs=True,
        exclude_sim_procedures_list=['printf', '__printf_chk',
                                     'vprintf', '__vprintf_chk',
                                     'fprintf', '__fprintf_chk',
                                     'vfprintf', '__vfprintf_chk',
                                     'puts', 'abort', '__assert_fail',
                                     '__stack_chk_fail'])
  except Exception as e:
    L.critical("Cannot create Angr instance on binary {}: {}".format(
        args.binary, e))
    return 1

  setup_ea = find_symbol_ea(project, 'DeepState_Setup')
  if not setup_ea:
    L.critical("Cannot find symbol `DeepState_Setup` in binary `{}`".format(
        args.binary))
    return 1

  entry_state = project.factory.entry_state(
      add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                   angr.options.STRICT_PAGE_ACCESS})

  addr_size_bits = entry_state.arch.bits

  # Concretely execute up until `DeepState_Setup`.
  concrete_manager = angr.SimulationManager(
        project=project,
        active_states=[entry_state])
  concrete_manager.explore(find=setup_ea)

  try:
    run_state = concrete_manager.found[0]
  except:
    L.critical("Execution never hit `DeepState_Setup` in binary `{}`".format(
        args.binary))
    return 1

  # Read the API table, which will tell us about the location of various
  # symbols. Technically we can look these up with the `labels.lookup` API,
  # but we have the API table for Manticore-compatibility, so we may as well
  # use it.
  ea_of_api_table = find_symbol_ea(project, 'DeepState_API')
  if not ea_of_api_table:
    L.critical("Could not find API table in binary `{}`".format(args.binary))
    return 1

  mc = DeepAngr(state=run_state)
  apis = mc.read_api_table(ea_of_api_table)

  # Hook various functions.
  hook_function(project, apis['IsSymbolicUInt'], IsSymbolicUInt)
  hook_function(project, apis['ConcretizeData'], ConcretizeData)
  hook_function(project, apis['ConcretizeCStr'], ConcretizeCStr)
  hook_function(project, apis['MinUInt'], MinUInt)
  hook_function(project, apis['MaxUInt'], MaxUInt)
  hook_function(project, apis['Assume'], Assume)
  hook_function(project, apis['Pass'], Pass)
  hook_function(project, apis['Crash'], Crash)
  hook_function(project, apis['Fail'], Fail)
  hook_function(project, apis['Abandon'], Abandon)
  hook_function(project, apis['SoftFail'], SoftFail)
  hook_function(project, apis['Log'], Log)
  hook_function(project, apis['StreamInt'], StreamInt)
  hook_function(project, apis['StreamFloat'], StreamFloat)
  hook_function(project, apis['StreamString'], StreamString)
  hook_function(project, apis['ClearStream'], ClearStream)
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
