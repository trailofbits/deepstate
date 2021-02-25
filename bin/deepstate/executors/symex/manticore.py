#!/usr/bin/env python3.6
# Copyright (c) 2019 Trail of Bits, Inc.
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

import logging

import sys
try:
    import manticore
    import manticore.native
except Exception as e:
  if "Z3NotFoundError" in repr(type(e)):
    print("Manticore requires Z3 to be installed.")
    sys.exit(255)
  else:
    raise
import traceback

from manticore.utils import config
from manticore.utils import log
from manticore.core.state import TerminateState
from manticore.core.smtlib.solver import SolverType # type: ignore
from manticore.native.manticore import _make_initial_state

from deepstate.core import SymexFrontend, TestInfo

L = logging.getLogger(__name__)

OUR_TERMINATION_REASON = "I DeepState'd it"

consts = config.get_group("core")

# make sure we use yices
consts_smt = config.get_group("smt")
consts_smt.solver=SolverType.yices

class DeepManticore(SymexFrontend):

  NAME = "Manticore"

  def __init__(self, state):
    super(DeepManticore, self).__init__()
    self.state = state

  def __del__(self):
    self.state = None

  def get_context(self):
    return self.state.context

  def is_symbolic(self, val):
    return manticore.issymbolic(val)

  def create_symbol(self, name, size_in_bits):
    return self.state.new_symbolic_value(size_in_bits)

  def read_uintptr_t(self, ea, concretize=True, constrain=False):
    addr_size_bits = self.state.cpu.address_bit_size
    next_ea = ea + (addr_size_bits // 8)
    val = self.state.cpu.read_int(ea, size=addr_size_bits)
    if concretize:
      val = self.concretize(val, constrain=constrain)
    return val, next_ea

  def read_uint64_t(self, ea, concretize=True, constrain=False):
    val = self.state.cpu.read_int(ea, size=64)
    if concretize:
      val = self.concretize(val, constrain=constrain)
    return val, ea + 8

  def read_uint32_t(self, ea, concretize=True, constrain=False):
    val = self.state.cpu.read_int(ea, size=32)
    if concretize:
      val = self.concretize(val, constrain=constrain)
    return val, ea + 4

  def read_uint8_t(self, ea, concretize=True, constrain=False):
    val = self.state.cpu.read_int(ea, size=8)
    if concretize:
      val = self.concretize(val, constrain=constrain)
    if isinstance(val, str):
      assert len(val) == 1
      val = ord(val)
    return val, ea + 1

  def write_uint8_t(self, ea, val):
    self.state.cpu.write_int(ea, val, size=8)
    return ea + 1

  def write_uint32_t(self, ea, val):
    self.state.cpu.write_int(ea, val, size=32)
    return ea + 4

  def concretize(self, val, constrain=False):
    if isinstance(val, (int)):
      return val
    elif isinstance(val, str):
      assert len(val) == 1
      return ord(val[0])

    assert self.is_symbolic(val)
    concrete_val = self.state.solve_one(val)
    if isinstance(concrete_val, str):
      assert len(concrete_val) == 1
      concrete_val = ord(concrete_val[0])
    if constrain:
      self.add_constraint(val == concrete_val)
    return concrete_val

  def concretize_min(self, val, constrain=False):
    if isinstance(val, (int)):
      return val
    concrete_val = min(self.state.concretize(val, policy='MINMAX'))
    if constrain:
      self.add_constraint(val == concrete_val)
    return concrete_val

  def concretize_max(self, val, constrain=False):
    if isinstance(val, (int)):
      return val
    concrete_val = max(self.state.concretize(val, policy='MINMAX'))
    if constrain:
      self.add_constraint(val == concrete_val)
    return concrete_val

  def concretize_many(self, val, max_num):
    assert 0 < max_num
    if isinstance(val, (int)):
      return [val]
    return self.state.solve_n(val, max_num)

  def add_constraint(self, expr):
    if self.is_symbolic(expr):
      self.state.constrain(expr)
      return self.state.is_feasible()
    return True

  def pass_test(self):
    super(DeepManticore, self).pass_test()
    raise TerminateState(OUR_TERMINATION_REASON, testcase=False)

  def crash_test(self):
    super(DeepManticore, self).crash_test()
    raise TerminateState(OUR_TERMINATION_REASON, testcase=False)

  def fail_test(self):
    super(DeepManticore, self).fail_test()
    raise TerminateState(OUR_TERMINATION_REASON, testcase=False)

  def abandon_test(self):
    super(DeepManticore, self).abandon_test()
    raise TerminateState(OUR_TERMINATION_REASON, testcase=False)


def hook_IsSymbolicUInt(state, arg):
  """Implements DeepState_IsSymblicUInt, which returns 1 if its input argument
  has more then one solutions, and zero otherwise."""
  return DeepManticore(state).api_is_symbolic_uint(arg)


def hook_Assume(state, arg, expr_ea, file_ea, line):
  """Implements _DeepState_Assume, which tries to inject a constraint."""
  DeepManticore(state).api_assume(arg, expr_ea, file_ea, line)


def hook_StreamInt(state, level, format_ea, unpack_ea, uint64_ea):
  """Implements _DeepState_StreamInt, which gives us an integer to stream, and
  the format to use for streaming."""
  DeepManticore(state).api_stream_int(level, format_ea, unpack_ea, uint64_ea)


def hook_StreamFloat(state, level, format_ea, unpack_ea, double_ea):
  """Implements _DeepState_StreamFloat, which gives us an double to stream, and
  the format to use for streaming."""
  DeepManticore(state).api_stream_float(level, format_ea, unpack_ea, double_ea)


def hook_StreamString(state, level, format_ea, str_ea):
  """Implements _DeepState_StreamString, which gives us an double to stream, and
  the format to use for streaming."""
  DeepManticore(state).api_stream_string(level, format_ea, str_ea)


def hook_ClearStream(state, level):
  """Implements DeepState_ClearStream, which clears the contents of a stream
  for level `level`."""
  DeepManticore(state).api_clear_stream(level)


def hook_LogStream(state, level):
  """Implements DeepState_LogStream, which converts the contents of a stream for
  level `level` into a log for level `level`."""
  DeepManticore(state).api_log_stream(level)


def hook_Pass(state):
  """Implements DeepState_Pass, which notifies us of a passing test."""
  DeepManticore(state).api_pass()

def hook_Crash(state):
  """Implements DeepState_Crash, which notifies us of a crashing test."""
  DeepManticore(state).api_crash()

def hook_Fail(state):
  """Implements DeepState_Fail, which notifies us of a failing test."""
  DeepManticore(state).api_fail()


def hook_Abandon(state, reason):
  """Implements DeepState_Abandon, which notifies us that a problem happened
  in DeepState."""
  DeepManticore(state).api_abandon(reason)


def hook_SoftFail(state):
  """Implements DeepState_Fail, which notifies us of a passing test."""
  DeepManticore(state).api_soft_fail()


def hook_ConcretizeData(state, begin_ea, end_ea):
  """Implements the `Deeptate_ConcretizeData` API function, which lets the
  programmer concretize some data in the exclusive range
  `[begin_ea, end_ea)`."""
  return DeepManticore(state).api_concretize_data(begin_ea, end_ea)


def hook_ConcretizeCStr(state, begin_ea):
  """Implements the `Deeptate_ConcretizeCStr` API function, which lets the
    programmer concretize a NUL-terminated string starting at `begin_ea`."""
  return DeepManticore(state).api_concretize_cstr(begin_ea)


def hook_MinUInt(state, val):
  """Implements the `Deeptate_MinUInt` API function, which lets the
  programmer ask for the minimum satisfiable value of an unsigned integer."""
  return DeepManticore(state).api_min_uint(val)


def hook_MaxUInt(state, val):
  """Implements the `Deeptate_MaxUInt` API function, which lets the
  programmer ask for the minimum satisfiable value of a signed integer."""
  return DeepManticore(state).api_max_uint(val)


def hook_Log(state, level, ea):
  """Implements DeepState_Log, which lets Manticore intercept and handle the
  printing of log messages from the simulated tests."""
  DeepManticore(state).api_log(level, ea)


def hook_TakeOver(state):
  """Implements `DeepState_TakeOver`, returning 1 to indicate that it was
  hooked for symbolic execution."""
  return 1


def hook(func):
  return lambda state: state.invoke_model(func)


def _is_program_crash(reason):
  """Using the `reason` for the termination of a Manticore `will_terminate_state`
  event, decide if we want to treat the termination as a "crash" of the program
  being analyzed."""

  if not isinstance(reason, TerminateState):
    return False

  return 'Invalid memory access' in str(reason)


def _is_program_exit(reason):
  """Using the `reason` for the termination of a Manticore `will_terminate_state`
  event, decide if we want to treat the termination as a simple exit of the program
  being analyzed."""

  if not isinstance(reason, TerminateState):
    return False

  return 'Program finished with exit status' in str(reason)


def done_test(_, state, reason):
  """Called when a state is terminated."""
  mc = DeepManticore(state)

  # Note that `reason` is either an `Exception` or a `str`. If it is the special
  # `OUR_TERMINATION_REASON`, then the state was terminated via a hook into the
  # DeepState API, so we can just report it as is. Otherwise, we check to see if
  # it was due to behavior that would typically crash the program being analyzed.
  # If so, we save it as a crash. If not, we abandon it.

  if str(OUR_TERMINATION_REASON) != str(reason):
    if _is_program_crash(reason):
      L.info("State %s terminated due to crashing program behavior: %s", state._id, reason)

      # Don't raise new `TerminateState` exception
      super(DeepManticore, mc).crash_test()
    elif _is_program_exit(reason):
      L.info("State %s terminated due to program exit: %s", state._id, reason)
      super(DeepManticore, mc).pass_test()
      #super(DeepManticore, mc).abandon_test()
    else:
      L.error("State %s terminated due to internal error: %s", state._id, reason)

      # Don't raise new `TerminateState` exception
      super(DeepManticore, mc).ubandon_test()

  mc.report()


def find_symbol_ea(m, name):
  try:
    ea = m.resolve(name)
    if ea:
      return ea
  except:
    pass

  try:
    return m.resolve("_{}".format(name))
  except:
    pass

  return 0


def do_run_test(state, apis, test, workspace, hook_test=False):
  """Run an individual test case."""
  state.cpu.PC = test.ea

  mc = DeepManticore(state)
  mc.context['apis'] = apis

  # Tell the system that we're using symbolic execution.
  mc.write_uint32_t(apis["UsingSymExec"], 8589934591)

  mc.begin_test(test)

  del mc

  # NOTE(alan): cannot init State with new native.Manticore in 0.3.0 as it
  # will try to delete the non-existent stored state from new workspace
  m = manticore.native.Manticore(state, sys.argv[1:], workspace_url=workspace)
  log.set_verbosity(1)

  m.add_hook(apis['IsSymbolicUInt'], hook(hook_IsSymbolicUInt))
  m.add_hook(apis['ConcretizeData'], hook(hook_ConcretizeData))
  m.add_hook(apis['ConcretizeCStr'], hook(hook_ConcretizeCStr))
  m.add_hook(apis['MinUInt'], hook(hook_MinUInt))
  m.add_hook(apis['MaxUInt'], hook(hook_MaxUInt))
  m.add_hook(apis['Assume'], hook(hook_Assume))
  m.add_hook(apis['Pass'], hook(hook_Pass))
  m.add_hook(apis['Crash'], hook(hook_Crash))
  m.add_hook(apis['Fail'], hook(hook_Fail))
  m.add_hook(apis['SoftFail'], hook(hook_SoftFail))
  m.add_hook(apis['Abandon'], hook(hook_Abandon))
  m.add_hook(apis['Log'], hook(hook_Log))
  m.add_hook(apis['StreamInt'], hook(hook_StreamInt))
  m.add_hook(apis['StreamFloat'], hook(hook_StreamFloat))
  m.add_hook(apis['StreamString'], hook(hook_StreamString))
  m.add_hook(apis['ClearStream'], hook(hook_ClearStream))
  m.add_hook(apis['LogStream'], hook(hook_LogStream))

  if hook_test:
    m.add_hook(test.ea, hook(hook_TakeOver))

  m.subscribe('will_terminate_state', done_test)

  # attempts to kill after consts.timeout
  with m.kill_timeout(consts.timeout):
    m.run()

  # if Manticore is stuck, forcefully kill all workers
  m.kill()


def run_test(state, apis, test, workspace, hook_test=False):
  try:
    do_run_test(state, apis, test, workspace, hook_test)
  except:
    L.error("Uncaught exception: %s\n%s", sys.exc_info()[0], traceback.format_exc())


def run_tests(args, state, apis, workspace):
  mc = DeepManticore(state)
  mc.context['apis'] = apis
  tests = mc.find_test_cases()

  if not args.which_test:
    L.info("Running %d tests across %d workers", len(tests), args.num_workers)

    for test in tests:
      run_test(state, apis, test, workspace)

  else:
    test = [t for t in tests if t.name == args.which_test]
    if len(test) == 0:
      L.error("No test found with specified name.")
      exit(1)
    elif len(test) > 1:
      L.error("Multiple tests found with same name.")
      exit(1)

    L.info("Running `%d` test across %d workers", args.which_test, args.num_workers)
    run_test(state, apis, test[0], workspace)


def get_base(m):
  initial_state = _make_initial_state(m.binary_path)
  e_type = initial_state.platform.elf['e_type']
  if e_type == 'ET_EXEC':
    return 0x0
  elif e_type == 'ET_DYN':
    if initial_state.cpu.address_bit_size == 32:
      return 0x56555000
    else:
      return 0x555555554000
  else:
    L.critical("Invalid binary type `%s`", e_type)
    exit(1)

def main_takeover(m, args, takeover_symbol):
  takeover_ea = find_symbol_ea(m, takeover_symbol)
  if not takeover_ea:
    L.critical("Cannot find symbol `%s` in binary `%s`",
                  takeover_symbol, args.binary)
    return 1

  takeover_state = _make_initial_state(m.binary_path)

  mc = DeepManticore(takeover_state)

  ea_of_api_table = find_symbol_ea(m, 'DeepState_API')
  if not ea_of_api_table:
    L.critical("Could not find API table in binary `%s`", args.binary)
    return 1

  base = get_base(m)
  apis = mc.read_api_table(ea_of_api_table, base)

  del mc

  fake_test = TestInfo(takeover_ea, '_takeover_test', '_takeover_file', 0)

  hook_test = not args.klee
  takeover_hook = lambda state: run_test(state, apis, fake_test, m._workspace.uri, hook_test)
  m.add_hook(takeover_ea, takeover_hook)

  with m.kill_timeout(consts.timeout):
    m.run()

  m.kill()


def main_unit_test(m, args):
  setup_ea = find_symbol_ea(m, 'DeepState_Setup')
  if not setup_ea:
    L.critical("Cannot find symbol `DeepState_Setup` in binary `%s`", args.binary)
    return 1

  setup_state = _make_initial_state(m.binary_path)

  mc = DeepManticore(setup_state)

  ea_of_api_table = find_symbol_ea(m, 'DeepState_API')
  if not ea_of_api_table:
    L.critical("Could not find API table in binary `%s`", args.binary)
    return 1

  base = get_base(m)
  apis = mc.read_api_table(ea_of_api_table, base)
  del mc

  m.add_hook(setup_ea, lambda state: run_tests(args, state, apis, m._workspace.uri))

  with m.kill_timeout(consts.timeout):
    m.run()

  m.kill()


def main():
  args = DeepManticore.parse_args()

  consts.procs = args.num_workers
  consts.timeout = args.timeout
  consts.mprocessing = consts.mprocessing.single

  try:
    m = manticore.native.Manticore(args.binary)
  except Exception as e:
    L.critical("Cannot create Manticore instance on binary %s: %s", args.binary, e)
    return 1

  log.set_verbosity(args.verbosity)

  if args.take_over:
    return main_takeover(m, args, 'DeepState_TakeOver')
  elif args.klee:
    return main_takeover(m, args, 'main')
  else:
    return main_unit_test(m, args)


if "__main__" == __name__:
  exit(main())
