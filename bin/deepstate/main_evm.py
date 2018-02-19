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

import logging
logging.basicConfig()

import collections
import sys
try:
  import manticore.ethereum
except Exception as e:
  if "Z3NotFoundError" in repr(type(e)):  
    print "Manticore requires Z3 to be installed."
    sys.exit(255)
  else:
    raise
import multiprocessing
import traceback
from .common import DeepState

from manticore.core.state import TerminateState
from manticore.utils.helpers import issymbolic


L = logging.getLogger("deepstate.evm")
L.setLevel(logging.INFO)

OUR_TERMINATION_REASON = "I DeepState'd it"

class DeepManticore(DeepState):
  def __init__(self, state):
    super(DeepManticore, self).__init__()
    self.state = state

  def __del__(self):
    self.state = None

  def get_context(self):
    return self.state.context

  def is_symbolic(self, val):
    return manticore.utils.helpers.issymbolic(val)

  def create_symbol(self, name, size_in_bits):
    return self.state.new_symbolic_value(size_in_bits, name)

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

  def concretize(self, val, constrain=False):
    if isinstance(val, (int, long)):
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
    if isinstance(val, (int, long)):
      return val
    concrete_val = min(self.state.concretize(val, policy='MINMAX'))
    if constrain:
      self.add_constraint(val == concrete_val)
    return concrete_val

  def concretize_max(self, val, constrain=False):
    if isinstance(val, (int, long)):
      return val
    concrete_val = max(self.state.concretize(val, policy='MINMAX'))
    if constrain:
      self.add_constraint(val == concrete_val)
    return concrete_val

  def concretize_many(self, val, max_num):
    assert 0 < max_num
    if isinstance(val, (int, long)):
      return [val]
    return self.state.solver.eval_upto(val, max_num)

  def add_constraint(self, expr):
    if self.is_symbolic(expr):
      self.state.constrain(expr)
      # TODO(pag): How to check satisfiability?
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


def hook_MinUInt(self, val):
  """Implements the `Deeptate_MinUInt` API function, which lets the
  programmer ask for the minimum satisfiable value of an unsigned integer."""
  return DeepManticore(procedure=self).api_min_uint(val)


def hook_MaxUInt(self, val):
  """Implements the `Deeptate_MaxUInt` API function, which lets the
  programmer ask for the minimum satisfiable value of a signed integer."""
  return DeepManticore(procedure=self).api_max_uint(val)


def hook_Log(state, level, ea):
  """Implements DeepState_Log, which lets Manticore intercept and handle the
  printing of log messages from the simulated tests."""
  DeepManticore(state).api_log(level, ea)


def hook(func):
  return lambda state: state.invoke_model(func)


def _is_program_crash(reason):
  """Using the `reason` for the termination of a Manticore `will_terminate_state`
  event, decide if we want to treat the termination as a "crash" of the program
  being analyzed."""

  if not isinstance(reason, TerminateState):
    return False

  return 'Invalid memory access' in reason.message


def done_test(x, state, state_id, reason):
  """Called when a state is terminated."""
  print x
  print state
  print state_id
  print reason

  """
  mc = DeepManticore(state)

  # Note that `reason` is either an `Exception` or a `str`. If it is the special
  # `OUR_TERMINATION_REASON`, then the state was terminated via a hook into the
  # DeepState API, so we can just report it as is. Otherwise, we check to see if
  # it was due to behavior that would typically crash the program being analyzed.
  # If so, we save it as a crash. If not, we abandon it.
  if OUR_TERMINATION_REASON not in reason:
    if _is_program_crash(reason):
      L.info("State {} terminated due to crashing program behavior: {}".format(
        state_id, reason))

      # Don't raise new `TerminateState` exception
      super(DeepManticore, mc).crash_test()
    else:
      L.error("State {} terminated due to internal error: {}".format(state_id,
                                                                     reason))

      # Don't raise new `TerminateState` exception
      super(DeepManticore, mc).abandon_test()

  mc.report()
  """

def find_symbol_ea(m, name):
  try:
    ea = m._get_symbol_address(name)
    if ea:
      return ea
  except:
    pass

  try:
    return m._get_symbol_address("_{}".format(name))
  except:
    pass

  return 0


def do_run_test(contract, (test_name, test_args)):
  """Run an individual test case."""
  print contract, test_name, test_args
  m = manticore.ethereum.ManticoreEVM()
  m.subscribe('will_terminate_state', done_test)
 
  source_code = open(contract,"r").read()
  owner_account = m.create_account(balance=1000)
  contract_account = m.solidity_create_contract(source_code, owner=owner_account, contract_name="TEST")
  func = contract_account.__getattribute__(test_name)
  args = [None]*len(test_args)
  func(*args)

def run_test(contract, test):
  try:
    do_run_test(contract, test)
  except:
    L.error("Uncaught exception: {}\n{}".format(
        sys.exc_info()[0], traceback.format_exc()))

def find_test_cases(contract):
  m = manticore.ethereum.ManticoreEVM()
  source_code = open(contract,"r").read()
  owner_account = m.create_account(balance=1000)
  #print "[+] Creating a contract account"
  contract_account = m.solidity_create_contract(source_code, owner=owner_account, contract_name="TEST")
  signatures = m.get_metadata(contract_account.address).signatures
  test_cases = []
  for (h, n) in signatures.items():
    if "Test_" in n:
      test_name = n.split("(")[0]
      test_args = n.split("(")[1].split(")")[0].split(",")
      test_cases.append((test_name,test_args))

  return test_cases

def run_tests(contract, num_workers):
  """Run all of the test cases."""
  pool = multiprocessing.Pool(processes=max(1, num_workers))
  results = []
  #mc = DeepManticore(state)
  tests = find_test_cases(contract)

  L.info("Running {} tests across {} workers".format(
      len(tests), num_workers))

  for test in tests:
    res = pool.apply_async(run_test, (contract, test))
    results.append(res)

  pool.close()
  pool.join()

  exit(0)


def main():
  args = DeepManticore.parse_args()

  try:
    m = manticore.ethereum.ManticoreEVM()
    source_code = open(args.binary,"r").read()
    owner_account = m.create_account(balance=1000)
    contract_account = m.solidity_create_contract(source_code, owner=owner_account, contract_name="TEST")

  except Exception as e:
    L.critical("Cannot create Manticore instance on contract {}: {}".format(
        args.binary, e))
    return 1

  m.verbosity(1)
  run_tests(args.binary, args.num_workers)


if "__main__" == __name__:
  exit(main())
