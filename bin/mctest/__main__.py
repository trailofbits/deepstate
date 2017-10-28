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
import logging
import sys

L = logging.getLogger("mctest")
L.setLevel(logging.INFO)

def hook_function(project, name, cls):
  """Hook the function `name` with the SimProcedure `cls`."""
  project.hook(project.kb.labels.lookup(name),
               cls(project=project))


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
  """Read a uint64_t value from memory."""
  return state.solver.eval(state.mem[ea].uintptr_t.resolved, cast_to=int)


def read_uint32_t(state, ea):
  """Read a uint64_t value from memory."""
  return state.solver.eval(state.mem[ea].uint32_t.resolved, cast_to=int)


def find_test_cases(project, state):
  """Find the test case descriptors."""
  obj = project.loader.main_object
  tests = []
  addr_size_bytes = state.arch.bits // 8
  for sec in obj.sections:
    if sec.name != ".mctest_funcs":
      continue

    for ea in xrange(sec.vaddr, sec.vaddr + sec.memsize, 32):
      test_func_ea = read_uintptr_t(state, ea + 0 * addr_size_bytes)
      test_name_ea = read_uintptr_t(state, ea + 1 * addr_size_bytes)
      file_name_ea = read_uintptr_t(state, ea + 2 * addr_size_bytes)
      file_line_num = read_uint32_t(state, ea + 3 * addr_size_bytes)

      if not test_func_ea or \
         not test_name_ea or \
         not file_name_ea or \
         not file_line_num:  # `__LINE__` in C always starts at `1` ;-)
        continue

      test_name = read_c_string(state, test_name_ea)
      file_name = read_c_string(state, file_name_ea)
      L.info("Test case {} at {:x} is at {}:{}".format(
          test_name, test_func_ea, file_name, file_line_num))
      tests.append((test_func_ea, test_name, file_name, file_line_num))

  return tests


def make_symbolic_input(project, state):
  """Fill in the input data array with symbolic data."""
  obj = project.loader.main_object
  for sec in obj.sections:
    if sec.name == ".mctest_data":
      data = state.se.Unconstrained('MCTEST_INPUT', sec.memsize * 8)
      state.memory.store(sec.vaddr, data)
      return data


def hook_predicate_int_func(project, state, name, num_bits):
  """Hook a McTest function that checks whether or not its integer argument
  is symbolic."""
  class Hook(angr.SimProcedure):
    def run(self, arg):
      return int(self.state.se.symbolic(arg))
  hook_function(project, "McTest_IsSymbolic{}".format(name), Hook)


class Assume(angr.SimProcedure):
  """Implements _McTest_CanAssume, which tries to inject a constraint."""
  def run(self, arg):
    constraint = arg != 0
    self.state.solver.add(constraint)
    if not self.state.solver.satisfiable():
      L.error("Failed to assert assumption {}".format(constraint))
      self.exit(2)


class Pass(angr.SimProcedure):
  """Implements McTest_Pass, which notifies us of a passing test."""
  def run(self):
    L.info("Passed test case")
    self.exit(0)


class Fail(angr.SimProcedure):
  """Implements McTest_Fail, which notifies us of a passing test."""
  def run(self):
    L.error("Failed test case")
    self.exit(1)


def main():
  """Run McTest."""
  if 2 > len(sys.argv):
    return 1

  project = angr.Project(
      sys.argv[1],
      use_sim_procedures=True,
      translation_cache=True,
      support_selfmodifying_code=False,
      auto_load_libs=False)

  entry_state = project.factory.entry_state()
  addr_size_bits = entry_state.arch.bits
  
  # Find the test cases that we want to run.
  tests = find_test_cases(project, entry_state)

  # Concretely execute up until `main`.
  concrete_manager = angr.SimulationManager(
        project=project,
        active_states=[entry_state])
  ea_of_main = project.kb.labels.lookup('main')
  concrete_manager.explore(find=ea_of_main)
  main_state = concrete_manager.found[0]
  
  # Introduce symbolic input that the tested code will use.
  symbolic_input = make_symbolic_input(project, main_state)

  # Hook predicate functions that should return 1 or 0 depending on whether
  # or not their argument is symbolic.
  hook_predicate_int_func(project, main_state, 'UInt', 32)

  hook_function(project, '_McTest_Assume', Assume)
  hook_function(project, 'McTest_Pass', Pass)
  hook_function(project, 'McTest_Fail', Fail)

  # For each test, create a simulation manager whose initial state calls into
  # the test case function, and returns to `McTest_DoneTestCase`.
  test_managers = []
  for entry_ea, test_name, file_name, line_num in tests:
    test_state = project.factory.call_state(
        entry_ea,
        base_state=main_state)

    # NOTE(pag): Enabling Veritesting seems to miss some cases where the
    #            tests fail.
    test_manager = angr.SimulationManager(
        project=project,
        active_states=[test_state])

    L.info("Running test case {}".format(test_name))
    test_manager.run()

    for state in test_manager.deadended:
      last_event = state.history.events[-1]
      if 'terminate' == last_event.type:
        code = last_event.objects['exit_code']._model_concrete.value
    
  return 0

if "__main__" == __name__:
  exit(main())
