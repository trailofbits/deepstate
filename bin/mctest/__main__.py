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
import sys

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


def read_uint64_t(state, ea):
  """Read a uint64_t value from memory."""
  return state.solver.eval(state.mem[ea].uint64_t.resolved,
                           cast_to=int)


def find_test_cases(project, state):
  """Find the test case descriptors."""
  obj = project.loader.main_object
  tests = []
  for sec in obj.sections:
    if sec.name != ".mctest_entrypoints":
      continue
    for ea in xrange(sec.vaddr, sec.vaddr + sec.memsize, 32):
      test_func_ea = read_uint64_t(state, ea + 0)
      test_name_ea = read_uint64_t(state, ea + 8)
      file_name_ea = read_uint64_t(state, ea + 16)
      file_line_num = read_uint64_t(state, ea + 24)

      test_name = read_c_string(state, test_name_ea)
      file_name = read_c_string(state, file_name_ea)

      tests.append((test_func_ea, test_name, file_name, file_line_num))
  return tests


def hook_symbolic_int_func(project, state, name, num_bits):
  """Hook a McTest function and make it return a symbolic integer."""
  class Function(angr.SimProcedure):
    def run(self):
      return self.state.solver.BVS("", num_bits)
  
  func_name = "McTest_{}".format(name)
  ea = project.kb.labels.lookup(func_name)
  project.hook(ea, Function(project=project))


def hook_predicate_int_func(project, state, name, num_bits):
  """Hook a McTest function that checks whether or not its integer argument
  is symbolic."""
  class Function(angr.SimProcedure):
    def run(self, arg):
      return int(self.state.se.symbolic(arg))

  func_name = "McTest_IsSymbolic{}".format(name)
  ea = project.kb.labels.lookup(func_name)
  project.hook(ea, Function(project=project))


class Assume(angr.SimProcedure):
  """Implements McTest_Assume, which injects a constraint."""
  def run(self, arg):
    if self.state.se.symbolic(arg):
      constraint = arg != 0
      eval_res = self.state.se.eval(constraint)
      if eval_res:
        self.state.add_constraints(constraint)
      ret = eval_res
    else:
      ret = self.state.se.eval(arg) != 0
    return int(ret)


def main():
  """Run McTest."""
  if 2 > len(sys.argv):
    return 1

  project = angr.Project(
      sys.argv[1],
      use_sim_procedures=True,
      translation_cache=True,
      support_selfmodifying_code=False)

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
  
  #concrete_manager.move(from_stash='found', to_stash='deadended')

  # Hook functions that should now return symbolic values.
  hook_symbolic_int_func(project, main_state, 'Bool', 1)
  hook_symbolic_int_func(project, main_state, 'Size', addr_size_bits)
  hook_symbolic_int_func(project, main_state, 'UInt64', 64)
  hook_symbolic_int_func(project, main_state, 'UInt', 32)

  # Hook predicate functions that should return 1 or 0 depending on whether
  # or not their argument is symbolic.
  hook_predicate_int_func(project, main_state, 'UInt', 32)

  # Hook the assume function.
  project.hook(project.kb.labels.lookup('McTest_Assume'),
               Assume(project=project))

  ea_of_done = project.kb.labels.lookup('McTest_DoneTestCase')

  # For each test, create a simulation manager whose initial state calls into
  # the test case function, and returns to `McTest_DoneTestCase`.
  test_managers = []
  for entry_ea, test_name, file_name, line_num in tests:
    test_state = project.factory.call_state(
        entry_ea,
        base_state=main_state,
        ret_addr=ea_of_done)

    # NOTE(pag): Enabling Veritesting seems to miss some cases where the
    #            tests fail.
    test_manager = angr.SimulationManager(
        project=project,
        active_states=[test_state])

    test_manager.run()

    for state in test_manager.deadended:
      last_event = state.history.events[-1]
      if 'terminate' == last_event.type:
        code = last_event.objects['exit_code']._model_concrete.value
        print "{} in {}:{} terminated with {}".format(test_name, file_name, line_num, code)
    
  return 0

if "__main__" == __name__:
  exit(main())
