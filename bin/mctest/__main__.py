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
import manticore
import sys

from manticore.utils.helpers import issymbolic

L = logging.getLogger("mctest")
L.setLevel(logging.INFO)


class EntryPointPlugin(manticore.core.plugin.Plugin):
  """Interpose on system calls. When we come across McTest's special system
  call that is invoked at the beginnning of McTest_Run, then we stop execution
  there and take over."""
  def on_syscall_callback(self, state, index):
    if 0x41414141 == index:
      print 'here!!!!!'
      state_id = self.manticore._executor._workspace.save_state(state)
      self.manticore._executor.put(state_id)
      raise manticore.TerminateState("Canceled", testcase=False)

def read_uintptr_t(state, ea):
  """Read a uint64_t value from memory."""
  next_ea = ea + (state.cpu.address_bit_size // 8)
  val = state.cpu.read_int(ea)
  if issymbolic(val):
    val = state.solve_one(val)
  return val, next_ea

def read_c_string(state, ea):
  return state.cpu.read_string(ea)

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

def IsSymbolicUInt(state, arg):
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


def Assume(state, arg):
  """Implements _McTest_CanAssume, which tries to inject a constraint."""
  constraint = arg != 0
  state.constrain(constraint)
  if len(state.concretize(constraint, 'ONE')) == 0:
    L.error("Failed to assert assumption {}".format(constraint))
    self.exit(2)


def Pass(self):
  """Implements McTest_Pass, which notifies us of a passing test."""
  L.info("Passed test case")
  self.exit(0)

def Fail(self):
  """Implements McTest_Fail, which notifies us of a passing test."""
  L.error("Failed test case")
  self.exit(1)



def main():
  m = manticore.Manticore(sys.argv[1], sys.argv[1:])
  m.verbosity(1)

  # Hack to get around current broken _get_symbol_address 
  m._binary_type = 'not elf'
  m._binary_obj = m._initial_state.platform.elf

  mctest = m._get_symbol_address('McTest_Run')
  run_state = m._initial_state

  ea_of_api_table = m._get_symbol_address('McTest_API')
  apis = read_api_table(run_state, ea_of_api_table)

  # Introduce symbolic input that the tested code will use.
  symbolic_input = make_symbolic_input(run_state,
      apis['InputBegin'], apis['InputEnd'])

  m.add_hook(apis['IsSymbolicUInt'], lambda state: state.invoke_model(IsSymbolicUInt))
  m.add_hook(apis['Assume'], lambda state: state.invoke_model(Assume))
  m.add_hook(apis['Pass'], lambda state: state.invoke_model(Pass))
  m.add_hook(apis['Fail'], lambda state: state.invoke_model(Fail))

  print "Finished establishing hooks"

  # To Do: create test states

if "__main__" == __name__:
  exit(main())
