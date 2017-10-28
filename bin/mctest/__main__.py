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


L = logging.getLogger("mctest")
L.setLevel(logging.INFO)


class EntryPointPlugin(manticore.core.plugin.Plugin):
  """Interpose on system calls. When we come across McTest's special system
  call that is invoked at the beginnning of McTest_Run, then we stop execution
  there and take over."""
  def on_syscall_callback(self, state, index):
    if 0x41414141 == index:
      print 'here!!!!!'
      state_id = self._executor._workspace.save_state(state)
      self._executor.put(state_id)
      raise manticore.TerminateState("Canceled", testcase=False)


class McTest(manticore.Manticore):
  def __init__(self, argv):
    assert isinstance(argv, (list, tuple))
    super(McTest, self).__init__(argv[0], argv=argv)
    self._unregister_default_plugins()
    self.register_plugin(EntryPointPlugin())

  def _unregister_default_plugins(self):
    """Unregister the default plugins."""
    for plugin in tuple(self.plugins):
      self.unregister_plugin(plugin)


def main():
  print 'here'
  McTest.verbosity(1)
  m = McTest(sys.argv[1:])
  print 'running...'
  m.run()

if "__main__" == __name__:
  exit(main())
