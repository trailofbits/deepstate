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

import os
import subprocess
import argparse
import functools

class DeepStateFrontend(object):
  """
  Defines a base front-end object for using DeepState to interact with fuzzers. Base object designed
  around `afl-fuzz` front-end as default.
  """

  def __init__(self, name, compiler=None, envvar="PATH"):
    """
    initializes base object with fuzzer executable and path, and checks to see if fuzzer
    executable exists in supplied environment variable (default is $PATH).

    optionally also sets path to compiler executable for compile-time instrumentation,
    for those fuzzers that support it.
    """
    if os.environ.get(envvar) is None:
      raise RuntimeError(f"${envvar} does not contain any known paths.")

    # collect paths from envvar, and check to see if fuzzer executable is present in paths
    potential_paths = [var for var in os.environ.get(envvar).split(":")]
    fuzzer_paths = [f"{path}/{name}" for path in potential_paths if os.path.isfile(path + '/' + name)]
    if len(fuzzer_paths) == 0:
      raise RuntimeError(f"${envvar} does not contain supplied fuzzer executable.")

    # if supplied, check if compiler exists in potential_paths
    if compiler is not None:
      compiler_paths = [f"{path}/{compiler}" for path in potential_paths if os.path.isfile(path + '/' + compiler)]
      if len(compiler_paths) == 0:

        # check to see if user supplied absolute path
        if os.path.is_file(compiler):
          self.compiler = compiler
        else:
          raise RuntimeError(f"{compiler} does not exist as absolute path or in ${envvar}")

      # use first compiler executable if multiple exists
      self.compiler = compiler_path[0]


    # in case name supplied as `bin/fuzzer`, strip executable name
    if '/' in name:
      self.name = name.split('/')[-1]
    else:
      self.name = name

    # use first fuzzer executable path if multiple exists
    self.fuzzer = fuzzer_paths[0]


  def compile(self, flags):
    """
    provides an interface for calling a compiler to instrument a test harness for
    mutation-based fuzzers
    """
    if self.compiler is None:
      raise RuntimeError(f"No compiler specified for compile-time instrumentation.")

    self.compile_cmd = [self.compiler, flags]
    try:
      r = subprocess.call(self.compile_cmd)
    except BaseException as e:
      raise RuntimeError(f"{self.compiler} interrupted due to exception:", e)


  def cli_command(self, cmd_dict, compiler=None, cli_other=None):
    """
    provides an interface for constructing proper command to be passed
    to fuzzer cli executable.
    """

    # turn arg mapping into viable cli args
    cmd_args = list(functools.reduce(lambda key, val: key + val, cmd_dict.items()))
    cmd_args = [arg for arg in cmd_args if arg is not None]

    # prepends compiler executable if specified
    if compiler is not None:
      self.cmd = [compiler, self.fuzzer]
    else:
      self.cmd = [self.fuzzer]

    # create command to execute by fuzzer, append any other optional arguments
    self.cmd += cmd_args
    if cli_other is not None:
      self.cmd += cli_other


  def execute_fuzzer(self):
    """
    takes constructed cli command and executes fuzzer with subprocess.call
    """
    try:
      r = subprocess.call(self.cmd)
      print(f"{self.name} finished with exit code", r)
    except BaseException as e:
      raise RuntimeError(f"{self.fuzzer} run interrupted due to exception:", e)


  def post_processing(self):
    """
    performs any post-fuzzing operations, like test extraction / parsing
    """
    raise NotImplementedError("Must be implemented by front-end executor.")


  _ARGS = None

  @classmethod
  def parse_args(cls):
    if cls._ARGS:
      return cls._ARGS

    parser = argparse.ArgumentParser(
      description="Use fuzzer as back-end for DeepState.")

    parser.add_argument("binary", type=str, help="Path to the test binary to run.")

    parser.add_argument("--output_test_dir", type=str, default="out", help="Directory where tests will be saved.")

    parser.add_argument("--timeout", type=int, default=3600, help="How long to fuzz.")

    parser.add_argument("--seeds", type=str, help="Directory with seed inputs.")

    parser.add_argument("--which_test", type=str, help="Which test to run (equivalent to --input_which_test).")

    parser.add_argument("--max_input_size", type=int, default=8192, help="Maximum input size.")

    parser.add_argument("--fuzzer_help", action='store_true', help="Show fuzzer command line options.")

    parser.add_argument("--args", default=[], nargs=argparse.REMAINDER, help="Other arguments to pass to fuzzer cli.")

    cls._ARGS = parser.parse_args()
    return cls._ARGS
