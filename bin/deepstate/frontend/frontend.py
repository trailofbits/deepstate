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
logging.basicConfig()

import os
import sys
import time
import subprocess
import argparse
import functools

L = logging.getLogger("deepstate.frontend")
L.setLevel(logging.INFO)

class FrontendError(Exception):
  pass


class DeepStateFrontend(object):
  """
  Defines a base front-end object for using DeepState to interact with fuzzers.
  """

  def __init__(self, envvar="PATH"):
    """
    Initializes base object with fuzzer executable and path, and checks to see if fuzzer
    executable exists in supplied environment variable (default is $PATH). Optionally also
    sets path to compiler executable for compile-time instrumentation, for those fuzzers that support it.

    User must define FUZZER and COMPILER members in inherited fuzzer class.

    :param envvar: name of envvar to discover executables. Default is $PATH.
    """

    if not hasattr(self, "FUZZER"):
      raise FrontendError("DeepStateFrontend.FUZZER not set")

    fuzzer_name = self.FUZZER

    if hasattr(self, "COMPILER"):
      compiler = self.COMPILER
    else:
      compiler = None

    if os.environ.get(envvar) is None:
      raise FrontendError(f"${envvar} does not contain any known paths.")

    # collect paths from envvar, and check to see if fuzzer executable is present in paths
    potential_paths = [var for var in os.environ.get(envvar).split(":")]
    fuzzer_paths = [f"{path}/{fuzzer_name}" for path in potential_paths if os.path.isfile(path + '/' + fuzzer_name)]
    if len(fuzzer_paths) == 0:
      raise FrontendError(f"${envvar} does not contain supplied fuzzer executable.")

    L.debug(fuzzer_paths)

    # if supplied, check if compiler exists in potential_paths
    if compiler is not None:
      compiler_paths = [f"{path}/{compiler}" for path in potential_paths if os.path.isfile(path + '/' + compiler)]
      if len(compiler_paths) == 0:

        # check to see if user supplied absolute path or compiler resides in PATH
        if os.path.isfile(compiler):
          self.compiler = compiler
        else:
          raise FrontendError(f"{compiler} does not exist as absolute path or in ${envvar}")

      # use first compiler executable if multiple exists
      self.compiler = compiler_paths[0]

      L.info(f"Initialized compiler: {self.compiler}")


    # in case name supplied as `bin/fuzzer`, strip executable name
    if '/' in fuzzer_name:
      self.name = fuzzer_name.split('/')[-1]
    else:
      self.name = fuzzer_name

    # use first fuzzer executable path if multiple exists
    self.fuzzer = fuzzer_paths[0]

    L.info(f"Initialized fuzzer path: {self.fuzzer}")

    self.start_time = int(time.time())
    self._on = False


  def print_help(self):
    """
    Calls fuzzer to print executable help menu.
    """
    subprocess.call([self.fuzzer, "--help"])


  def compile(self, compiler_args, env=os.environ.copy()):
    """
    Provides a simple interface that allows the user to compile a test harness
    with instrumentation using the specified compiler. Users should implement an
    inherited method that constructs the arguments necessary, and then pass it to the
    base object.

    :param compiler_args: list of arguments for compiler (excluding compiler executable)
    :param env: optional envvars to set during compilation

    """
    if self.compiler is None:
      raise FrontendError(f"No compiler specified for compile-time instrumentation.")

    L.info(f"Compiling test harness `{self._ARGS.compile_test}` with {self.compiler}")

    env["CC"] = self.compiler
    env["CXX"] = self.compiler

    L.debug(f"CC={env['CC']} and CXX={env['CXX']}")

    if custom_cmd is not None:
      compile_cmd = custom_cmd
    else:
      compile_cmd = [self.compiler] + compiler_args

    L.debug(f"Compilation command: {str(compile_cmd)}")

    try:
      ps = subprocess.Popen(compile_cmd, env=env)
      ps.communicate()
    except BaseException as e:
      raise FrontendError(f"{self.compiler} interrupted due to exception:", e)


  def pre_exec(self):
    """
    Called before fuzzer execution in order to perform sanity checks. Base method contains
    default argument checks. Users should implement inherited method for any other environment
    checks or initializations before execution.
    """

    args = self._ARGS
    if args is None:
      raise FrontendError("No arguments parsed yet. Call parse_args before pre_exec.")

    if args.fuzzer_help:
      self.print_help()
      sys.exit(0)

    if args.binary is None:
      self.print_help()
      sys.exit(1)

    L.debug(f"Target binary: {args.binary}")

    if not args.output_test_dir:
      raise FrontendError("No output test directory path specified.")

    L.debug(f"Output directory: {args.output_test_dir}")



  @staticmethod
  def _dict_to_cmd(cmd_dict):
    """
    provides an interface for constructing proper command to be passed
    to cli executable.

    :param cmd_dict: dict with keys as cli flags and values as arguments
    """

    cmd_args = list(functools.reduce(lambda key, val: key + val, cmd_dict.items()))
    cmd_args = [arg for arg in cmd_args if arg is not None]

    L.debug(f"Fuzzer arguments: `{str(cmd_args)}`")

    return cmd_args


  def run(self, compiler=None):
    """
    Spawns the fuzzer by taking the self.cmd property and initializing a command in a list
    format for subprocess.

    :param compiler: if necessary, a compiler that is invoked before fuzzer executable (ie `dotnet`)
    """

    # call pre_exec for any checks/inits before execution
    L.info("Calling pre_exec before fuzzing")
    self.pre_exec()

    # initialize cmd from property or throw exception
    if hasattr(self, "cmd") or isinstance(getattr(type(self), "cmd", None), property):
      command = [self.fuzzer] + DeepStateFrontend._dict_to_cmd(self.cmd)
    else:
      raise FrontendError("No DeepStateFrontend.cmd attribute defined.")

    # prepend compiler that invokes fuzzer
    if compiler:
      command.insert(0, compiler)

    L.info(f"Executing command `{str(command)}`")

    # TODO(alan): other stuff before calling cmd
    L.info(f"Fuzzer start time: {self.start_time}")
    self._on = True
    try:
      ps = subprocess.Popen(command)
      ps.communicate()
    except BaseException as e:
      raise FrontendError(f"{self.fuzzer} run interrupted due to exception {e}.")

    self._off = True
    L.info(f"Fuzzer end time: {self.start_time}")

    # do post-fuzz operations
    if hasattr(self, 'post_exec') and callable(getattr(self, 'post_exec')):
      L.info("Calling post-exec for fuzzer post-processing")
      self.post_exec()


  # TODO
  def sync_seeds(self, path):
    pass


  _ARGS = None

  @classmethod
  def parse_args(cls):
    if cls._ARGS:
      return cls._ARGS

    # use existing argparser if defined in fuzzer object,
    # or initialize new one, both with default arguments
    if hasattr(cls, "parser"):
      L.debug("Using previously initialized parser")
      parser = cls.parser
    else:
      parser = argparse.ArgumentParser(
        description="Use fuzzer as back-end for DeepState.")

    # Target binary (not required, as we enforce manual checks in pre_exec)
    parser.add_argument("binary", nargs='?', type=str, help="Path to the test binary to run.")

    # Input/output workdirs
    parser.add_argument("-i", "--input_seeds", type=str, help="Directory with seed inputs.")
    parser.add_argument("-o", "--output_test_dir", type=str, default="out", help="Directory where tests will be saved.")

    # Fuzzer execution options
    parser.add_argument("-t", "--timeout", type=int, default=3600, help="How long to fuzz.")
    parser.add_argument("-j", "--jobs", type=int, default=1, help="How many worker processes to spawn.")
    parser.add_argument("-s", "--max_input_size", type=int, default=8192, help="Maximum input size.")

    # Miscellaneous options
    parser.add_argument("--fuzzer_help", action='store_true', help="Show fuzzer command line options.")
    parser.add_argument("--which_test", type=str, help="Which test to run (equivalent to --input_which_test).")
    parser.add_argument("--args", default=[], nargs=argparse.REMAINDER, help="Overrides DeepState arguments to pass to test(s).")

    cls._ARGS = parser.parse_args()
    cls.parser = parser

    return cls._ARGS
