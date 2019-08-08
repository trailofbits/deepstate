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
import time
import sys
import subprocess
import threading
import argparse
import functools


L = logging.getLogger("deepstate.frontend")
L.setLevel(os.environ.get("DEEPSTATE_LOG", "INFO").upper())


class AttrDict(dict):
  """
  Since the argparser dictates most of the attributes the frontend
  uses to orchestrate a fuzzer, we can create a custom AttrDict that
  enables us to access keys as attributes.
  """

  def __init__(self, *args, **kwargs):
    super(AttrDict, self).__init__(*args, **kwargs)
    self.__dict__ = self


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

        # if not in envvar, check to see if user supplied absolute path
        if os.path.isfile(compiler):
          self.compiler = compiler

        # .. or check if in $PATH before tossing exception
        else:
          for path in os.environ["PATH"].split(os.pathsep):
            compiler_path = os.path.join(path, compiler)

            L.debug(f"Checking if `{compiler_path}` is a valid compiler path")
            if os.path.isfile(compiler_path) and os.access(compiler_path, os.X_OK):
              self.compiler = compiler_path
              break

      # use first compiler executable if multiple exists
      else:
        self.compiler = compiler_paths[0]


    # toss exception if compiler could not be found
    if not hasattr(self, "compiler"):
      raise FrontendError(f"{compiler} does not exist as absolute path, or in ${envvar} or $PATH")

    L.debug(f"Initialized compiler: {self.compiler}")

    # in case name supplied as `bin/fuzzer`, strip executable name
    if '/' in fuzzer_name:
      self.name = fuzzer_name.split('/')[-1]
    else:
      self.name = fuzzer_name

    # use first fuzzer executable path if multiple exists
    self.fuzzer = fuzzer_paths[0]

    L.debug(f"Initialized fuzzer path: {self.fuzzer}")

    self._start_time = int(time.time())
    self._on = False


  def __repr__(self):
    return "{}".format(self.__class__.__name__)


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

    # initialize compiler envvars
    env["CC"] = self.compiler
    env["CXX"] = self.compiler
    L.debug(f"CC={env['CC']} and CXX={env['CXX']}")

    # initialize command with prepended compiler
    compile_cmd = [self.compiler] + compiler_args
    L.debug(f"Compilation command: {str(compile_cmd)}")

    L.info(f"Compiling test harness `{self._ARGS.compile_test}` with {self.compiler}")
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

    # if compile_test is an existing argument, call compile for user
    if hasattr(args, "compile_test"):
      if args.compile_test:
        self.compile()
        sys.exit(0)

    # manually check if binary positional argument was passed
    if args.binary is None:
      self.parser.print_help()
      print("\nError: Target binary not specified.")
      sys.exit(1)

    L.debug(f"Target binary: {args.binary}")

    # no sanity check, since some fuzzers require optional input seeds
    if args.input_seeds:
      L.debug(f"Input seeds directory: {args.input_seeds}")

    L.debug(f"Output directory: {args.output_test_dir}")

    # check if we in ensemble mode, and initialize directory
    if args.enable_sync:
      if not os.path.isdir(args.sync_dir):
        L.info("Initializing sync directory for ensembling")
        os.mkdir(args.sync_dir)
      L.debug(f"Sync directory: {args.sync_dir}")


  @staticmethod
  def _dict_to_cmd(cmd_dict):
    """
    Helper that provides an interface for constructing proper command to be passed
    to fuzzer executable. This takes a dict that maps a str argument flag to a value,
    and transforms it into list.

    :param cmd_dict: dict with keys as cli flags and values as arguments
    """

    cmd_args = list(functools.reduce(lambda key, val: key + val, cmd_dict.items()))
    cmd_args = [arg for arg in cmd_args if arg is not None]

    L.debug(f"Fuzzer arguments: `{str(cmd_args)}`")
    return cmd_args


  def reporter(self):
    """
    Provides an interface for fuzzers to output important statistics during an ensemble
    cycle. This ensure that fuzzer outputs don't clobber STDOUT, and that users can gain
    insight during ensemble run.
    """
    return NotImplementedError("Must implement in frontend subclass.")


  def run(self, compiler=None, no_exec=False):
    """
    Spawns the fuzzer by taking the self.cmd property and initializing a command in a list
    format for subprocess.

    :param compiler: if necessary, a compiler that is invoked before fuzzer executable (ie `dotnet`)
    :param no_exec: skips pre- and post-processing steps during execution
    """
    args = self._ARGS

    # call pre_exec for any checks/inits before execution.
    if not no_exec:
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

    # exec fuzzer
    L.info(f"Fuzzer start time: {self._start_time}")
    self._on = True


    # if we are syncing seeds, we background the AFL process but still process output
    # to the foreground
    if args.enable_sync:
      self.proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
      L.info(f"Starting fuzzer with seed synchronization with PID `{self.proc.pid}`")
    else:
      self.proc = subprocess.Popen(command)
      L.info(f"Starting fuzzer normally with PID `{self.proc.pid}`")


    try:

      if args.enable_sync:

        # do not ensemble as fuzzer initializes
        time.sleep(5)
        self.sync_count = 0

        while self._is_alive():
          L.debug(f"{self.name} - Performing sync cycle {self.sync_count}")
          time.sleep(args.sync_cycle)
          self.ensemble()
          self.reporter()
          self.sync_count += 1

      # if not syncing, start regular foreground child process
      else:
        self.proc.communicate()


    except OSError as e:
      raise FrontendError(f"{self.fuzzer} run interrupted due to exception {e}.")

    except KeyboardInterrupt:
      self._kill()

    finally:
      self._kill()

    if not args.enable_sync:
      self.exec_time = round(time.time() - self._start_time, 2)

    # five second delay due to ensemble wait, subtract from time
    else:
      self.exec_time = round(time.time() - self._start_time, 2) - 5

    L.info(f"Fuzzer exec time: {self.exec_time}s")

    # do post-fuzz operations
    if not no_exec:
      if hasattr(self, "post_exec") and callable(getattr(self, "post_exec")):
        L.info("Calling post-exec for fuzzer post-processing")
        self.post_exec()


  def _is_alive(self):
    """
    Checks to see if fuzzer PID is running, but tossing SIGT (0) to see if we can
    interact. Ideally used in an event loop during a running process.
    """

    if self._on:
      return True

    try:
      os.kill(self.proc.pid, 0)
    except (OSError, ProcessLookupError):
      return False

    return True


  def _kill(self):
    """
    Kills running fuzzer process. Can be used forcefully if
    KeyboardInterrupt signal falls through and process continues execution.
    """
    if not hasattr(self, "proc"):
      raise FrontendError("Attempted to kill non-running PID.")

    self.proc.terminate()
    try:
      self.proc.wait(timeout=0.5)
      L.info(f"Fuzzer subprocess exited with `{self.proc.returncode}`")
    except subprocess.TimeoutExpired:
      raise FrontendError("Subprocess could not terminate in time")

    self._on = False


  @property
  def stats(self):
    """
    Parses out stats generated by fuzzer output. Should be implemented by user, and can return custom
    feedback.
    """
    raise NotImplementedError("Must implement in frontend subclass.")


  def _sync_seeds(self, mode, src, dest, excludes=[]):
    """
    Helper that invokes rsync for convenient file syncing between two files.

    TODO(alan): implement functionality for syncing across servers.
    TODO(alan): consider implementing "native" syncing alongside current "rsync mode".

    :param mode: str representing mode (either 'GET' or 'PUSH')
    :param src: path to source queue
    :param dest: path to destination queue
    :param excludes: list of string patterns for paths to ignore when rsync-ing
    """

    if not mode in ["GET", "PUSH"]:
      raise FrontendError(f"Unknown mode for seed syncing: `{mode}`")

    rsync_cmd = ["rsync", "-racz", "--ignore-existing"]

    # subclass should invoke with list of pattern ignores
    if len(excludes) > 0:
      rsync_cmd += [f"--exclude={e}" for e in excludes]

    # TODO: determine other necessary arguments

    if mode == "GET":
      rsync_cmd += [dest, src]
    elif mode == "PUSH":
      rsync_cmd += [src, dest]

    L.debug(f"rsync command: {rsync_cmd}")
    try:
      subprocess.Popen(rsync_cmd)
    except subprocess.CalledProcessError as e:
      raise FrontendError(f"{self.fuzzer} run interrupted due to exception {e}.")


  @staticmethod
  def _queue_len(queue_path):
    """
    Helper that checks the number of seeds in queue, returns 0 if path doesn't
    exist yet.

    :param queue_path: path to queue (ie AFL_out/queue/)
    """
    if not os.path.exists(queue_path):
      return 0
    return len([path for path in os.listdir(queue_path)])


  def ensemble(self, local_queue=None, global_queue=None):
    """
    Base method for implementing ensemble fuzzing with seed synchronization. User should
    implement any additional logic for determining whether to sync/get seeds as if in event loop.
    """
    args = self._ARGS

    if global_queue is None:
      global_queue = args.sync_dir + "/"

    global_len = DeepStateFrontend._queue_len(global_queue)
    L.debug(f"Global seed queue: {global_queue} with {global_len} files")

    if local_queue is None:
      local_queue = args.output_test_dir + "/queue/"

    local_len = DeepStateFrontend._queue_len(local_queue)
    L.debug(f"Fuzzer local seed queue: {local_queue} with {local_len} files")

    # sanity check: if global queue is empty, populate from local queue
    if (global_len == 0) and (local_len > 0):
      L.info("Nothing in global queue, pushing seeds from local queue")
      self._sync_seeds("PUSH", local_queue, global_queue)
      return

    # get seeds from local to global queue, rsync will deal with duplicates
    self._sync_seeds("GET", global_queue, local_queue)

    # push seeds from global queue to local, rsync will deal with duplicates
    self._sync_seeds("PUSH", global_queue, local_queue)


  _ARGS = None

  def set_args(self, target_dict):
    """
    Helper method that allows a user to manually instantiate _ARGS as an AttrDict for
    attribute accessibility. Optimal when accessing frontends without parse_args instantiation.
    """

    if type(self._ARGS) is argparse.ArgumentParser:
      raise FrontendError("Arguments already parsed with parse_args.")

    if self._ARGS is None:
      self._ARGS = AttrDict()

    for key, value in target_dict.items():
      self._ARGS.update({key: value})


  @classmethod
  def parse_args(cls):
    """
    Default base argument parser for DeepState frontends. Comprises of default arguments all
    frontends must implement to maintain consistency in executables. Users can inherit this
    method to extend and add own arguments or override for outstanding deviations in fuzzer CLIs.
    """
    if cls._ARGS:
      return cls._ARGS

    # use existing argparser if defined in fuzzer object,
    # or initialize new one, both with default arguments
    if hasattr(cls, "parser"):
      L.debug("Using previously initialized parser")
      parser = cls.parser
    else:
      parser = argparse.ArgumentParser(description="Use {} fuzzer as a backend for DeepState".format(str(cls)))

    # Compilation/instrumentation support, only if COMPILER is set
    if cls.COMPILER:
      compile_group = parser.add_argument_group("compilation and instrumentation arguments")
      compile_group.add_argument("--compile_test", type=str, help="Path to DeepState test harness for compilation.")
      compile_group.add_argument("--compiler_args", type=str, help="Linker flags (space seperated) to include for external libraries.")
      compile_group.add_argument("--out_test_name", type=str, default="out", help="Set name of generated instrumented binary.")

    # Target binary (not required, as we enforce manual checks in pre_exec)
    parser.add_argument("binary", nargs="?", type=str, help="Path to the test binary to run.")

    # Input/output workdirs
    parser.add_argument("-i", "--input_seeds", type=str, help="Directory with seed inputs.")
    parser.add_argument("-o", "--output_test_dir", type=str, default="{}_out".format(str(cls())), help="Directory where tests will be saved.")

    # Fuzzer execution options
    parser.add_argument("-t", "--timeout", type=int, default=3600, help="How long to fuzz.")
    parser.add_argument("-s", "--max_input_size", type=int, default=8192, help="Maximum input size.")

    # Parallel / Ensemble Fuzzing
    parser.add_argument("--enable_sync", action="store_true", help="Enable seed synchronization.")
    parser.add_argument("--sync_dir", type=str, default="out_sync", help="Directory for seed synchronization.")
    parser.add_argument("--sync_cycle", type=int, default=5, help="Time between sync cycle.")
    parser.add_argument("--sync_crashes", action="store_true", help="Sync crashes between local and global queue.")
    parser.add_argument("--sync_hangs", action="store_true", help="Sync hanging inputs between local and global queue.")

    # Miscellaneous options
    parser.add_argument("--fuzzer_help", action="store_true", help="Show fuzzer command line options.")
    parser.add_argument("--which_test", type=str, help="Which test to run (equivalent to --input_which_test).")
    parser.add_argument("--args", default=[], nargs=argparse.REMAINDER, help="Overrides DeepState arguments to pass to test(s).")

    cls._ARGS = parser.parse_args()
    cls.parser = parser
