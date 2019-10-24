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

from typing import ClassVar, Optional


L = logging.getLogger("deepstate.frontend")
L.setLevel(os.environ.get("DEEPSTATE_LOG", "INFO").upper())


class FrontendError(Exception):
  """
  Defines our custom exception class for DeepStateFrontend
  """
  pass


class DeepStateFrontend(object):
  """
  Defines a base front-end object for using DeepState to interact with fuzzers.
  """

  # to be implemented by fuzzer subclass
  FUZZER: ClassVar[Optional[str]] = None
  COMPILER: ClassVar[Optional[str]]  = None

  # temporary attribute for argparsing, and should be used to build up object attributes
  _ARGS: ClassVar[Optional[dict]] = None


  def __init__(self, envvar: str = "PATH") -> None:
    """
    Initializes base object with fuzzer executable and path, and checks to see if fuzzer
    executable exists in supplied environment variable (default is $PATH). Optionally also
    sets path to compiler executable for compile-time instrumentation, for those fuzzers that support it.

    User must define FUZZER and COMPILER members in inherited fuzzer class.

    :param envvar: name of envvar to discover executables. Default is $PATH.
    """

    fuzzer_name: Optional[str] = self.FUZZER
    if fuzzer_name is None:
      raise FrontendError("DeepStateFrontend.FUZZER not set")

    compiler: Optional[str] = self.COMPILER

    if os.environ.get(envvar) is None:
      raise FrontendError(f"${envvar} does not contain any known paths.")

    # collect paths from envvar, and check to see if fuzzer executable is present in paths
    potential_paths: List[str] = [var for var in os.environ.get(envvar).split(":")]
    fuzzer_paths: List[str] = [f"{path}/{fuzzer_name}" for path in potential_paths if os.path.isfile(path + '/' + fuzzer_name)]
    if len(fuzzer_paths) == 0:
      raise FrontendError(f"${envvar} does not contain supplied fuzzer executable for `{self.FUZZER}`.")

    L.debug(fuzzer_paths)

    # if supplied, check if compiler exists in potential_paths
    if compiler is not None:

      compiler_paths: List[str] = [f"{path}/{compiler}" for path in potential_paths if os.path.isfile(path + '/' + compiler)]
      if len(compiler_paths) == 0:

        # if not in envvar, check to see if user supplied absolute path
        if os.path.isfile(compiler):
          self.compiler: str = compiler

        # .. or check if in $PATH before tossing exception
        else:
          for path in os.environ["PATH"].split(os.pathsep):
            compiler_path: str = os.path.join(path, compiler)

            L.debug(f"Checking if `{compiler_path}` is a valid compiler path")
            if os.path.isfile(compiler_path) and os.access(compiler_path, os.X_OK):
              self.compiler: str = compiler_path
              break

      # use first compiler executable if multiple exists
      else:
        self.compiler: str = compiler_paths[0]

      # toss exception if compiler still could not be found
      if not hasattr(self, "compiler"):
        raise FrontendError(f"{compiler} does not exist as absolute path, or in ${envvar} or $PATH")

      L.debug(f"Initialized compiler: {self.compiler}")

    # in case name supplied as `bin/fuzzer`, strip executable name
    self.name: str = fuzzer_name.split('/')[-1] if '/' in fuzzer_name else fuzzer_name
    L.debug(f"Fuzzer name: {self.name}")

    # use first fuzzer executable path if multiple exists
    self.fuzzer = fuzzer_paths[0]
    L.debug(f"Initialized fuzzer path: {self.fuzzer}")

    self._on = False


  def __repr__(self):
    return "{}".format(self.__class__.__name__)


  def init_fuzzer(self, _args=None):
    """
    Builder-like initialization routine used to instantiate the attributes of the frontend object, either from the stored
    _ARGS namespace, or manual arguments passed in (not ideal, but useful for ensembler orchestration).

    :param _self. optional dictionary with parsed arguments to set as attributes.
    """
    args = vars(self._ARGS) if not _args else _args
    for key, value in args.items():
      setattr(self, key, value)


  @classmethod
  def parse_args(cls):
    """
    Default base argument parser for DeepState frontends. Comprises of default arguments all
    frontends must implement to maintain consistency in executables. Users can inherit this
    method to extend and add own arguments or override for outstanding deviations in fuzzer CLIs.
    """

    if cls._ARGS:
      return cls._ARGS

    # use existing argparser if defined in fuzzer object, or initialize new one, both with default arguments
    if hasattr(cls, "parser"):
      L.debug("Using previously initialized parser")
      parser = cls.parser
    else:
      parser = argparse.ArgumentParser(description="Use {} fuzzer as a backend for DeepState".format(str(cls)))

    # Compilation/instrumentation support, only if COMPILER is set
    if hasattr(cls, "COMPILER"):
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
    parser.add_argument("-t", "--timeout", type=str, default="3600", help="How long to fuzz.")
    parser.add_argument("-s", "--max_input_size", type=int, default=8192, help="Maximum input size.")

    # Parallel / Ensemble Fuzzing
    parser.add_argument("--enable_sync", action="store_true", help="Enable seed synchronization.")
    parser.add_argument("--sync_out", action="store_true", help="When set, output individual fuzzer stat summary, instead of a global summary from the ensembler")
    parser.add_argument("--sync_dir", type=str, default="out_sync", help="Directory for seed synchronization.")
    parser.add_argument("--sync_cycle", type=int, default=5, help="Time between sync cycle.")

    # Miscellaneous options
    parser.add_argument("--fuzzer_help", action="store_true", help="Show fuzzer command line options.")
    parser.add_argument("--which_test", type=str, help="Which test to run (equivalent to --input_which_test).")
    parser.add_argument("--prog_args", default=[], nargs=argparse.REMAINDER, help="Other DeepState flags to pass to harness before execution, in format `--arg=val`.")


    # NOTE(alan): we don't use namespace param so we "build up" object with `init_fuzzer()`
    cls._ARGS = parser.parse_args()
    cls.parser = parser


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

    `compile()` also supports compiling arbitrary harnesses without instrumentation if a compiler
    isn't set.

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

    L.info(f"Compiling test harness `{self.compile_test}` with {self.compiler}")
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

    if self._ARGS is None:
      raise FrontendError("No arguments parsed yet. Call parse_self.before pre_exec.")

    if self.fuzzer_help:
      self.print_help()
      sys.exit(0)

    # if compile_test is an existing argument, call compile for user
    if hasattr(self, "compile_test"):
      if self.compile_test:
        self.compile()
        sys.exit(0)

    # manually check if binary positional argument was passed
    if self.binary is None:
      self.parser.print_help()
      print("\nError: Target binary not specified.")
      sys.exit(1)

    L.debug(f"Target binary: {self.binary}")

    # no sanity check, since some fuzzers require optional input seeds
    if self.input_seeds:
      L.debug(f"Input seeds directory: {self.input_seeds}")

    L.debug(f"Output directory: {self.output_test_dir}")

    # check if we in ensemble mode, and initialize directory
    if self.enable_sync:
      if not os.path.isdir(self.sync_dir):
        L.info("Initializing sync directory for ensembling")
        os.mkdir(self.sync_dir)
      L.debug(f"Sync directory: {self.sync_dir}")


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


  def build_cmd(self, cmd_dict, input_symbol="@@"):
    """
    Helper method to be invoked by child fuzzer class's cmd() property method in order
    to finalize command called by the fuzzer executable with appropriate arguments for the
    test harness. Should NOT be called if a fuzzer gets invoked differently (ie arguments necessary
    that deviate from how standard fuzzers invoke binaries).

    :param cmd_dict: incomplete dict to complete with harness argument information
    :param input_symbol: symbol recognized by fuzzer to replace when conducting file-based fuzzing
    """

    # initialize command with harness binary and DeepState flags to pass to it
    cmd_dict.update({
      "--": self.binary,
      "--input_test_file": input_symbol,
      "--abort_on_fail": None,
      "--no_fork": None
    })

    # append any other DeepState flags
    if self.prog_args:
      for arg in self.prog_args:
        vals = arg.split("=")
        if len(vals) == 1:
          cmd_dict.update({ vals[0] : None })
        else:
          cmd_dict.update({ vals[0] : vals[1] })

    # test selection
    if self.which_test:
      cmd_dict["--input_which_test"] = self.which_test

    return cmd_dict


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

    self._on = True
    self._start_time = int(time.time())

    try:

      # if we are syncing seeds, we background the process and all of the output generated
      if self.enable_sync:
        self.proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        L.info(f"Starting fuzzer with seed synchronization with PID `{self.proc.pid}`")
      else:
        self.proc = subprocess.Popen(command)
        L.info(f"Starting fuzzer  with PID `{self.proc.pid}`")

      L.info(f"Fuzzer start time: {self._start_time}")

      # check status if fuzzer exited early, and return error
      stdout, stderr = self.proc.communicate()
      if self.proc.returncode != 0:
        self._kill()
        err = stdout if stderr is None else stderr
        raise FrontendError(f"{self.fuzzer} run interrupted with non-zero return status. Error: {err.decode('utf-8')}")

      # invoke ensemble if seed synchronization option is set
      if self.enable_sync:

        # do not ensemble as fuzzer initializes
        time.sleep(5)
        self.sync_count = 0

        # ensemble "event" loop
        while self._is_alive():

          L.debug(f"{self.name} - Performing sync cycle {self.sync_count}")

          # sleep for execution cycle
          time.sleep(self.sync_cycle)

          # call ensemble to perform seed synchronization
          self.ensemble()

          # if sync_out argument set, output individual fuzzer statistics
          # rather than have our ensembler report global stats
          if self.sync_out:
            print(f"\n{self.name} Fuzzer Stats\n")
            for head, stat in self.reporter().items():
              print(f"{head}\t:\t{stat}")

          self.sync_count += 1


    # any OS-specific errors encountered
    except OSError as e:
      self._kill()
      raise FrontendError(f"{self.fuzzer} run interrupted due to exception {e}.")

    # SIGINT stops fuzzer, but continues execution
    except KeyboardInterrupt:
      print(f"Killing fuzzer {self.name} with PID {self.proc.pid}")
      self._kill()

    finally:
      self._kill()

    # calculate total execution time
    self.exec_time = round(time.time() - self._start_time, 2)
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

    if global_queue is None:
      global_queue = self.sync_dir + "/"

    global_len = DeepStateFrontend._queue_len(global_queue)
    L.debug(f"Global seed queue: {global_queue} with {global_len} files")

    if local_queue is None:
      local_queue = self.output_test_dir + "/queue/"

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
