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
import argparse
import functools
import multiprocessing

from typing import ClassVar, Optional, Dict, List, Any

from deepstate.core.base import AnalysisBackend


L = logging.getLogger("deepstate.core.fuzz")
L.setLevel(os.environ.get("DEEPSTATE_LOG", "INFO").upper())


class FuzzFrontendError(Exception):
  """
  Defines our custom exception class for FuzzerFrontend
  """
  pass


class FuzzerFrontend(AnalysisBackend):
  """
  Defines a base front-end object for using DeepState to interact with fuzzers.
  """

  def __init__(self, envvar: str = "PATH") -> None:
    """
    Initializes base object with fuzzer executable and path, and checks to see if fuzzer
    executable exists in supplied environment variable (default is $PATH). Optionally also
    sets path to compiler executable for compile-time instrumentation, for those fuzzers that support it.

    User must define NAME and COMPILER (if compiling) members in inherited fuzzer class.

    :param envvar: name of envvar to discover executables. Default is $PATH.
    """

    fuzzer_name: Optional[str] = self.NAME
    if fuzzer_name is None:
      raise FuzzFrontendError("FuzzerFrontend.FUZZER not set")

    compiler: Optional[str] = self.COMPILER

    # work-around for mypy type-checking
    _env = os.environ.get(envvar)
    if _env is None:
      raise FuzzFrontendError(f"${envvar} does not contain any known paths.")
    env: str = str(_env)

    # collect paths from envvar, and check to see if fuzzer executable is present in paths
    potential_paths: List[str] = [var for var in env.split(":")]
    fuzzer_paths: List[str] = [f"{path}/{fuzzer_name}" for path in potential_paths if os.path.isfile(path + '/' + fuzzer_name)]
    if len(fuzzer_paths) == 0:
      raise FuzzFrontendError(f"${envvar} does not contain supplied fuzzer executable for `{self.NAME}`.")

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
          for path in os.environ.get("PATH").split(os.pathsep):
            compiler_path: str = os.path.join(path, compiler)

            L.debug(f"Checking if `{compiler_path}` is a valid compiler path")
            if os.path.isfile(compiler_path) and os.access(compiler_path, os.X_OK):
              self.compiler = compiler_path
              break

      # use first compiler executable if multiple exists
      else:
        self.compiler = compiler_paths[0]

      # toss exception if compiler still could not be found
      if not hasattr(self, "compiler"):
        raise FuzzFrontendError(f"{compiler} does not exist as absolute path, or in ${envvar} or $PATH")

      L.debug(f"Initialized compiler: {self.compiler}")

    # in case name supplied as `bin/fuzzer`, strip executable name
    self.name: str = fuzzer_name.split('/')[-1] if '/' in fuzzer_name else fuzzer_name
    L.debug(f"Fuzzer name: {self.name}")

    # use first fuzzer executable path if multiple exists
    self.fuzzer = fuzzer_paths[0]
    L.debug(f"Initialized fuzzer path: {self.fuzzer}")

    # flag to ensure fuzzer processes do not persist
    self._on: bool = False

    # parsed argument attributes
    self.binary: Optional[str] = None
    self.prog_args: List[str] = []
    self.output_test_dir: str = "{}_out".format(str(self))
    self.timeout: int = 0
    self.num_workers: int = 1

    self.compile_test: Optional[str] = None
    self.compiler_args: List[str] = []
    self.out_test_name: str = "out"

    self.enable_sync: bool = False
    self.sync_cycle: int = 5
    self.sync_out: bool = True
    self.sync_dir: str = "out_sync"

    self.which_test: Optional[str] = None


  def __repr__(self) -> str:
    return "{}".format(self.__class__.__name__)


  @classmethod
  def parse_args(cls) -> Optional[argparse.Namespace]:
    """
    Default base argument parser for DeepState frontends. Comprises of default arguments all
    frontends must implement to maintain consistency in executables. Users can inherit this
    method to extend and add own arguments or override for outstanding deviations in fuzzer CLIs.
    """

    L.debug("Parsing arguments with internal base class routine")

    if cls._ARGS:
      L.debug("Returning already-parsed arguments")
      return cls._ARGS

    # use existing argparser if defined in fuzzer object, or initialize new one, both with default arguments
    if cls.parser:
      L.debug("Using previously initialized parser")
      parser = cls.parser
    else:
      L.debug("Instantiating new ArgumentParser")
      parser = argparse.ArgumentParser(description="Use {} fuzzer as a backend for DeepState".format(str(cls)))

    # Fuzzer execution options
    parser.add_argument(
      "-i", "--input_seeds", type=str,
      help="Directory with seed inputs for fuzzers to queue and mutate.")

    parser.add_argument(
      "-s", "--max_input_size", type=int, default=8192,
      help="Maximum input size for input generator (default is 8192).")


    # Parallel / Ensemble Fuzzing
    ensemble_group = parser.add_argument_group("Parallel/Ensemble Fuzzing")
    ensemble_group.add_argument(
      "--enable_sync", action="store_true",
      help="Enable seed synchronization to another seed queue directory.")

    ensemble_group.add_argument(
      "--sync_out", action="store_true",
      help="When set, output individual fuzzer stat summary, instead of a global summary from the ensembler")

    ensemble_group.add_argument(
      "--sync_dir", type=str, default="out_sync",
      help="Directory representing seed queue for synchronization between local queue.")

    ensemble_group.add_argument(
      "--sync_cycle", type=int, default=5,
      help="Time in seconds the executor should sync to sync directory (default is 5 seconds).")


    # Miscellaneous options
    parser.add_argument(
      "--fuzzer_help", action="store_true",
      help="Show fuzzer command line interface's help options.")

    # finalize building up parser by passing to superclass, and instantiate object attributes
    # the base `parse_args` sets state with _ARGS, so we do need to return a namespace
    cls.parser = parser
    super(FuzzerFrontend, cls).parse_args()


  def print_help(self) -> None:
    """
    Calls fuzzer to print executable help menu.
    """
    subprocess.call([self.fuzzer, "--help"])


  ##############################################
  # Fuzzer pre-execution methods
  ##############################################


  def compile(self, lib_path: str, flags: List[str], _out_bin: str, env = os.environ.copy()) -> Optional[str]:
    """
    Provides a simple interface that allows the user to compile a test harness
    with instrumentation using the specified compiler. Users should implement an
    inherited method that constructs the arguments necessary, and then pass it to the
    base object. Returns string of generated binary if successful.

    `compile()` also supports compiling arbitrary harnesses without instrumentation if a compiler
    isn't set.

    :param lib_path: path to DeepState static library for linking
    :param flags: list of compiler flags (TODO: parse from compilation database)
    :param _out_bin: name of linked test harness binary
    :param env: optional envvars to set during compilation
    """

    if self.compiler is None:
      raise FuzzFrontendError(f"No compiler specified for compile-time instrumentation.")

    if self.binary is not None:
      raise FuzzFrontendError(f"User-specified test binary conflicts with compiling from source.")

    if not os.path.isfile(lib_path):
      raise FuzzFrontendError("No {}-instrumented DeepState static library found in {}".format(cls, lib_path))
    L.debug(f"Static library path: {lib_path}")

    # initialize compiler envvars
    env["CC"] = self.compiler
    env["CXX"] = self.compiler
    L.debug(f"CC={env['CC']} and CXX={env['CXX']}")

    # initialize command with prepended compiler
    compiler_args = ["-std=c++11", self.compile_test] + flags + \
                    ["-o", _out_bin]
    compile_cmd = [self.compiler] + compiler_args
    L.debug(f"Compilation command: {str(compile_cmd)}")

    # call compiler, and deal with exceptions accordingly
    L.info(f"Compiling test harness `{self.compile_test}` with {self.compiler}")
    try:
      subprocess.Popen(compile_cmd, env=env).communicate()
    except BaseException as e:
      raise FuzzFrontendError(f"{self.compiler} interrupted due to exception:", e)

    # extra check if target binary was successfully compiled, and set that as target binary
    out_bin = os.path.join(os.environ.get("PWD"), _out_bin)
    if os.path.exists(out_bin):
      self.binary = out_bin


  def pre_exec(self):
    """
    Called before fuzzer execution in order to perform sanity checks. Base method contains
    default argument checks. Users should implement inherited method for any other environment
    checks or initializations before execution.
    """

    if self.parser is None:
      raise FuzzFrontendError("No arguments parsed yet. Call parse_args() before pre_exec().")

    if self.fuzzer_help:
      self.print_help()
      sys.exit(0)

    # if compile_test is set, call compile for user
    if self.compile_test:
      self.compile()

      if self.binary is None:
        print("\nError: Could not compile binary for execution.")
        sys.exit(1)

      if not self.no_exit_compile:
        print(f"\nDone compiling target binary `{self.binary}`.")
        sys.exit(0)

    # manually check if binary positional argument was passed
    if self.binary is None:
      self.parser.print_help()
      print("\nError: Target binary not specified.")
      sys.exit(1)

    # check if binary exists and contains an absolute path
    if not os.path.isabs(self.binary):
      self.binary = os.path.abspath(self.binary)

    L.debug(f"Target binary: {self.binary}")

    # no sanity check, since some fuzzers require optional input seeds
    if self.input_seeds:
      L.debug(f"Input seeds directory: {self.input_seeds}")

    L.debug(f"Output directory: {self.output_test_dir}")

    # check if we enabled seed synchronization, and initialize directory
    if self.enable_sync:
      if not os.path.isdir(self.sync_dir):
        L.info("Initializing sync directory for ensembling seeds.")
        os.mkdir(self.sync_dir)
      L.debug(f"Sync directory: {self.sync_dir}")


  ##################################
  # Fuzzer command builder methods
  ##################################


  @property
  def cmd(self) -> Dict[str, Optional[str]]:
    """
    Property method that implements the logic for constructing a valid command
    for fuzzing, which is then bootstrapped and consumed by subprocess. User must
    implement functionality that can construct a valid dict of flags (key) to values,
    and then returns it to build_cmd().
    """
    raise NotImplementedError("Must implement in frontend subclass.")


  @staticmethod
  def _dict_to_cmd(cmd_dict: Dict[str, Optional[str]]) -> List[Optional[str]]:
    """
    Helper that provides an interface for constructing proper command to be passed
    to fuzzer executable. This takes a dict that maps a str argument flag to a value,
    and transforms it into list.

    :param cmd_dict: dict with keys as cli flags and values as arguments
    """

    # explicit lambda def to deal with mypy-lambda relations
    concat = lambda key, val: key + val
    cmd_args: List[Optional[str]] = list(functools.reduce(concat, cmd_dict.items()))
    cmd_args = [arg for arg in cmd_args if arg is not None]

    L.debug(f"Fuzzer arguments: `{str(cmd_args)}`")
    return cmd_args


  def build_cmd(self, cmd_dict: Dict[str, Optional[str]], input_symbol: str = "@@") -> Dict[str, Optional[str]]:
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


  ##############################################
  # Fuzzer process execution methods
  ##############################################

  def run(self, compiler: Optional[str] = None, no_exec: bool = False):
    """
    Interface for spawning and executing fuzzer jobs. Uses the configured `num_workers` in order to
    create a multiprocessing pool to parallelize fuzzers for execution in self._run.

    :param compiler: if necessary, a compiler that is invoked before fuzzer executable (ie `dotnet`)
    :param no_exec: skips pre- and post-processing steps during execution

    """

    # NOTE(alan): we don't use namespace param so we "build up" object attributes when we execute run()
    super(FuzzerFrontend, self).init_from_dict()

    # call pre_exec for any checks/inits before execution.
    if not no_exec:
      L.info("Calling pre_exec before fuzzing")
      self.pre_exec()

    # initialize cmd from property
    command = [self.fuzzer] + self._dict_to_cmd(self.cmd)

    # prepend compiler that invokes fuzzer
    if compiler:
      command.insert(0, compiler)

    results: List[int] = []
    pool = multiprocessing.Pool(processes=self.num_workers)
    results = pool.apply_async(self._run, args=(command,))

    pool.close()
    pool.join()

    L.debug(results)

    # TODO: check results for failures

    # do post-fuzz operations
    if not no_exec:
      if callable(getattr(self, "post_exec")):
        L.info("Calling post-exec for fuzzer post-processing")
        self.post_exec()


  def _run(self, command: List[str]) -> int:
    """
    Spawns a singular fuzzer process for execution with proper error-handling and foreground STDOUT output.
    Also supports rsync-style seed synchronization if configured to share seeds between a global queue.

    :param command: list of arguments representing fuzzer command to execute.
    """

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

      # while fuzzers may configure timeout, subprocess can ensure exit and is useful when parallelizing
      # processes or doing ensemble-based testing.
      stdout, stderr = self.proc.communicate(timeout=self.timeout if self.timeout != 0 else None)
      if self.proc.returncode != 0:
        self._kill()
        if self.enable_sync:
          err = stdout if stderr is None else stderr
          raise FuzzFrontendError(f"{self.fuzzer} run interrupted with non-zero return status. Message: {err.decode('utf-8')}")
        else:
          raise FuzzFrontendError(f"{self.fuzzer} run interrupted with non-zero return status. Error code: {self.proc.returncode}")

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
      raise FuzzFrontendError(f"{self.fuzzer} run interrupted due to exception {e}.")

    # SIGINT stops fuzzer, but continues execution
    except KeyboardInterrupt:
      print(f"Killing fuzzer {self.name} with PID {self.proc.pid}")
      self._kill()
      return 1

    finally:
      self._kill()

    # calculate total execution time
    exec_time: float = round(time.time() - self._start_time, 2)
    L.info(f"Fuzzer exec time: {exec_time}s")

    return 0


  def _is_alive(self) -> bool:
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


  def _kill(self) -> None:
    """
    Kills running fuzzer process. Can be used forcefully if
    KeyboardInterrupt signal falls through and process continues execution.
    """
    if not hasattr(self, "proc"):
      raise FuzzFrontendError("Attempted to kill non-running PID.")

    self.proc.terminate()
    try:
      self.proc.wait(timeout=0.5)
      L.info(f"Fuzzer subprocess exited with `{self.proc.returncode}`")
    except subprocess.TimeoutExpired:
      raise FuzzFrontendError("Subprocess could not terminate in time")

    self._on = False


  ############################################
  # Auxiliary reporting and processing methods
  ############################################


  def reporter(self):
    """
    Provides an interface for fuzzers to output important statistics during an ensemble
    cycle. This ensure that fuzzer outputs don't clobber STDOUT, and that users can gain
    insight during ensemble run.
    """
    return NotImplementedError("Must implement in frontend subclass.")


  @property
  def stats(self):
    """
    Parses out stats generated by fuzzer output. Should be implemented by user, and can return custom
    feedback.
    """
    raise NotImplementedError("Must implement in frontend subclass.")


  def post_exec(self):
    """
    Performs user-specified post-processing execution logic. Should be implemented by user, and can implement
    things like crash triaging, testcase minimization (ie with `deepstate-reduce`), or any other manipulations
    with produced testcases.
    """
    raise NotImplementedError("Must implement in frontend subclass.")


  ###################################
  # Ensemble/Parallel Fuzzing methods
  ###################################


  def _sync_seeds(self, mode: str, src: str, dest: str, excludes: List[str] = []) -> None:
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
      raise FuzzFrontendError(f"Unknown mode for seed syncing: `{mode}`")

    rsync_cmd: List[str] = ["rsync", "-racz", "--ignore-existing"]

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
      raise FuzzFrontendError(f"{self.fuzzer} run interrupted due to exception {e}.")


  @staticmethod
  def _queue_len(queue_path: str) -> int:
    """
    Helper that checks the number of seeds in queue, returns 0 if path doesn't
    exist yet.

    :param queue_path: path to queue (ie AFL_out/queue/)
    """
    if not os.path.exists(queue_path):
      return 0
    return len([path for path in os.listdir(queue_path)])


  def ensemble(self, local_queue: Optional[str] = None, global_queue: Optional[str] = None):
    """
    Base method for implementing ensemble fuzzing with seed synchronization. User should
    implement any additional logic for determining whether to sync/get seeds as if in event loop.
    """

    if global_queue is None:
      global_queue = self.sync_dir + "/"

    global_len: int = self._queue_len(global_queue)
    L.debug(f"Global seed queue: {global_queue} with {global_len} files")

    if local_queue is None:
      local_queue = self.output_test_dir + "/queue/"

    local_len: int = self._queue_len(local_queue)
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
