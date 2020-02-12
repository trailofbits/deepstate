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

import os
import time
import sys
import subprocess
import argparse
import shutil
import multiprocessing as mp

from tempfile import mkdtemp
from multiprocessing.pool import ApplyResult
from typing import Optional, Dict, List, Any, Tuple

from deepstate.core.base import AnalysisBackend, AnalysisBackendError


L = logging.getLogger(__name__)


class FuzzFrontendError(AnalysisBackendError):
  """
  Defines our custom exception class for FuzzerFrontend
  """
  pass


class FuzzerFrontend(AnalysisBackend):
  """
  Defines a base front-end object for using DeepState to interact with fuzzers.
  """

  def __init__(self, envvar: str) -> None:
    """
    Create and store variables:
      - fuzzer_exe (fuzzer executable file)
      - env (environment variable name)
      - search_dirs (directories inside fuzzer home dir where to look for executables)

    Inherits:
      - name (name for pretty printing)
      - compiler_exe (fuzzer compiler file, optional)

    User must define in inherited fuzzer class:
      - NAME str
      - EXECUTABLES dict with keys:
          FUZZER, COMPILER (if compiling) and any executable it will use

    :param envvar: name of envvar to discover executables.
    """
    super(FuzzerFrontend, self).__init__()

    if "FUZZER" not in self.EXECUTABLES:
      raise FuzzFrontendError("FuzzerFrontend.EXECUTABLES[\"FUZZER\"] not set.")
    self.fuzzer_exe: str = self.EXECUTABLES.pop("FUZZER")

    self.envvar: str = envvar
    self.env: Optional[str] = os.environ.get(envvar, None)

    self.search_dirs: List[str] = getattr(self, "SEARCH_DIRS", [])

    # flag to ensure fuzzer processes do not persist
    self._on: bool = False

    # parsed argument attributes
    self.input_seeds: Optional[str] = None
    self.max_input_size: int = 8192
    self.dictionary: Optional[str] = None
    self.exec_timeout: Optional[int] = None
    self.blackbox: Optional[bool] = None
    self.fuzzer_args: List[Any] = []

    self.enable_sync: bool = False
    self.sync_cycle: int = 5
    self.sync_out: bool = True

    self.push_dir: str = ''  # push testcases from external sources here
    self.pull_dir: str = ''  # pull new testcases from this dir
    self.crash_dir: str = ''  # crashes will be in this dir

    self.post_stats: bool = False
    self.home_path: Optional[str] = None


  def __repr__(self) -> str:
    return "{}".format(self.__class__.__name__)


  @classmethod
  def parse_args(cls) -> Optional[argparse.Namespace]:
    """
    Default base argument parser for DeepState frontends. Comprises of default arguments all
    frontends must implement to maintain consistency in executables. Users can inherit this
    method to extend and add own arguments or override for outstanding deviations in fuzzer CLIs.

    Arguments provided by this method and usable in fuzzers' functions.
    Guaranteed arguments (have default value):
      - output_test_dir (default: out)
      - mem_limit (default: 50MiB)
      - max_input_size (default: 8192B)
      - fuzzer_args (default: {})
      - blackbox (default: False)
      - post_stats (default: False)

    Optional arguments (may be None):
      - input_seeds
      - dictionary
      - exec_timeout

    Arguments that should not be used by child class:
      - timeout (default: 0)
      - num_workers (default: 1)
      - target_args (default: {})
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
      help="Maximum input size for input generator in bytes (default is 8192). 0 for unlimited.")

    parser.add_argument("--dictionary", type=str,
      help="Optional fuzzer dictionary.")

    parser.add_argument(
      "--exec_timeout", type=int,
      help="Timeout for one test-case (fuzz run) in milliseconds.")

    parser.add_argument(
      "--blackbox", action="store_true",
      help="Black-box fuzzing without compile-time instrumentation.")

    parser.add_argument(
      "--fuzzer_args", default=[], nargs='*',
      help="Flags to pass to the fuzzer. Format: `a arg1=val` -> `-a --arg val`.")


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


    # Post-processing
    post_group = parser.add_argument_group("Execution Post-processing")
    post_group.add_argument("--post_stats", action="store_true",
      help="Output post-fuzzing statistics to user (if any).")


    # Miscellaneous options
    parser.add_argument(
      "--fuzzer_help", action="store_true",
      help="Show fuzzer command line interface's help options.")

    parser.add_argument(
      "--home_path", type=str,
      help="Path to fuzzer home directory. Will search executables there and in PATH.")

    # finalize building up parser by passing to superclass, and instantiate object attributes
    # the base `parse_args` sets state with _ARGS, so we do need to return a namespace
    cls.parser = parser
    super(FuzzerFrontend, cls).parse_args()

    # parse fuzzer_args
    _args: Dict[str, Any] = vars(cls._ARGS)

    fuzzer_args_parsed: List[Tuple[str, Optional[str]]] = []
    for arg in _args['fuzzer_args']:
      vals = arg.split("=", 1)
      key = vals[0]
      val = None
      if len(vals) == 2:
        val = vals[1]
      fuzzer_args_parsed.append((key, val))
    _args['fuzzer_args'] = fuzzer_args_parsed

    return None


  def print_help(self) -> None:
    """
    Calls fuzzer to print executable help menu.
    """
    subprocess.call([self.fuzzer_exe, "--help"])


  ##############################################
  # Fuzzer pre-execution methods
  ##############################################


  def _search_for_executable(self, exe_name):
    # exe as absolute name
    if os.path.isabs(exe_name):
      if not os.path.isfile(exe_name):
        raise FuzzFrontendError(f"File `{exe_name}` doesn't exists.")
      if not os.access(exe_name, os.X_OK):
        raise FuzzFrontendError(f"File `{exe_name}` is not executable.")
      return exe_name

    # search in env, add search_dirs
    if self.env:
      for one_env_path in self.env.split(":"):
        for search_dir in [""] + self.search_dirs:
          exe_path: Optional[str] = shutil.which(exe_name, path=os.path.join(one_env_path, search_dir))
          if exe_path is not None:
            return exe_path

    # search in current dir and $PATH
    where_to_search = ['.', None]
    for search_env in where_to_search:
      exe_path: Optional[str] = shutil.which(exe_name, path=search_env)
      if exe_path is not None:
        return exe_path

    raise FuzzFrontendError(f"Executable file `{exe_name}` not found in neither `{self.env}` nor $PATH.\n"
                            f"Please add path to {self.name} in {self.envvar} env var or in --home_path argument.")


  def _set_executables(self):
    """
    Search for required executables in ${env} (envvar from child class),
    then in --home_path CLI argument, then in current dir and then in $PATH.

    Except if executable is given as an absolute path, then just check if it exists
    and if permissions are correct.

    Update variables:
      - fuzzer_exe
      - compiler_exe
    
    Throws exception if some executable couldn't be found
    """

    # add path from argument to env
    if self.home_path:
      if self.env:
        self.env += f":{self.home_path}"
      else:
        self.env = self.home_path

    # set fuzzer_exe 
    self.fuzzer_exe = self._search_for_executable(self.fuzzer_exe)
    L.debug("Will use %s as fuzzer executable.", self.fuzzer_exe)

    # set compiler_exe
    if self.compiler_exe:
      self.compiler_exe = self._search_for_executable(self.compiler_exe)
      L.debug("Will use %s as fuzzer compiler.", self.compiler_exe)

    # set additional executables
    for exe_name, exe_file in self.EXECUTABLES.items():
      self.EXECUTABLES[exe_name] = self._search_for_executable(exe_file)


  def compile(self, lib_path: str, flags: List[str], _out_bin: str, env = os.environ.copy()) -> None:
    """
    Provides a simple interface that allows the user to compile a test harness
    with instrumentation using the specified compiler. Users should implement an
    inherited method that constructs the arguments necessary, and then pass it to the
    base object.

    `compile()` also supports compiling arbitrary harnesses without instrumentation if a compiler
    isn't set.

    :param lib_path: path to DeepState static library for linking
    :param flags: list of compiler flags (TODO: support parsing from compilation database path)
    :param _out_bin: name of linked test harness binary
    :param env: optional envvars to set during compilation
    """

    if self.compiler_exe is None:
      raise FuzzFrontendError(f"No compiler specified for compile-time instrumentation.")

    if self.binary is not None:
      raise FuzzFrontendError(f"User-specified test binary conflicts with compiling from source.")

    if not os.path.isfile(lib_path):
      raise FuzzFrontendError("No {}-instrumented DeepState static library found in {}".format(self, lib_path))
    L.debug("Static library path: %s", lib_path)

    # initialize compiler envvars
    env["CC"] = self.compiler_exe.replace('++', '')
    env["CXX"] = self.compiler_exe
    L.debug("CC=%s and CXX=%s", env['CC'], env['CXX'])

    # initialize command with prepended compiler
    compiler_args: List[str] = ["-std=c++11", self.compile_test] + flags + ["-o", _out_bin] # type: ignore
    compile_cmd = [self.compiler_exe] + compiler_args
    L.debug("Compilation command: %s", compile_cmd)

    # call compiler, and deal with exceptions accordingly
    L.info("Compiling test harness `%s`", compile_cmd)
    subprocess.Popen(compile_cmd, env=env).communicate()

    # extra check if target binary was successfully compiled, and set that as target binary
    out_bin = os.path.join(os.getcwd(), _out_bin)
    if os.path.exists(out_bin):
      self.binary = out_bin


  def create_fake_seeds(self):
    self.input_seeds = mkdtemp()
    with open(os.path.join(self.input_seeds, "fake_seed"), 'wb') as f:
      f.write(b'X')
    L.info("Creating fake input seeds directory: %s", self.input_seeds)


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

    # search for executables and set proper variables
    self._set_executables()

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
    self.binary = os.path.abspath(self.binary)
    if not os.path.isfile(self.binary):
      raise FuzzFrontendError(f"Binary {self.binary} doesn't exists.")
    L.debug("Target binary: %s", self.binary)

    # if input_seeds is provided run checks
    if self.input_seeds:
      L.debug("Input seeds directory: %s", self.input_seeds)

      if not os.path.exists(self.input_seeds):
        raise FuzzFrontendError(f"Input seeds dir (`{self.input_seeds}`) doesn't exist.")

      if not os.path.isdir(self.input_seeds):
        raise FuzzFrontendError(f"Input seeds dir (`{self.input_seeds}`) is not a directory.")

      if len(os.listdir(self.input_seeds)) == 0:
        raise FuzzFrontendError(f"No seeds present in directory `{self.input_seeds}`.")

    # require empty output directory
    L.debug("Output directory: %s", self.output_test_dir)
    if not self.output_test_dir:
      raise FuzzFrontendError("Must provide -o/--output_test_dir.")

    if not os.path.exists(self.output_test_dir):
      raise FuzzFrontendError(f"Output test dir (`{self.output_test_dir}`) doesn't exist.")

    if not os.path.isdir(self.output_test_dir):
      raise FuzzFrontendError(f"Output test dir (`{self.output_test_dir}`) is not a directory.")

    # check if we enabled seed synchronization, and initialize directory
    if self.enable_sync:
      if not os.path.isdir(self.sync_dir):
        L.info("Initializing sync directory for ensembling seeds.")
        os.mkdir(self.sync_dir)
      L.debug("Sync directory: %s", self.sync_dir)


  ##################################
  # Fuzzer command builder methods
  ##################################


  @property
  def cmd(self) -> List[str]:
    """
    Property method that implements the logic for constructing a valid command
    for fuzzing, which is then bootstrapped and consumed by subprocess. User must
    implement functionality that can construct a valid list of flags (key-value tuples),
    and then returns it to build_cmd().
    """
    raise NotImplementedError("Must implement in frontend subclass.")


  def build_cmd(self, cmd_list: List[Optional[str]], input_symbol: str = "@@") -> List[Optional[str]]:
    """
    Helper method to be invoked by child fuzzer class's cmd() property method in order
    to finalize command called by the fuzzer executable with appropriate arguments for the
    test harness. Should NOT be called if a fuzzer gets invoked differently (ie arguments necessary
    that deviate from how standard fuzzers invoke binaries).

    :param cmd_list: incomplete dict to complete with harness argument information
    :param input_symbol: symbol recognized by fuzzer to replace when conducting file-based fuzzing
    """

    # initialize command with harness binary and DeepState flags to pass to it
    cmd_list.extend([
      "--", self.binary,
      "--input_test_file", input_symbol,
      "--abort_on_fail",
      "--no_fork",
      "--min_log_level", str(self.min_log_level)
    ])

    # append any other DeepState flags
    for key, val in self.target_args:
      if len(key) == 1:
        cmd_list.append('-{}'.format(key))
      else:
        cmd_list.append('--{}'.format(key))
      if val is not None:
        cmd_list.append(val)

    # test selection
    if self.which_test:
      cmd_list.extend(["--input_which_test", self.which_test])

    return cmd_list


  def main(self):
    """
    Helper method for calling fuzzer methods in correct order
    """
    try:
      self.parse_args()
      self.run()
      return 0
    except AnalysisBackendError as e:
      L.error(e)
      return 1


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
    command = [self.fuzzer_exe] + self.cmd # type: ignore

    # prepend compiler that invokes fuzzer
    if compiler:
      command.insert(0, compiler)

    results: List[ApplyResult[int]]
    results_outputs: List[int]
    mp.set_start_method('fork')
    with mp.Pool(processes=self.num_workers) as pool:
      results = [pool.apply_async(self._run, args=(command,)) for _ in range(self.num_workers)]
      results_outputs = [result.get() for result in results]

    L.debug(results_outputs)

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

    L.info("Executing command `%s`", command)

    self._on = True
    self._start_time = int(time.time())

    try:

      # if we are syncing seeds, we background the process and all of the output generated
      if self.enable_sync or self.num_workers > 1:
        self.proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        L.info("Starting fuzzer with seed synchronization with PID `%d`", self.proc.pid)
      else:
        self.proc = subprocess.Popen(command)
        L.info("Starting fuzzer  with PID `%d`", self.proc.pid)

      L.info("Fuzzer start time: %s", self._start_time)

      # while fuzzers may configure timeout, subprocess can ensure exit and is useful when parallelizing
      # processes or doing ensemble-based testing.
      stdout, stderr = self.proc.communicate(timeout=self.timeout if self.timeout != 0 else None)
      if self.proc.returncode != 0:
        self._kill()
        if self.enable_sync:
          err = stdout if stderr is None else stderr
          raise FuzzFrontendError(f"{self.name} run interrupted with non-zero return status. Message: {err.decode('utf-8')}")
        else:
          raise FuzzFrontendError(f"{self.name} run interrupted with non-zero return status. Error code: {self.proc.returncode}")

      # invoke ensemble if seed synchronization option is set
      if self.enable_sync:

        # do not ensemble as fuzzer initializes
        time.sleep(5)
        self.sync_count = 0

        # ensemble "event" loop
        while self._is_alive():

          L.debug("%s - Performing sync cycle %s", self.name, self.sync_count)

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
      raise FuzzFrontendError(f"{self.name} run interrupted due to exception {e}.")

    # SIGINT stops fuzzer, but continues execution
    except KeyboardInterrupt:
      print(f"Killing fuzzer {self.name} with PID {self.proc.pid}")
      self._kill()
      return 1

    except AnalysisBackendError as e:
      raise e

    except Exception:
      import traceback
      L.error(traceback.format_exc())

    finally:
      self._kill()

    # calculate total execution time
    exec_time: float = round(time.time() - self._start_time, 2)
    L.info("Fuzzer exec time: %ss", exec_time)

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
      L.info("Fuzzer subprocess exited with `%d`", self.proc.returncode)
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

    L.debug("rsync command: %s", rsync_cmd)
    try:
      subprocess.Popen(rsync_cmd)
    except subprocess.CalledProcessError as e:
      raise FuzzFrontendError(f"{self.name} run interrupted due to exception {e}.")


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
    L.debug("Global seed queue: %s with %d files", global_queue, global_len)

    if local_queue is None:
      local_queue = self.output_test_dir + "/queue/"

    local_len: int = self._queue_len(local_queue)
    L.debug("Fuzzer local seed queue: %s with %d files", local_queue, local_len)

    # sanity check: if global queue is empty, populate from local queue
    if (global_len == 0) and (local_len > 0):
      L.info("Nothing in global queue, pushing seeds from local queue")
      self._sync_seeds("PUSH", local_queue, global_queue)
      return

    # get seeds from local to global queue, rsync will deal with duplicates
    self._sync_seeds("GET", global_queue, local_queue)

    # push seeds from global queue to local, rsync will deal with duplicates
    self._sync_seeds("PUSH", global_queue, local_queue)
