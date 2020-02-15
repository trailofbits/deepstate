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
import psutil  # type: ignore
import argparse
import shutil
import traceback

from tempfile import mkdtemp
from pathlib import Path
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

  REQUIRE_SEEDS: bool = False

  PUSH_DIR: str
  PULL_DIR: str
  CRASH_DIR: str

  def __init__(self, envvar: str) -> None:
    """
    Create and store variables:
      - fuzzer_exe (fuzzer executable file)
      - env (environment variable name)
      - search_dirs (directories inside fuzzer home dir where to look for executables)
      - require_seeds
      - stats (dict that frontend should populate in populate_stats method)
      - stats_file (file where to put stats from fuzzer in common format)
      - output_file (file where stdout of fuzzer will be redirected)
      - proc (handler to fuzzer process)

      - push_dir (push testcases from external sources here)
      - pull_dir (pull new testcases from this dir)
      - crash_dir (crashes will be in this dir)

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

    self.proc: subprocess.Popen[bytes]
    self.require_seeds: bool = False
    self.stats_file: str = "deepstate-stats.txt"
    self.output_file: str = "fuzzer-output.txt"

    # same as AFL's (https://github.com/google/AFL/blob/master/docs/status_screen.txt)
    self.stats: Dict[str, Optional[str]] = {
      # guaranteed
      "unique_crashes": None,
      "fuzzer_pid": None,
      "start_time": None,
      "sync_dir_size": None,

      # not guaranteed
      "execs_done": None,
      "execs_per_sec": None,
      "last_update": None,
      "cycles_done": None,
      "paths_total": None,
      "paths_favored": None,
      "paths_found": None,
      "paths_imported": None,
      "max_depth": None,
      "cur_path": None,
      "pending_favs": None,
      "pending_total": None,
      "variable_paths": None,
      "stability": None,
      "bitmap_cvg": None,
      "unique_hangs": None,
      "last_path": None,
      "last_crash": None,
      "last_hang": None,
      "execs_since_crash": None,
      "slowest_exec_ms": None,
      "peak_rss_mb": None,
    }

    # parsed argument attributes
    self.input_seeds: Optional[str] = None
    self.max_input_size: int = 8192
    self.dictionary: Optional[str] = None
    self.exec_timeout: Optional[int] = None
    self.blackbox: Optional[bool] = None
    self.fuzzer_args: List[Any] = []
    self.fuzzer_out: bool = False

    self.sync_cycle: int = 5
    self.sync_out: bool = True
    self.sync_dir: Optional[str] = None

    self.push_dir: str = ''
    self.pull_dir: str = ''
    self.crash_dir: str = ''

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
      "--fuzzer_out", action="store_true",
      help="Show fuzzer-specific output (graphical interface) instead of deepstate one.")

    parser.add_argument(
      "--fuzzer_args", default=[], nargs='*',
      help="Flags to pass to the fuzzer. Format: `a arg1=val` -> `-a --arg val`.")


    # Parallel / Ensemble Fuzzing
    ensemble_group = parser.add_argument_group("Parallel/Ensemble Fuzzing")
    ensemble_group.add_argument(
      "--sync_dir", type=str,
      help="Directory representing seed queue for synchronization between fuzzers.")

    ensemble_group.add_argument(
      "--sync_cycle", type=int, default=5,
      help="Time in seconds the executor should sync to sync directory (default is 5 seconds).")

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
          exe_path: Optional[str] = shutil.which(exe_name, mode=os.F_OK, path=os.path.join(one_env_path, search_dir))
          if exe_path is not None:
            return exe_path

    # search in current dir and $PATH
    where_to_search = ['.', None]
    for search_env in where_to_search:
      exe_path: Optional[str] = shutil.which(exe_name, mode=os.F_OK, path=search_env)
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

    _out_bin += f".{self.NAME.lower()}"

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
    if not self.input_seeds:
      self.input_seeds = mkdtemp(prefix="deepstate_fake_seed")
    with open(os.path.join(self.input_seeds, "fake_seed"), 'wb') as f:
      f.write(b'X')
    L.info("Creating fake input seed file in directory `%s`", self.input_seeds)


  def check_required_directories(self, required_dirs):
    for required_dir in required_dirs:
      if not os.path.isdir(required_dir):
        raise FuzzFrontendError(f"Can't resume with output directory `{self.output_test_dir}`. "
                                f"No `{required_dir}` directory inside.")


  def setup_new_session(self, dirs_to_create=[]):
    for dir_to_create in dirs_to_create:
      Path(dir_to_create).mkdir(parents=True, exist_ok=True)
      L.debug(f"Creating directory {dir_to_create}.")

    if self.require_seeds is True and not self.input_seeds:
        self.create_fake_seeds()


  def pre_exec(self):
    """
    Called before fuzzer execution in order to perform sanity checks. Base method contains
    default argument checks. Users should implement inherited method for any other environment
    checks or initializations before execution.

    Do:
      - search for executables (update self.EXECUTABLES)
      - may print fuzzer help (and exit)
      - may compile
      - check for targets (self.binary)
      - may check for input_seeds
      - check for output directory
      - check for sync_dir
      - update stats_file path
    """

    if self.parser is None:
      raise FuzzFrontendError("No arguments parsed yet. Call parse_args() before pre_exec().")

    # search for executables and set proper variables
    self._set_executables()

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

    # require output directory
    L.debug("Output directory: %s", self.output_test_dir)
    if not self.output_test_dir:
      raise FuzzFrontendError("Must provide -o/--output_test_dir.")

    if not os.path.exists(self.output_test_dir):
      raise FuzzFrontendError(f"Output test dir (`{self.output_test_dir}`) doesn't exist.")

    if not os.path.isdir(self.output_test_dir):
      raise FuzzFrontendError(f"Output test dir (`{self.output_test_dir}`) is not a directory.")

    # update stats and output file
    self.stats_file = os.path.join(self.output_test_dir, self.stats_file)
    self.output_file = os.path.join(self.output_test_dir, self.output_file)

    # require seeds flag
    self.require_seeds = self.REQUIRE_SEEDS

    # push/pull/crash paths
    self.push_dir = os.path.join(self.output_test_dir, self.PUSH_DIR)
    self.pull_dir = os.path.join(self.output_test_dir, self.PULL_DIR)
    self.crash_dir = os.path.join(self.output_test_dir, self.CRASH_DIR)

    # check if we enabled seed synchronization, and initialize directory
    if self.sync_dir:
      if not os.path.exists(self.sync_dir):
        raise FuzzFrontendError(f"Seed synchronization dir (`{self.sync_dir}`) doesn't exist.")

      if not os.path.isdir(self.sync_dir):
        raise FuzzFrontendError(f"Seed synchronization dir (`{self.sync_dir}`) is not a directory.")

      L.info("Will synchronize seed using `%s` directory.", self.sync_dir)


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


  def manage(self):
    # print and save statistics
    self.populate_stats()
    self.save_stats()
    if not self.fuzzer_out:
      self.print_stats()

    # invoke ensemble if sync_dir is provided
    if self.sync_dir:
      L.info("%s - Performing sync cycle %s", self.name, self.sync_count)
      self.ensemble()
      self.sync_count += 1


  def cleanup(self):
    if not self.proc:
      return
    
    L.info(f"Killing process {self.proc.pid} and childs.")

    # terminate
    try:
      for some_proc in psutil.Process(self.proc.pid).children(recursive=True) + [self.proc]:
        some_proc.terminate()
    except psutil.NoSuchProcess:
      self.proc = None
      return

    # hard kill
    for some_proc in psutil.Process(self.proc.pid).children(recursive=True) + [self.proc]:
      try:
        some_proc.communicate(timeout=1)
        L.info("Fuzzer subprocess (PID %d) exited with `%d`", some_proc.pid, some_proc.returncode)
      except subprocess.TimeoutExpired:
        L.warning("Subprocess (PID %d) could not terminate in time, killing.", some_proc.pid)
        some_proc.kill()
      except psutil.NoSuchProcess:
        self.proc = None
        return

    self.proc = None


  def run(self, runner: Optional[str] = None, no_exec: bool = False):
    """
    Interface for spawning and executing fuzzer job.

    :param runner: if necessary, a runner that is invoked before fuzzer executable (ie `dotnet`)
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

    # prepend runner that invokes fuzzer
    if runner:
      command.insert(0, runner)

    L.info("Executing command `%s`", command)
    self.start_time: int = int(time.time())
    self.command: str = ' '.join(command)
    self.sync_count = 0

    total_execution_time: int = 0
    wait_time: int = self.sync_cycle
    run_fuzzer: bool = True
    prev_log_level = L.level

    # for fuzzer output
    if not self.fuzzer_out:
      fuzzer_out_file = open(self.output_file, "wb")

    # run or resume fuzzer process as long as it is needed
    # may create new processes continuously
    while run_fuzzer:
      run_one_fuzzer_process: bool = False
      try:
        if self.fuzzer_out:
          # disable deepstate output
          L.info("Using fuzzer output.")
          L.setLevel("ERROR")
          self.proc = subprocess.Popen(command)

        else:
          L.info("Using DeepState output.")
          # TODO: frontends uses blocking read in `populate_stats`,
          # we may replace PIPE with normal file and do reads non-blocking
          self.proc = subprocess.Popen(command, stdout=fuzzer_out_file, stderr=fuzzer_out_file)

        run_one_fuzzer_process = True
        L.info("Started fuzzer process with PID %d.", self.proc.pid)

      except (OSError, ValueError):
        L.setLevel(prev_log_level)
        L.error(traceback.format_exc())
        raise FuzzFrontendError("Exception during fuzzer startup.")

      # run-manage loop, until somethings happens (error, interrupt, fuzzer exits)
      # use only one process
      while run_one_fuzzer_process:
        # general timeout
        time_left = float('inf')
        total_execution_time = int(time.time() - self.start_time)
        if self.timeout != 0:
          time_left = self.timeout - total_execution_time
          if time_left < 0:
            run_one_fuzzer_process = False
            run_fuzzer = False
            wait_time = 0
            L.info("Timeout")

        try:
          # sleep/communicate for `self.sync_cycle` time
          timeout_one_cycle: int = wait_time
          if wait_time > time_left:
            timeout_one_cycle = int(time_left)

          L.debug("One cycle `communicate` with timeout %d.", timeout_one_cycle)
          stdout, stderr = self.proc.communicate(timeout=timeout_one_cycle)

          # fuzzer process exited
          # it's fine if returncode is 0 or 1 for libfuzzer 
          if self.proc.returncode == 0 or \
              (self.proc.returncode == 1 and self.name == "libFuzzer"):
            L.info("Fuzzer %s (PID %d) exited with return code %d.",
                      self.name, self.proc.pid, self.proc.returncode)
            run_one_fuzzer_process = False

          else:
            if stdout:
              L.error(stdout.decode('utf8'))
            if stderr:
              L.error(stderr.decode('utf8'))
            raise FuzzFrontendError(f"Fuzzer {self.name} (PID {self.proc.pid}) exited "
                                    f"with return code {self.proc.returncode}.")

        # Timeout, just continue to management step
        except subprocess.TimeoutExpired:
          L.debug("One cycle timeout.")

        # Any OS-specific errors encountered
        except OSError as e:
          L.error("%s run interrupted due to OSError: %s.", self.name, e)
          run_one_fuzzer_process = False

        # SIGINT stops fuzzer, but continues frontend execution
        except KeyboardInterrupt:
          L.info("Stopped the %s fuzzer.", self.name)
          run_one_fuzzer_process = False
          run_fuzzer = False

        # bad things happed, inform user and exit
        except Exception:
          L.error(traceback.format_exc())      
          L.error("Exception during fuzzer %s run.", self.name)
          run_one_fuzzer_process = False
          run_fuzzer = False

        # manage
        try:
          L.debug("Management cycle starts after %ss.", total_execution_time)
          self.manage()

        # error in management, exit
        except Exception:
          L.error(traceback.format_exc())      
          L.error("Exception during fuzzer %s run.", self.name)
          run_one_fuzzer_process = False
          run_fuzzer = False

      # cleanup
      try:
        self.cleanup()
      except:
        pass

      if run_fuzzer:
        self.post_exec()

      # and... loop again!

    if not self.fuzzer_out:
      fuzzer_out_file.close()

    L.setLevel(prev_log_level)
    # calculate total execution time
    exec_time: float = round(time.time() - self.start_time, 2)
    L.info("Fuzzer exec time: %ss", exec_time)

    # do post-fuzz operations
    if not no_exec:
      L.info("Calling post-exec for fuzzer post-processing")
      self.post_exec()


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


  def populate_stats(self):
    """
    Parses out stats generated by fuzzer output. Should be implemented by user, and can return custom
    feedback.
    """
    crashes: int = len(os.listdir(self.crash_dir))
    if os.path.isfile(os.path.join(self.crash_dir, "README.txt")):
      crashes -= 1
    self.stats["unique_crashes"] = str(crashes)
    self.stats["start_time"] = str(int(self.start_time))
    if self.proc:
      self.stats["fuzzer_pid"] = str(self.proc.pid)
    if self.sync_dir:
      self.stats["sync_dir_size"] = str(len(os.listdir(self.sync_dir)))


  def print_stats(self):
    for key, value in self.stats.items():
      if value:
        L.fuzz_stats("%s:%s", key, value)
    L.fuzz_stats("-"*30)


  def save_stats(self):
    with open(self.stats_file, 'w') as f:
      for key, value in self.stats.items():
        if value:
          f.write(f"{key}:{value}\n")


  def post_exec(self):
    """
    Performs user-specified post-processing execution logic. Should be implemented by user, and can implement
    things like crash triaging, testcase minimization (ie with `deepstate-reduce`), or any other manipulations
    with produced testcases.
    """
    # make sure that child processes are killed
    self.cleanup()


  ###################################
  # Ensemble/Parallel Fuzzing methods
  ###################################


  def _sync_seeds(self, src: str, dest: str, excludes: List[str] = []) -> None:
    """
    Helper that invokes rsync for convenient file syncing between two files.

    TODO(alan): implement functionality for syncing across servers.
    TODO(alan): consider implementing "native" syncing alongside current "rsync mode".

    :param src: path to source queue
    :param dest: path to destination queue
    :param excludes: list of string patterns for paths to ignore when rsync-ing
    """

    rsync_cmd: List[str] = [
      "rsync",
      "--recursive",
      "--archive",
      "--checksum",
      "--compress",
      "--ignore-existing"
    ]

    # subclass should invoke with list of pattern ignores
    if len(excludes) > 0:
      rsync_cmd += [f"--exclude={e}" for e in excludes]

    rsync_cmd += [
      os.path.join(src, ""),  # append trailing / 
      dest
    ]

    # L.debug("rsync command: %s", rsync_cmd)
    L.debug("rsync %s: from `%s` to `%s`.", self.name, src, dest)
    try:
      subprocess.Popen(rsync_cmd)
    except subprocess.CalledProcessError as e:
      raise FuzzFrontendError(f"{self.name} rsync interrupted due to exception {e}.")


  def ensemble(self, local_queue: Optional[str] = None, global_queue: Optional[str] = None):
    """
    Base method for implementing ensemble fuzzing with seed synchronization. User should
    implement any additional logic for determining whether to sync/get seeds as if in event loop.
    """

    if not self.sync_dir:
      L.warning("Called `ensemble`, but `--sync_dir` not provided.")
      return

    global_queue = os.path.join(self.sync_dir, "queue")
    global_crashes = os.path.join(self.sync_dir, "crashes")
    local_queue = self.push_dir
    local_crashes = self.crash_dir

    # check global queue
    global_len: int = len(os.listdir(self.crash_dir))
    L.debug("Global seed queue: `%s` with %d files", global_queue, global_len)

    # update local queue with new findings
    self._sync_seeds(src=self.pull_dir, dest=self.push_dir)

    # check local queue
    local_len: int = len(os.listdir(self.push_dir))
    L.debug("Fuzzer local seed queue: `%s` with %d files", local_queue, local_len)

    # get seeds from local to global queue, rsync will deal with duplicates
    self._sync_seeds(src=local_queue, dest=global_queue)
    self._sync_seeds(src=local_crashes, dest=global_crashes)

    # push seeds from global queue to local, rsync will deal with duplicates
    self._sync_seeds(src=global_queue, dest=local_queue)
