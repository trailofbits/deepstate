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
import sys
import time
import string
import random
import argparse
import multiprocessing

from multiprocessing import Process
from collections import defaultdict

from deepstate.core.fuzz import FuzzerFrontend
from deepstate.executors.fuzz.afl import AFL
from deepstate.executors.fuzz.honggfuzz import Honggfuzz
from deepstate.executors.fuzz.angora import Angora
from deepstate.executors.fuzz.eclipser import Eclipser


L = logging.getLogger(__name__)


class Ensembler(FuzzerFrontend):
  """
  Ensembler is the ensemble-based fuzzer that orchestrates and invokes fuzzer frontends, while also
  supporting seed synchronization between those frontends. It initializes a set of global input args
  for each frontend, performs an "ensemble compile", and spawns fuzzers in parallel while maintaining
  seed synchronization between them.
  """

  NAME = "Ensembler"
  EXECUTABLES = {"FUZZER": "deepstate-ensembler"}

  @classmethod
  def parse_args(cls):
    parser = argparse.ArgumentParser(description="Ensemble-based fuzzer executor for DeepState")
    test_group = parser.add_mutually_exclusive_group(required=True)

    # Mutually exclusive target options
    test_group.add_argument("--test", type=str, \
      help="Path to test case harness for compilation and instrumentation.")

    test_group.add_argument("--test_dir", type=str, \
      help="Path to existing workspace directory with compiled and instrumented binaries.")

    # Compilation options
    parser.add_argument("-a", "--compiler_args", type=str, \
      help="Compiler linker arguments for test harness, if provided as argument.")

    parser.add_argument("--ignore_calls", type=str, \
      help="Path to static/shared libraries (colon seperated) to blackbox for taint analysis.")

    parser.add_argument("-w", "--workspace", type=str, default="ensemble_bins", \
      help="Path to workspace to store compiled and instrumented binaries (default is `ensemble_bins`).")

    # Ensembler execution options
    parser.add_argument("-n", "--num_cores", type=int, default=multiprocessing.cpu_count(), \
      help="Override number of cores to use.")

    parser.add_argument("--no_global", action="store_true", \
      help="If set, disable global ensembler output, and instead report individual fuzzer stats.")

    # TODO(alan): other execution options

    #parser.add_argument("--fuzzers", type=str, \
    #  help="Comma-seperated string of fuzzers to ensemble with (overrides default ensemble).")

    #parser.add_argument("--abort_on_crash", action="store_true", \
    #  help="Stop ensembler when any base fuzzer returns a crash.")

    cls.parser = parser
    super(Ensembler, cls).parse_args()


  def pre_exec(self):
    """
    Implements pre_exec method from frontend superclass, and does sanity-checking on
    parsed arguments before we can go ahead and provision an environment for ensemble fuzzing.
    """

    # `--fuzzer_help` equivalent to `--help`
    if self.fuzzer_help:
      self.parser.print_help()

    # ignore compiler-related arguments if not necessary
    if self.test_dir and (self.ignore_calls or self.compiler_args):
      L.info("Ignoring --ignore_calls and/or --compiler_args arguments passed")

    # initial path check
    _test = self.test if not self.test_dir else self.test_dir
    if not os.path.exists(_test):
      L.error("Target path `%s` does not exist. Exiting.", _test)
      sys.exit(1)

    if not os.path.isdir(self.input_seeds):
      L.error("Input seeds directory `%s` does not exist. Exiting.", self.input_seeds)
      sys.exit(1)

    if not os.path.isdir(self.output_test_dir):
      L.warn("Output directory does not exist. Creating.")
      os.mkdir(self.output_test_dir)

    if not self.sync_dir:
        L.warn("No seed synchronization dir specified, using `sync`.")
        self.sync_dir = "sync"

    sync_dir = self.output_test_dir + "/" + self.sync_dir
    if not os.path.isdir(sync_dir):
      L.warn("Sync directory does not exist. Creating.")
      os.mkdir(sync_dir)
    elif os.path.isdir(sync_dir) and len([f for f in os.listdir(sync_dir)]) != 0:
      L.error("Sync directory exists and is not empty. Exiting.")
      sys.exit(1)


  @staticmethod
  def _init_fuzzers(ret_all=False):
    """
    Initialize a pre-defined ensemble of fuzzer objects. Return all subcasses if
    param is set.

    Default fuzzer ensemble (four cores):
        afl,honggfuzz,angora,eclipser

    """
    if ret_all:
      return [subclass() for subclass in FuzzerFrontend.__subclasses__()]
    else:
      return [
        AFL(envvar="AFL_HOME"), 
        Honggfuzz(envvar="HONGGFUZZ_HOME"),
        Angora(envvar="ANGORA_HOME"),
        Eclipser(envvar="ECLIPSER_HOME")
      ]


  def _get_tests(self, tests):
    """
    Given a workspace path, retrieve testcases and map to specific fuzzer. We map
    based on the condition that the generated test binary contains an extension
    denoting the fuzzer name.

    :param tests: list of paths to workspace with already-compiled target binaries
    """

    def _get_fuzzer(test):
      ext = test.split(".")[-1]
      if ext in ["fast", "taint"]:
        return "angora"
      elif ext == "hfuzz":
        return "honggfuzz"
      return ext.lower()

    fuzz_map = defaultdict(list)
    for test in tests:
      for fuzzer in self.fuzzers:
        if str(fuzzer).lower() == _get_fuzzer(test):
          fuzz_map[fuzzer].append(test)

    L.debug("Fuzzer and corresponding test cases: %s", fuzz_map)
    return fuzz_map


  def provision(self):
    """
    Initializes our ensemble of fuzzers, and creates a workspace with instrumented
    harness binaries, if necessary.
    """

    # manually call pre_exec (we don't use frontend's runner routine) before provisioning
    self.pre_exec()

    # initialize target - test str if user specified a harness, or a list to already-compiled binaries
    target = self.test if not self.test_dir else list([f for f in os.listdir(self.test_dir)])
    L.info("Provisioning environment with target `%s`", target)

    self.fuzzers = list(self._init_fuzzers())
    L.debug("Fuzzers for ensembling: %s", self.fuzzers)

    # given a path to a DeepState harness, provision/compile, and retrieve test bins
    if isinstance(target, str):
      L.info("Detected source target. Compiling and then retrieving harnesses from workspace.")
      self.targets = self._get_tests(self._provision_workspace(target))

    # given a list of paths from a workspace, instantiate normally
    elif isinstance(target, list):
      L.info("Detected workspace target. Retrieving harnesses from workspace.")
      self.targets = self._get_tests(target)

    L.debug("Target for analysis: %s", self.targets)


  def _provision_workspace(self, test_case):
    """
    Given a testcase source, provision a workspace with appropriate target binaries.

    :param test_case: path to uncompiled test case directory
    """
    if not os.path.isdir(self.workspace):
      L.info("Workspace doesn't exist. Creating.")
      os.mkdir(self.workspace)

    L.info("Provisioning test case into workspace with instrumented binaries")
    for fuzzer in self.fuzzers:

      test_name = self.workspace + "/" + test_case.split(".")[0]
      L.debug("Compiling `%s` for fuzzer `%s`", test_name, fuzzer)

      cmd_map = {
        "compile_test": test_case,
        "out_test_name": test_name,
        "compiler_args": self.compiler_args if self.compiler_args else None
      }

      if isinstance(fuzzer, Angora):
        cmd_map["mode"] = "llvm"
        cmd_map["ignore_calls"] = self.ignore_calls

      fuzzer.init_from_dict(cmd_map)

      L.info("Compiling test case %s as `%s` with %s", test_case, test_name, fuzzer)
      fuzzer.compile()

    return [test for test in os.listdir(self.workspace)]


  def report(self):
    """
    Global status reporter for ensemble fuzzing. We store and parse each individual
    fuzzers reporter and provide a global output during fuzzer execution.
    """
    while True:

      global_stats = dict()
      for fuzzer in self.fuzzers:
        time.sleep(self.sync_cycle)

        stats = fuzzer.reporter()
        global_stats.update(stats)

      print("\n\n[\tEnsemble Fuzzer Status\t\t]\n")
      for head, stat in global_stats.items():
        print(f"Total {head}\t:\t{stat}")


  def run_ensembler(self):
    """
    Bootstraps all fuzzers for ensembling with appropriate arguments,
    and run fuzzers in parallel.

    TODO(alan): exit_crash arg to kill fuzzer and report when one crash is found
    """

    def _rand_id():
      return "".join(random.choice(string.ascii_uppercase + string.digits)
      for _ in range(4))

    #pool = multiprocessing.Pool(processes=self.num_cores)
    procs = []

    L.info("Initializing fuzzers for ensembling.")

    # for each fuzzer, instantiate fuzzer arguments manually using () rather than
    # the parse_args() interface in each frontend. Specific fuzzers need specific options, so
    # we also set those
    # TODO(alan): migrate instantiation to provision or _provision_workspace
    for fuzzer, binary in self.targets.items():
      fuzzer_args = {

        # default fuzzer execution related options
        "timeout": self.timeout,
        "binary": self.workspace + "/" + binary[0],
        "input_seeds": self.input_seeds,
        "output_test_dir": "{}/{}_{}_out".format(self.output_test_dir, str(fuzzer), _rand_id()),
        "dictionary": None,
        "max_input_size": self.max_input_size if self.max_input_size else 8192,
        "mem_limit": 50,
        "which_test": self.which_test,
        "target_args": self.target_args,

        # set sync options for all fuzzers (TODO): configurable exec cycle
        # set sync_out to output global fuzzer stats, set as default
        "enable_sync": True,
        "sync_cycle": self.sync_cycle,
        "sync_dir": self.sync_dir,
        "sync_out": not self.no_global
      }

      # TODO(alan): store default dict in each fuzzer's _ARGS such that we don't need to
      # manually instantiate fuzzer-specific attributes

      # manually set and override options for Angora, due to the requirement of two binaries
      if isinstance(fuzzer, Angora):
        fuzzer_args.update({
          "binary": next((self.workspace + "/" + b for b in binary if ".fast" in b), None),
          "taint_binary": next((self.workspace + "/" + b for b in binary if ".taint" in b), None),
          "no_afl": False,
          "mode": "llvm",
          "no_exploration": False
        })

      # manually set and override "AFL modes" that configured during execution
      elif isinstance(fuzzer, AFL):
        fuzzer_args.update({
          "parallel_mode": False,
          "dirty_mode": False,
          "dumb_mode": False,
          "qemu_mode": False,
          "crash_explore": False,
          "file": None
        })

      # manually set Honggfuzz options
      elif isinstance(fuzzer, Honggfuzz):
        fuzzer_args.update({
          "iterations": None,
          "persistent": False,
          "no_inst": False,
          "keep_output": False,
          "sanitizers": False,
          "clear_env": False,
          "save_all": True,
          "keep_aslr": False,
          "perf_instr": False,
          "perf_branch": False
        })

      fuzzer.init_from_dict(fuzzer_args)

      # sets compiler and no_exec params before execution
      # Eclipser requires `dotnet` to be invoked before fuzzer executable.
      if isinstance(fuzzer, Eclipser):
        args = ("dotnet", True)
      else:
        args = (None, True)


      L.info("Initialized %s for ensemble-fuzzing and spinning up child proc.", fuzzer)

      # initialize concurrent process and add to process pool
      proc = Process(target=fuzzer.run, args=args)
      procs.append(proc)

    # TODO(alan): fix up delayed reporter; try not to have an individual proc run for
    # reporting
    if not self.no_global:
      L.info("Starting up child proc for global stats reporting.")
      report_proc = Process(target=self.report, args=())
      procs.append(report_proc)

    for proc in procs:
      proc.start()

    # sleep until fuzzers finalize initialization, approx 5 seconds
    time.sleep(5)

    for proc in procs:
      proc.join()


def main():
  ensembler = Ensembler(envvar="PATH")

  # parse arguments and provision ensembler
  ensembler.parse_args()
  ensembler.init_from_dict()
  ensembler.provision()

  # call ensembler routine
  ensembler.run_ensembler()
  return 0


if __name__ == "__main__":
  exit(main())
