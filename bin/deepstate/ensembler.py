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
import importlib
import argparse
import multiprocessing

from collections import defaultdict
from multiprocessing import Process

from .frontend import DeepStateFrontend


# dynamically imports any known subclass of DeepStateFrontend
# TODO(alan): refactor with any safe sanity checks?
for subclass in DeepStateFrontend.__subclasses__():
  __import__(subclass.__module__, globals(), locals(), [subclass.__name__])
  globals().update({subclass.__name__:
                    getattr(sys.modules[subclass.__module__], subclass.__name__)})


L = logging.getLogger("deepstate.ensembler")
L.setLevel(os.environ.get("DEEPSTATE_LOG", "INFO").upper())


class Ensembler:

  def __init__(self, target, seeds, out_dir, out_sync, num_cores, timeout, workspace, \
               compiler_args=None, ignore_list=None):

    self.seeds = os.path.abspath(seeds)
    self.out_dir = os.path.abspath(out_dir)
    self.sync_dir = os.path.abspath(out_sync)
    self.workspace = os.path.abspath(workspace)

    self.num_cores = num_cores
    self.timeout = timeout

    self.fuzzers = list(self._init_fuzzers())
    L.debug(f"Fuzzers for ensembling: {self.fuzzers}")

    # given a path to a DeepState harness, provision/compile, and retrieve test bins
    if type(target) is str:
      self.targets = self.get_tests(self._provision(target, compiler_args))

    # given a list of paths from a workspace, instantiate normally
    elif type(target) is list:
      self.targets = self.get_tests(target)


  def _provision(self, test_case, compiler_args, ignore_list=None):
    """
    Given a testcase source, provision a workspace with appropriate target binaries.

    :param test_case: path to uncompiled test case directory
    :param compiler_args: compilation flags (ie for linking) needed to successfully compile
    :param ignore_list: optional str of static libraries to ignore for taint analysis (see Angora frontend)
    """
    if not os.path.isdir(self.workspace):
      L.info("Workspace doesn't exist. Creating.")
      os.mkdir(self.workspace)

    L.info("Provisioning test case into workspace with instrumented binaries")
    for fuzzer in self.fuzzers:

      test_name = self.workspace + "/" + test_case.split(".")[0]
      L.debug(f"Compiling `{test_name}` for fuzzer `{fuzzer}`")

      cmd_map = {
        "compile_test": test_case,
        "out_test_name": test_name,
        "compiler_args": compiler_args
      }

      if type(fuzzer) is Angora:
        cmd_map["mode"] = "llvm"
        cmd_map["ignore_calls"] = ignore_list

      fuzzer.set_args(cmd_map)
      fuzzer.compile()

    return [test for test in os.listdir(self.workspace)]


  def _init_fuzzers(self):
    """
    Retrieves a list of all fuzzer subclasses.

    TODO(alan): allow human interaction to specify manual fuzzers to use
    """
    return [subclass() for subclass in DeepStateFrontend.__subclasses__()]


  def get_tests(self, tests):
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
      else:
        return ext.lower()

    fuzz_map = defaultdict(list)
    for test in tests:
      for fuzzer in self.fuzzers:
        if str(fuzzer).lower() == _get_fuzzer(test):
          fuzz_map[fuzzer].append(test)

    L.debug(f"Fuzzer and corresponding test cases: {fuzz_map}")
    return fuzz_map


  def report(self):
    """
    Global status reporter for ensemble fuzzing
    """
    while True:

      global_stats = dict()
      for fuzzer in self.fuzzers:
        time.sleep(fuzzer._ARGS.sync_cycle)

        stats = fuzzer.reporter()
        global_stats.update(stats)

      print("\n\n[\tEnsemble Fuzzer Status\t\t]\n")
      for head, stat in global_stats.items():
        print(f"Total {head}\t:\t{stat}")


  def run(self, which_test=None, exit_crash=False, global_reporter=True):
    """
    Bootstraps all fuzzers for ensembling with appropriate arguments,
    and run fuzzers in parallel.

    :param which_test: specifies which test from suite to analyze
    :param exit_crash: if set, kills fuzzers once a singular crash is discovered
    """

    procs = []

    for fuzzer, binary in self.targets.items():
      fuzzer_args = {
        "enable_sync": True,
        "sync_cycle": 3,
        "sync_dir": self.sync_dir,
        "timeout": self.timeout,
        "binary": self.workspace + "/" + binary[0],
        "input_seeds": self.seeds,
        "output_test_dir": "{}/{}_out".format(self.out_dir, str(fuzzer)),
        "args": [],
        "max_input_size": 8192,
        "mem_limit": 50,
        "which_test": which_test,
      }

      if global_reporter:
        fuzzer_args.update({
          "sync_out": False
        })

      if type(fuzzer) is Angora:
        fuzzer_args.update({
          "binary": next((self.workspace + "/" + b for b in binary if ".fast" in b), None),
          "taint_binary": next((self.workspace + "/" + b for b in binary if ".taint" in b), None),
          "no_afl": False,
          "mode": "llvm",
          "no_exploration": False
        })

      elif type(fuzzer) is AFL:
        fuzzer_args.update({
          "parallel_mode": False,
          "dirty_mode": False,
          "dumb_mode": False,
          "qemu_mode": False,
          "crash_explore": False,
          "dictionary": None,
          "file": None
        })


      fuzzer.set_args(fuzzer_args)


      # sets compiler and no_exec params before execution
      if type(fuzzer) is Eclipser:
        args = ("dotnet", True)
      else:
        args = (None, True)

      # initialize concurrent process and add to process pool
      p = Process(target=fuzzer.run, args=args)
      procs.append(p)

    for p in procs:
      p.start()

    time.sleep(10)

    if global_reporter:
      report_proc = Process(target=self.report, args=())
      report_proc.start()
      procs.append(report_proc)

    for p in procs:
      p.join()


  def post_process(self, global_stats=False):
    """
    Perform post-processing for each ensembled fuzzer.

    TODO: global coverage map generation / visualization
    """
    for fuzzer in self.fuzzers:
      if not global_stats:
        if hasattr(fuzzer, "post_exec"):
          fuzzer.post_exec()



def main():
  parser = argparse.ArgumentParser(description="DeepState Ensemble Fuzzer.")
  test_group = parser.add_mutually_exclusive_group(required=True)

  # Mutually exclusive target options
  test_group.add_argument("--test", type=str, \
    help="Path to test case harness for compilation and instrumentation.")

  test_group.add_argument("--test_dir", type=str, \
    help="Path to existing workspace directory with compiled and instrumented binaries.")


  # Compilation options
  parser.add_argument("-a", "--compiler_args", type=str, \
    help="Compiler linker arguments for test harness, if provided as argument")
  parser.add_argument("--ignore_calls", type=str, \
    help="Path to static/shared libraries (colon seperated) for functions to blackbox for taint analysis.")


  # Fuzzer-related in/output paths
  parser.add_argument("-i", "--input_seeds", type=str, required=True, \
    help="Path to directory with initial seed inputs for all fuzzer instances.")

  parser.add_argument("-o", "--out_dir", type=str, default="out", \
    help="Path to output directory for generated fuzzer logs and local queue (default is `out`).")

  parser.add_argument("-s", "--sync_dir", type=str, default="out_sync", \
    help="Path to shared seed synchronization directory (default is `out_sync`).")

  parser.add_argument("-w", "--workspace", type=str, default="ensemble_bins", \
    help="Path to workspace to store compiled and instrumented binaries (default is `ensemble_bins`).")

  # TODO(alan): allow user to manually specify base fuzzers to implement


  # Ensembler execution options
  parser.add_argument("-n", "--num_cores", type=int, default=multiprocessing.cpu_count(), \
    help="Override number of cores to use.")

  parser.add_argument("--which_test", type=str, \
    help="Which test to run (equivalent to --input_which_test).")

  parser.add_argument("-t", "--timeout", type=int, default=360, \
    help="Timeout for ensemble fuzzer in seconds (default: 360).")

  parser.add_argument("--abort_on_crash", action="store_true", \
    help="Stop ensembler when any base fuzzer returns a crash")

  args = parser.parse_args()

  # ignore compiler-related arguments if not necessary
  if args.test_dir and (args.ignore_calls or args.compiler_args):
    L.info("Ignoring --ignore_calls and/or --compiler_args arguments passed")

  # initial path check
  _test = args.test if not args.test_dir else args.test_dir
  if not os.path.exists(_test):
    print(f"Target path `{_test}` does not exist. Exiting.")
    sys.exit(1)

  # initialize target - test str if user specified a harness, or a list to already-compiled binaries
  test = args.test if not args.test_dir else list([f for f in os.listdir(args.test_dir)])

  # initialize test case to run from harness, if specified
  which_test = args.which_test if args.which_test else None

  if not os.path.isdir(args.input_seeds):
    print(f"Input seeds directory `{args.input_seeds}` does not exist. Exiting.")
    sys.exit(1)

  if not os.path.isdir(args.out_dir):
    print("Output directory does not exist. Creating.")
    os.mkdir(args.out_dir)

  if not os.path.isdir(args.sync_dir):
    print("Sync directory does not exist. Creating.")
    os.mkdir(args.sync_dir)
  elif os.path.isdir(args.sync_dir) and len([f for f in os.listdir(args.sync_dir)]) != 0:
    print("Sync directory exists and is not empty. Exiting.")
    sys.exit(1)


  # initialize ensembler
  ensembler = Ensembler(test, args.input_seeds, args.out_dir, args.sync_dir,
                        args.num_cores, args.timeout, args.workspace,
                        args.compiler_args, args.ignore_calls)

  ensembler.run(which_test, args.abort_on_crash)
  ensembler.post_process()
  return 0


if __name__ == "__main__":
  exit(main())
