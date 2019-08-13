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
import sys
import logging
import argparse

from .frontend import DeepStateFrontend, FrontendError


L = logging.getLogger("deepstate.frontend.afl")
L.setLevel(os.environ.get("DEEPSTATE_LOG", "INFO").upper())


class AFL(DeepStateFrontend):
  """ Defines default AFL fuzzer frontend """

  FUZZER = "afl-fuzz"
  COMPILER = "afl-clang++"

  @classmethod
  def parse_args(cls):
    parser = argparse.ArgumentParser(description="Use AFL as a backend for DeepState")

    # Execution options
    parser.add_argument("--dictionary", type=str, help="Optional fuzzer dictionary for AFL.")
    parser.add_argument("--mem_limit", type=int, default=50, help="Child process memory limit in MB (default is 50).")
    parser.add_argument("--file", type=str, help="Input file read by fuzzed program, if any.")

    # AFL execution modes
    parser.add_argument("--dirty_mode", action="store_true", help="Fuzz without deterministic steps.")
    parser.add_argument("--dumb_mode", action="store_true", help="Fuzz without instrumentation.")
    parser.add_argument("--qemu_mode", action="store_true", help="Fuzz with QEMU mode.")
    parser.add_argument("--crash_explore", action="store_true", help="Fuzz with crash exploration.")

    # Misc. post-processing
    parser.add_argument("--post_stats", action="store_true", help="Output post-fuzzing stats.")

    cls.parser = parser
    return super(AFL, cls).parse_args()


  def compile(self):
    args = self._ARGS

    lib_path = "/usr/local/lib/libdeepstate_AFL.a"
    L.debug(f"Static library path: {lib_path}")

    if not os.path.isfile(lib_path):
      raise FrontendError("no AFL-instrumented DeepState static library found in {}".format(lib_path))

    flags = ["-ldeepstate_AFL"]
    if args.compiler_args:
      flags += [arg for arg in args.compiler_args.split(" ")]

    compiler_args = ["-std=c++11", args.compile_test] + flags + \
                    ["-o", args.out_test_name + ".afl"]
    super().compile(compiler_args)


  def pre_exec(self):
    """
    Perform argparse and environment-related sanity checks.
    """

    # check if core dump pattern is set as `core`
    with open("/proc/sys/kernel/core_pattern") as f:
      if not "core" in f.read():
        raise FrontendError("No core dump pattern set. Execute 'echo core | sudo tee /proc/sys/kernel/core_pattern'")

    super().pre_exec()

    args = self._ARGS

    # require input seeds if we aren't in dumb mode, or we are using crash mode
    if not args.dumb_mode or args.crash_mode:
      if not args.input_seeds:
        raise FrontendError("Must provide -i/--input_seeds option for AFL.")

      seeds = args.input_seeds

      # check if seeds dir exists
      if not os.path.exists(seeds):
        os.mkdir(seeds)
        raise FrontendError("Seed path doesn't exist. Creating empty seed directory and exiting.")

      # check if seeds dir is empty
      if len([name for name in os.listdir(seeds)]) == 0:
        raise FrontendError(f"No seeds present in directory {seeds}.")


  @property
  def cmd(self):
    args = self._ARGS

    cmd_dict = {
      "-o": args.output_test_dir,
      "-t": str(args.timeout),
      "-m": str(args.mem_limit)
    }

    # since this is optional for AFL's dumb fuzzing
    if args.input_seeds:
      cmd_dict["-i"] = args.input_seeds

    # check if we are using one of AFL's many "modes"
    if args.dirty_mode:
      cmd_dict["-d"] = None
    if args.dumb_mode:
      cmd_dict["-n"] = None
    if args.qemu_mode:
      cmd_dict["-Q"] = None
    if args.crash_explore:
      cmd_dict["-C"] = None

    # other misc arguments
    if args.dictionary:
      cmd_dict["-x"] = args.dictionary
    if args.file:
      cmd_dict["-f"] = args.file

    cmd_dict['--'] = args.binary

    # if not specified, set DeepState flags to help AFL coverage
    if len(args.args) == 0:
      cmd_dict["--input_test_file"] = "@@"
      cmd_dict["--abort_on_fail"] = None
      cmd_dict["--no_fork"] = None

    if args.which_test:
      cmd_dict["--input_which_test"] = args.which_test

    return cmd_dict


  @property
  def stats(self):
    """
    Retrieves and parses the stats file produced by AFL
    """
    args = self._ARGS
    stat_file = args.output_test_dir + "/fuzzer_stats"
    with open(stat_file, "r") as sf:
      lines = sf.readlines()

    stats = {
      "last_update": None,
      "start_time": None,
      "fuzzer_pid": None,
      "cycles_done": None,
      "execs_done": None,
      "execs_per_sec": None,
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
      "unique_crashes": None,
      "unique_hangs": None,
      "last_path": None,
      "last_crash": None,
      "last_hang": None,
      "execs_since_crash": None,
      "exec_timeout": None,
      "afl_banner": None,
      "afl_version": None,
      "command_line": None
    }

    for l in lines:
      for k in stats.keys():
        if k in l:
          stats[k] = l[19:].strip(": %\r\n")
    return stats


  def reporter(self):
    return dict({
        "Execs Done": self.stats["execs_done"],
        "Cycle Completed": self.stats["cycles_done"],
        "Unique Crashes": self.stats["unique_crashes"],
        "Unique Hangs": self.stats["unique_hangs"],
    })


  def _sync_seeds(self, mode, src, dest, excludes=["*.cur_input"]):
    super()._sync_seeds(mode, src, dest, excludes=excludes)


  def post_exec(self):
    """
    AFL post_exec outputs last updated fuzzer stats,
    and (TODO) performs crash triaging with seeds from
    both sync_dir and local queue.
    """
    args = self._ARGS

    if args.post_stats:
      print("\nAFL RUN STATS:\n")
      for stat, val in self.stats.items():
        fstat = stat.replace("_", " ").upper()
        print(f"{fstat}:\t\t\t{val}")



def main():
  fuzzer = AFL()
  fuzzer.parse_args()
  fuzzer.run()
  return 0


if __name__ == "__main__":
  exit(main())
