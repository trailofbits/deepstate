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
import logging
import argparse

from typing import ClassVar, List, Dict, Any, Optional

from deepstate.core import FuzzerFrontend, FuzzFrontendError
from deepstate.core.base import AnalysisBackend


L = logging.getLogger("deepstate.frontend.afl")
L.setLevel(os.environ.get("DEEPSTATE_LOG", "INFO").upper())


class AFL(FuzzerFrontend):
  """ Defines AFL fuzzer frontend """

  NAME: ClassVar[str] = "afl-fuzz"
  COMPILER: ClassVar[str] = "afl-clang++"


  @classmethod
  def parse_args(cls) -> None:
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
      description="Use AFL as a backend for DeepState")

    # Execution options
    parser.add_argument("--dictionary", type=str,
      help="Optional fuzzer dictionary for AFL.")

    parser.add_argument("--run_timeout", type=int, default=50,
      help="Timeout for each instance of a run in ms (default is 50ms).")

    parser.add_argument("--mem_limit", type=int, default=50,
      help="Child process memory limit in MB (default is 50).")

    parser.add_argument("--file", type=str,
      help="Input file read by fuzzed program, if any.")


    # AFL execution modes
    parser.add_argument("--dirty_mode", action="store_true",
      help="Fuzz without deterministic steps.")

    parser.add_argument("--dumb_mode", action="store_true",
      help="Fuzz without instrumentation.")

    parser.add_argument("--qemu_mode", action="store_true",
      help="Fuzz with QEMU mode.")

    parser.add_argument("--crash_explore", action="store_true",
      help="Fuzz with crash exploration.")

    cls.parser = parser
    super(AFL, cls).parse_args()


  def compile(self) -> None: # type: ignore
    lib_path: str = "/usr/local/lib/libdeepstate_AFL.a"

    flags: List[str] = list()
    if self.compiler_args:
      flags += [arg for arg in self.compiler_args.split(" ")]
    flags.append("-ldeepstate_AFL")

    super().compile(lib_path, flags, self.out_test_name + ".afl")


  def pre_exec(self):
    """
    Perform argparse and environment-related sanity checks.
    """

    # check if core dump pattern is set as `core`
    with open("/proc/sys/kernel/core_pattern") as f:
      if not "core" in f.read():
        raise FuzzFrontendError("No core dump pattern set. Execute 'echo core | sudo tee /proc/sys/kernel/core_pattern'")

    with open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor") as f:
      if not "perf" in f.read(4):
        with open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_min_freq") as f_min:
          with open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq") as f_max:
            if f_min.read() != f_max.read():
              raise FuzzFrontendError("Suboptimal CPU scaling governor. Execute 'echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor'")

    super().pre_exec()

    # require input seeds if we aren't in dumb mode, or we are using crash mode
    if not self.dumb_mode or self.crash_mode:
      if self.input_seeds is None:
        raise FuzzFrontendError("Must provide -i/--input_seeds option for AFL.")

      seeds: str = self.input_seeds
      L.debug(f"Fuzzing with seed directory: {seeds}.")

      # AFL uses "-" to tell it to resume fuzzing, don't treat as a real seed dir
      if seeds != "-":
        # check if seeds dir exists
        if not os.path.exists(seeds):
          os.mkdir(seeds)
          raise FuzzFrontendError("Seed path doesn't exist. Creating empty seed directory and exiting.")

        # check if seeds dir is empty
        if len([name for name in os.listdir(seeds)]) == 0:
          raise FuzzFrontendError(f"No seeds present in directory {seeds}.")


  @property
  def cmd(self):
    cmd_dict = {
      "-o": self.output_test_dir,
      "-m": str(self.mem_limit)
    }

    # since this is optional for AFL's dumb fuzzing
    if self.input_seeds:
      cmd_dict["-i"] = self.input_seeds

    # AFL's timeout affects run cycle rather than the whole process
    if self.run_timeout:
      cmd_dict["-t"] = str(self.run_timeout)

    # check if we are using one of AFL's many "modes"
    if self.dirty_mode:
      cmd_dict["-d"] = None
    if self.dumb_mode:
      cmd_dict["-n"] = None
    if self.qemu_mode:
      cmd_dict["-Q"] = None
    if self.crash_explore:
      cmd_dict["-C"] = None

    # other misc arguments
    if self.dictionary:
      cmd_dict["-x"] = self.dictionary
    if self.file:
      cmd_dict["-f"] = self.file

    return self.build_cmd(cmd_dict)


  @property
  def stats(self) -> Dict[str, Optional[str]]:
    """
    Retrieves and parses the stats file produced by AFL
    """
    stat_file: str = self.output_test_dir + "/fuzzer_stats"
    with open(stat_file, "r") as sf:
      lines = sf.readlines()

    stats: Dict[str, Optional[str]] = {
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


  def reporter(self) -> Dict[str, Optional[str]]:
    """
    Report a summarized version of statistics, ideal for ensembler output.
    """
    return dict({
        "Execs Done": self.stats["execs_done"],
        "Cycle Completed": self.stats["cycles_done"],
        "Unique Crashes": self.stats["unique_crashes"],
        "Unique Hangs": self.stats["unique_hangs"],
    })


  def _sync_seeds(self, mode, src, dest, excludes=["*.cur_input"]) -> None:
    super()._sync_seeds(mode, src, dest, excludes=excludes)


  def post_exec(self) -> None:
    """
    AFL post_exec outputs last updated fuzzer stats,
    and (TODO) performs crash triaging with seeds from
    both sync_dir and local queue.
    """
    if self.post_stats:
      print("\nAFL RUN STATS:\n")
      for stat, val in self.stats.items():
        fstat: str = stat.replace("_", " ").upper()
        print(f"{fstat}:\t\t\t{val}")



def main():
  fuzzer = AFL()

  # parse user arguments and build object
  fuzzer.parse_args()

  # run fuzzer with parsed attributes
  fuzzer.run()
  return 0


if __name__ == "__main__":
  exit(main())
