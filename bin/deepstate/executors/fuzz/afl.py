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

from typing import List, Dict, Optional

from deepstate.core import FuzzerFrontend, FuzzFrontendError


L = logging.getLogger(__name__)


class AFL(FuzzerFrontend):
  """ Defines AFL fuzzer frontend """

  NAME = "AFL"
  EXECUTABLES = {"FUZZER": "afl-fuzz",
                  "COMPILER": "afl-clang++"
                  }

  @classmethod
  def parse_args(cls) -> None:
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
      description=f"Use AFL as a backend for DeepState")

    cls.parser = parser
    super(AFL, cls).parse_args()


  def compile(self) -> None: # type: ignore
    lib_path: str = "/usr/local/lib/libdeepstate_AFL.a"

    flags: List[str] = list()
    if self.compiler_args:
      flags += [arg for arg in self.compiler_args.split(" ")]
    flags.append("-ldeepstate_AFL")

    super().compile(lib_path, flags, self.out_test_name)


  def pre_exec(self):
    """
    Perform argparse and environment-related sanity checks.
    """
    # check for afl-qemu-trace if in QEMU mode 
    if 'Q' in self.fuzzer_args or self.blackbox == True:
      self.EXECUTABLES["AFL-QEMU-TRACE"] = "afl-qemu-trace"

    super().pre_exec()

    # check if core dump pattern is set as `core`
    with open("/proc/sys/kernel/core_pattern") as f:
      if not "core" in f.read():
        raise FuzzFrontendError("No core dump pattern set. Execute 'echo core | sudo tee /proc/sys/kernel/core_pattern'")

    # check if CPU scaling governor is set to `performance`
    with open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor") as f:
      if not "perf" in f.read(4):
        with open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_min_freq") as f_min:
          with open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq") as f_max:
            if f_min.read() != f_max.read():
              raise FuzzFrontendError("Suboptimal CPU scaling governor. Execute 'echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor'")

    # set input/output variables
    # if we aren't in dumb mode, or we are using crash mode
    if 'n' not in self.fuzzer_args or 'C' in self.fuzzer_args:
      self.require_seeds = True

    sync_dir = os.path.join(self.output_test_dir, "sync_dir")
    main_dir = os.path.join(self.output_test_dir, "the_fuzzer")
    self.push_dir = os.path.join(sync_dir, "queue")
    self.pull_dir = os.path.join(main_dir, "queue")
    self.crash_dir = os.path.join(main_dir, "crashes")

    # resume fuzzing
    if len(os.listdir(self.output_test_dir)) > 1:
      self.check_required_directories([self.push_dir, self.pull_dir, self.crash_dir])
      self.input_seeds = '-'
      L.info(f"Resuming fuzzing using seeds from {self.pull_dir} (skipping --input_seeds option).")
    else:
      self.setup_new_session([self.push_dir])


  @property
  def cmd(self):
    cmd_list: List[str] = list()

    # guaranteed arguments
    cmd_list.extend([
      "-o", self.output_test_dir,  # auto-create, reusable
      "-M", "the_fuzzer"  # TODO, detect when to use -S
    ])  

    if self.mem_limit == 0:
      cmd_list.extend(["-m", "1099511627776"])  # use 1TiB as unlimited
    else:
      cmd_list.extend(["-m", str(self.mem_limit)])

    for key, val in self.fuzzer_args:
      if len(key) == 1:
        cmd_list.append('-{}'.format(key))
      else:
        cmd_list.append('--{}'.format(key))
      if val is not None:
        cmd_list.append(val)

    # QEMU mode
    if self.blackbox == True:
      cmd_list.append('-Q')

    # optional arguments:
    # required, if provided: not auto-create and require any file inside
    if self.input_seeds:
      cmd_list.extend(["-i", self.input_seeds])

    if self.exec_timeout:
      cmd_list.extend(["-t", str(self.exec_timeout)])

    if self.dictionary:
      cmd_list.extend(["-x", self.dictionary])

    return self.build_cmd(cmd_list)


  def populate_stats(self):
    """
    Retrieves and parses the stats file produced by AFL
    """
    stat_file_path: str = os.path.join(self.output_test_dir, "the_fuzzer", "fuzzer_stats")
    with open(stat_file_path, "r") as stat_file:
      for line in stat_file:
        key = line.split(":", 1)[0].strip()
        value = line.split(":", 1)[1].strip()
        if key in self.stats:
          self.stats[key] = value


  def reporter(self) -> Dict[str, Optional[str]]:
    """
    Report a summarized version of statistics, ideal for ensembler output.
    """
    self.populate_stats()
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
    # TODO: merge output_test_dir/the_fuzzer/crashes* into one dir
    if self.post_stats:
      print(f"\n{self.name} RUN STATS:\n")
      for stat, val in self.stats.items():
        fstat: str = stat.replace("_", " ").upper()
        print(f"{fstat}:\t\t\t{val}")


def main():
  fuzzer = AFL(envvar="AFL_HOME")
  return fuzzer.main()


if __name__ == "__main__":
  exit(main())
