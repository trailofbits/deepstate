#!/usr/bin/env python
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
import json
import logging
import argparse
import subprocess
import time

from typing import List, Dict, Optional, Any

from deepstate.core import FuzzerFrontend, FuzzFrontendError


L = logging.getLogger(__name__)


class Angora(FuzzerFrontend):

  # these classvars are set under the assumption that $ANGORA_PATH is set to the built source
  NAME = "Angora"
  SEARCH_DIRS = ["clang+llvm/bin", "bin", "tools"]
  EXECUTABLES = {"FUZZER": "angora_fuzzer",
                  "COMPILER": "angora-clang++",
                  "GEN_LIB_ABILIST": "gen_library_abilist.sh",
                  "CLANG_COMPILER": "clang++"
                  }

  ENVVAR = "ANGORA_HOME"
  REQUIRE_SEEDS = True

  PUSH_DIR = os.path.join("sync_dir", "queue")
  PULL_DIR = os.path.join("angora", "queue")
  CRASH_DIR = os.path.join("angora", "crashes")


  @classmethod
  def parse_args(cls) -> None:
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
      description="Use Angora as a backend for DeepState.")

    # Other compilation arguments
    compile_group = parser.add_argument_group("compilation and instrumentation arguments")
    compile_group.add_argument("--ignore_calls", type=str,
      help="Path to static/shared libraries (colon seperated) for functions to skip (blackbox) for taint analysis.")

    # Angora-specific test execution options
    parser.add_argument("taint_binary", nargs="?", type=str,
      help="Path to binary compiled with taint tracking.")

    cls.parser = parser
    super(Angora, cls).parse_args()


  def compile(self) -> None: # type: ignore
    """
    Compilation interface provides extra support for generating taint policy for
    blacklisted ABI calls with DFsan.
    """

    env: Dict[str, str] = os.environ.copy()

    # generate ignored functions output for taint tracking
    # set envvar to file with ignored lib functions for taint tracking
    if self.ignore_calls: # type: ignore

      libpath: List[str] = self.ignore_calls.split(":") # type: ignore
      L.debug("Ignoring library objects: %s", libpath)

      out_file: str = "abilist.txt"

      # TODO(alan): more robust library check
      ignore_bufs: List[bytes] = []
      for path in libpath:
        if not os.path.isfile(path):
          raise FuzzFrontendError(f"Library `{path}` to skip (blackbox) is not a valid library path.")

        # instantiate command to call, but store output to buffer
        cmd: List[str] = [self.EXECUTABLES["GEN_LIB_ABILIST"], path, "discard"]
        L.debug("Compilation command: %s", cmd)

        out: bytes = subprocess.check_output(cmd)
        ignore_bufs += [out]

      # write all to final out_file
      with open(out_file, "wb") as f:
        for buf in ignore_bufs:
          f.write(buf)

      # set envvar for fuzzer compilers
      env["ANGORA_TAINT_RULE_LIST"] = os.path.abspath(out_file)

    # make a binary with taint tracking information
    # env["USE_PIN"] = "1"  # TODO, add pin support
    env["USE_TRACK"] = "1"

    taint_path: str = "/usr/local/lib/libdeepstate_taint.a"
    L.debug("Static library path: %s", taint_path)

    taint_flags: List[str] = ["-ldeepstate_taint"]
    if self.compiler_args:
      taint_flags += [arg for arg in self.compiler_args.split(' ')]
    L.info("Compiling %s for %s with taint tracking", self.compile_test, self.name)
    super().compile(taint_path, taint_flags, self.out_test_name + ".taint", env=env)

    self.taint_binary = self.binary
    self.binary = None
    env.pop("USE_TRACK")

    # make a binary with light instrumentation
    env["USE_FAST"] = "1"

    fast_path: str = "/usr/local/lib/libdeepstate_fast.a"
    L.debug("Static library path: %s", fast_path)

    fast_flags: List[str] = ["-ldeepstate_fast"]
    if self.compiler_args:
      fast_flags += [arg for arg in self.compiler_args.split(" ")]
    L.info("Compiling %s for %s with light instrumentation.", self.compile_test, self.name)
    super().compile(fast_path, fast_flags, self.out_test_name + ".fast", env=env)


  def pre_exec(self):
    # correct version of clang is required
    self._set_executables()
    clang_for_angora_path = os.path.dirname(self.EXECUTABLES["CLANG_COMPILER"])
    os.environ["PATH"] = ":".join((clang_for_angora_path, os.environ.get("PATH", "")))
    L.info(f"Adding `{clang_for_angora_path}` to $PATH.")

    super().pre_exec()

    # since base method checks for self.binary by default
    if not self.taint_binary:
      self.parser.print_help()
      raise FuzzFrontendError(f"Must provide taint binary for {self.name}.")

    if not os.path.exists(self.taint_binary):
      raise FuzzFrontendError("Taint binary doesn't exist")

    # resume fuzzing
    if len(os.listdir(self.output_test_dir)) > 1:
      self.check_required_directories([self.push_dir, self.pull_dir, self.crash_dir])
      self.input_seeds = '-'
      L.info(f"Resuming fuzzing using seeds from {self.pull_dir} (skipping --input_seeds option).")
    else:
      self.setup_new_session([self.push_dir])

    if self.blackbox is True:
      raise FuzzFrontendError(f"Blackbox fuzzing is not supported by {self.name}.")

    if self.dictionary:
      L.error("%s can't use dictionaries.", self.name)


  @property
  def cmd(self):
    cmd_list: List[str] = list()

    # guaranteed arguments
    cmd_list.extend([
      "--mode", "llvm",  # TODO, add pin support
      "--track", os.path.abspath(self.taint_binary),
      "--memory_limit", str(self.mem_limit),
      "--output", self.output_test_dir,  # auto-create, not reusable
      "--sync_afl"
    ])

    for key, val in self.fuzzer_args:
      if len(key) == 1:
        cmd_list.append('-{}'.format(key))
      else:
        cmd_list.append('--{}'.format(key))
      if val is not None:
        cmd_list.append(val)

    # optional arguments:
    # required, if provided: not auto-create and require any file inside
    if self.input_seeds:
      cmd_list.extend(["--input", self.input_seeds])

    if self.exec_timeout:
      cmd_list.extend(["--time_limit", str(self.exec_timeout / 1000)])

    # autodetect
    cmd_list.append("--disable_exploitation")

    return self.build_cmd(cmd_list)


  def populate_stats(self):
    """
    Parses Angora output JSON config to dict for reporting.
    """
    super().populate_stats()

    stat_file_path: str = os.path.join(self.output_test_dir, "angora", "fuzzer_stats")
    try:
      with open(stat_file_path, "r") as stat_file:
        self.stats["fuzzer_pid"] = stat_file.read().split(":", 1)[1].strip()
    except:
      pass

    stat_file_path = os.path.join(self.output_test_dir, "angora", "chart_stat.json")
    new_stats: Dict[str, str] = {}
    try:
      with open(stat_file_path, "r") as stat_file:
        new_stats = json.loads(stat_file.read())
    except json.decoder.JSONDecodeError as e:
      L.error(f"Error parsing {stat_file_path}: {e}.")
    except:
      return

    # previous_stats = self.stats.copy()

    if new_stats.get("init_time"):
      self.stats["start_time"] = str(int(time.time() - int(new_stats.get("init_time"))))
    elif self.proc:
      self.stats["start_time"] = str(int(self.start_time))

    self.stats["last_update"] = str(int(os.path.getmtime(stat_file_path)))

    self.stats["execs_done"] = new_stats.get("num_exec", 0)
    self.stats["execs_per_sec"] = new_stats.get("speed", [0])[0]
    self.stats["paths_total"] = new_stats.get("num_inputs", 0)

    if new_stats.get("num_crashes"):
      self.stats["unique_crashes"] = new_stats.get("num_crashes")
    self.stats["unique_hangs"] = new_stats.get("num_hangs", 0)

    # all_fuzz = []
    # for one_fuzz in new_stats.get("fuzz", []):
    #   time_key = one_fuzz.pop("time", {})
    #   s = time_key.get("secs", 0)
    #   ns = time_key.get("nanos", 0)
    #   t = float('{}.{:09d}'.format(s, ns))
    #   all_fuzz.append((t, one_fuzz))
    # all_fuzz = sorted(all_fuzz, key=operator.itemgetter(0), reverse=True)

    # if len(all_fuzz) >= 2:
    #   last_crash_execs = 0
    #   for one_fuzz in all_fuzz:
    #     if one_fuzz.get("num_crashes") < self.stats["unique_crashes"]:
    #       last_crash_execs = one_fuzz["num_exec"]
    #   self.stats["execs_since_crash"] = self.stats["execs_done"] - last_crash_execs

    # self.stats["command_line"] = self.command


  def reporter(self) -> Optional[Dict[str, Any]]:

    # included to silence mypy error
    if self.stats is None:
      return None

    return dict({
      "Execs Done": self.stats["num_exec"],
      "Unique Crashes": self.stats["num_crashes"],
      "Unique Hangs": self.stats["num_hangs"],
    })


  def post_exec(self):
    pass


def main():
  fuzzer = Angora()
  return fuzzer.main()


if __name__ == "__main__":
  exit(main())
