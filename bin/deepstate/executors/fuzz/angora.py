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

from typing import ClassVar, List, Dict, Optional, Any

from deepstate.core import FuzzerFrontend, FuzzFrontendError


L = logging.getLogger("deepstate.frontend.angora")
L.setLevel(os.environ.get("DEEPSTATE_LOG", "INFO").upper())


class Angora(FuzzerFrontend):

  # these classvars are set under the assumption that $ANGORA_PATH is set to the built source
  NAME: ClassVar[str] = "angora_fuzzer"
  COMPILER: ClassVar[str] = "bin/angora-clang++"


  @classmethod
  def parse_args(cls) -> None:
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
      description="Use Angora as a backend for DeepState.")

    # Other compilation arguments
    compile_group = parser.add_argument_group("compilation and instrumentation arguments")
    compile_group.add_argument("--ignore_calls", type=str,
      help="Path to static/shared libraries (colon seperated) for functions to blackbox for taint analysis.")


    # Angora-specific test execution options
    parser.add_argument("taint_binary", nargs="?", type=str,
      help="Path to binary compiled with taint tracking.")

    parser.add_argument("--mode", type=str, default="llvm", choices=["llvm", "pin"],
      help="Specifies binary instrumentation framework used (either llvm or pin).")

    parser.add_argument("--no_afl", action='store_true',
      help="Disables AFL mutation strategies being used.")

    parser.add_argument("--no_exploration", action='store_true',
      help="Disables context-sensitive input bytes mutation.")

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

      libpath: List[str] = [path for path in self.ignore_calls.split(":")] # type: ignore
      L.debug(f"Ignoring library objects: {libpath}")

      out_file: str = "abilist.txt"

      # TODO(alan): more robust library check
      ignore_bufs: List[bytes] = []
      for path in libpath:
        if not os.path.isfile(path):
          raise FuzzFrontendError(f"Library `{path}` to blackbox was not a valid library path.")

        # instantiate command to call, but store output to buffer
        cmd: List[str] = [self.env + "/tools/gen_library_abilist.sh", path, "discard"]
        L.debug(f"Compilation command: {cmd}")

        out: bytes = subprocess.check_output(cmd)
        ignore_bufs += [out]


      # write all to final out_file
      with open(out_file, "wb") as f:
        for buf in ignore_bufs:
          f.write(buf)

      # set envvar for fuzzer compilers
      env["ANGORA_TAINT_RULE_LIST"] = os.path.abspath(out_file)


    # make a binary with light instrumentation
    fast_path: str = "/usr/local/lib/libdeepstate_fast.a"
    L.debug(f"Static library path: {fast_path}")

    fast_flags: List[str] = ["-ldeepstate_fast"]
    if self.compiler_args:
      fast_flags += [arg for arg in self.compiler_args.split(" ")]
    L.info(f"Compiling {self.compile_test} for Angora with light instrumentation")
    super().compile(fast_path, fast_flags, self.out_test_name + ".fast", env=env)

    # initialize envvar for instrumentation framework
    if self.mode == "pin": # type: ignore
      env["USE_PIN"] = "1"
    else:
      env["USE_TRACK"] = "1"

    # make a binary with taint tracking information
    taint_path: str = "/usr/local/lib/libdeepstate_taint.a"
    L.debug(f"Static library path: {taint_path}")

    taint_flags: List[str] = ["-ldeepstate_taint"]
    if self.compiler_args:
      taint_flags += [arg for arg in self.compiler_args.split(' ')]
    L.info(f"Compiling {self.compile_test} for Angora with taint tracking")
    super().compile(taint_path, taint_flags, self.out_test_name + ".taint", env=env)


  def pre_exec(self):
    super().pre_exec()

    # since base method checks for self.binary by default
    if not self.taint_binary:
      self.parser.print_help()
      raise FuzzFrontendError("Must provide taint binary for Angora.")

    if not self.input_seeds:
      raise FuzzFrontendError("Must provide -i/--input_seeds option for Angora.")

    seeds: str = os.path.abspath(self.input_seeds)
    L.debug(f"Seed path: {seeds}")

    if not os.path.exists(seeds):
      os.mkdir(seeds)
      raise FuzzFrontendError("Seed path doesn't exist. Creating empty seed directory and exiting.")

    if len([name for name in os.listdir(seeds)]) == 0:
      raise FuzzFrontendError(f"No seeds present in directory {seeds}")

    if os.path.exists(self.output_test_dir):
      raise FuzzFrontendError(f"Remove previous `{self.output_test_dir}` output directory before running Angora.")


  @property
  def cmd(self):
    cmd_dict = {
      "--mode": self.mode,
      "--input": self.input_seeds,
      "--output": self.output_test_dir,
      "--track": os.path.abspath(self.taint_binary),
    }

    # check for indefinite run
    if self.timeout != 0:
      cmd_dict["--time_limit"] = str(self.timeout)

    # execution options
    if self.no_afl:
      cmd_dict["--disable_afl_mutation"] = None
    if self.no_exploration:
      cmd_dict["--disable_exploitation"] = None

    return self.build_cmd(cmd_dict)


  @property
  def stats(self) -> Optional[Dict[str, str]]:
    """
    Parses Angora output JSON config to dict for reporting.
    """
    stat_file: str = self.output_test_dir + "/chart_stat.json"

    if not hasattr(self, "prev_stats"):
      self.prev_stats: Optional[Dict[str, str]] = None

    try:
      with open(stat_file, "r") as handle:
        stats: Optional[Dict[str, str]] = json.loads(handle.read())
        self.prev_stats = stats

    # fallback on initially parsed stats if failed to decode
    except json.decoder.JSONDecodeError:
      stats = self.prev_stats

    return stats


  def reporter(self) -> Optional[Dict[str, Any]]:

    # included to silence mypy error
    if self.stats is None:
      return None

    return dict({
      "Execs Done": self.stats["num_exec"],
      "Unique Crashes": self.stats["num_crashes"],
      "Unique Hangs": self.stats["num_hangs"],
    })


def main():
  fuzzer = Angora(envvar="ANGORA")
  return fuzzer.main()


if __name__ == "__main__":
  exit(main())
