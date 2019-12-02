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

from deepstate.core import FuzzerFrontend, FuzzFrontendError

L = logging.getLogger("deepstate.frontend.angora")
L.setLevel(os.environ.get("DEEPSTATE_LOG", "INFO").upper())


class Angora(FuzzerFrontend):

  NAME = "angora_fuzzer"
  COMPILER = "bin/angora-clang++"

  @classmethod
  def parse_args(cls):
    parser = argparse.ArgumentParser(description="Use Angora as a backend for DeepState.")

    compile_group = parser.add_argument_group("compilation and instrumentation arguments")
    compile_group.add_argument("--ignore_calls", type=str, help="Path to static/shared libraries (colon seperated) for functions to blackbox for taint analysis.")

    parser.add_argument("taint_binary", nargs="?", type=str, help="Path to binary compiled with taint tracking.")
    parser.add_argument("--mode", type=str, default="llvm", choices=["llvm", "pin"], help="Specifies binary instrumentation framework used (either llvm or pin).")
    parser.add_argument("--no_afl", action='store_true', help="Disables AFL mutation strategies being used.")
    parser.add_argument("--no_exploration", action='store_true', help="Disables context-sensitive input bytes mutation.")

    cls.parser = parser
    return super(Angora, cls).parse_args()


  def compile(self):
    env = os.environ.copy()

    # check if static libraries exist
    lib_path = "/usr/local/lib/"
    L.debug(f"Static library path: {lib_path}")

    if not os.path.isfile(lib_path + "libdeepstate_fast.a"):
      raise RuntimeError("no Angora branch-instrumented DeepState static library found in {}".format(lib_path))
    if not os.path.isfile(lib_path + "libdeepstate_taint.a"):
      raise RuntimeError("no Angora taint-tracked DeepState static library found in {}".format(lib_path))

    # generate ignored functions output for taint tracking
    # set envvar to file with ignored lib functions for taint tracking
    if self.ignore_calls:

      libpath = [path for path in self.ignore_calls.split(":")]
      L.debug(f"Ignoring library objects: {libpath}")

      out_file = "abilist.txt"

      # TODO(alan): more robust library check
      ignore_bufs = []
      for path in libpath:
        if not os.path.isfile(path):
          raise FuzzFrontendError(f"Library `{path}` to blackbox was not a valid library path.")

        # instantiate command to call, but store output to buffer
        cmd = [os.getenv("ANGORA") + "/tools/gen_library_abilist.sh", path, "discard"]
        L.debug(f"Compilation command: {cmd}")

        out = subprocess.check_output(cmd)
        ignore_bufs += [out]


      # write all to final out_file
      with open(out_file, "wb") as f:
        for buf in ignore_bufs:
          f.write(buf)

      # set envvar for fuzzer compilers
      env["ANGORA_TAINT_RULE_LIST"] = os.path.abspath(out_file)


    # make a binary with light instrumentation
    fast_flags = ["-ldeepstate_fast"]
    if self.compiler_args:
      fast_flags += [arg for arg in self.compiler_args.split(" ")]

    fast_args = ["-std=c++11", self.compile_test] + fast_flags + \
                ["-o", self.out_test_name + ".fast"]

    L.info(f"Compiling {self.compile_test} for Angora with light instrumentation")
    super().compile(compiler_args=fast_args, env=env)


    # make a binary with taint tracking information
    taint_flags = ["-ldeepstate_taint"]
    if self.compiler_args:
      taint_flags += [arg for arg in self.compiler_args.split(' ')]

    if self.mode == "pin":
      env["USE_PIN"] = "1"
    else:
      env["USE_TRACK"] = "1"

    taint_args = ["-std=c++11", self.compile_test] + taint_flags + \
                 ["-o", self.out_test_name + ".taint"]

    L.info(f"Compiling {self.compile_test} for Angora with taint tracking")
    super().compile(compiler_args=taint_args, env=env)


  def pre_exec(self):
    super().pre_exec()

    # since base method checks for self.binary by default
    if not self.taint_binary:
      self.parser.print_help()
      raise FuzzFrontendError("Must provide taint binary for Angora.")

    if not self.input_seeds:
      raise FuzzFrontendError("Must provide -i/--input_seeds option for Angora.")

    seeds = os.path.abspath(self.input_seeds)
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
      "--time_limit": str(self.timeout),
      "--mode": self.mode,
      "--input": self.input_seeds,
      "--output": self.output_test_dir,
      "--track": os.path.abspath(self.taint_binary),
    }

    # execution options
    if self.no_afl:
      cmd_dict["--disable_afl_mutation"] = None
    if self.no_exploration:
      cmd_dict["--disable_exploitation"] = None

    return self.build_cmd(cmd_dict)


  @property
  def stats(self):
    """
    Parses Angora output JSON config to dict for reporting.
    """
    stat_file = self.output_test_dir + "/chart_stat.json"

    if not hasattr(self, "prev_stats"):
      self.prev_stats = None

    try:
      with open(stat_file, "r") as handle:
        stats = json.loads(handle.read())
        self.prev_stats = stats
    except json.decoder.JSONDecodeError:
      stats = self.prev_stats

    return stats


  def reporter(self):
    return dict({
      "Execs Done": self.stats["num_exec"],
      "Unique Crashes": self.stats["num_crashes"],
      "Unique Hangs": self.stats["num_hangs"],
    })


def main():
  fuzzer = Angora(envvar="ANGORA")

  # parse user arguments and build object
  fuzzer.parse_args()

  # run fuzzer with parsed attributes
  fuzzer.run()
  return 0


if __name__ == "__main__":
  exit(main())
