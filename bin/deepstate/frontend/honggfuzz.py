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


L = logging.getLogger("deepstate.frontend.honggfuzz")
L.setLevel(os.environ.get("DEEPSTATE_LOG", "INFO").upper())


class Honggfuzz(DeepStateFrontend):

  FUZZER = "honggfuzz"
  COMPILER = "hfuzz-clang++"

  @classmethod
  def parse_args(cls):
    parser = argparse.ArgumentParser(description="Use Honggfuzz as a backend for DeepState")

    # Execution options
    parser.add_argument("--dictionary", type=str, help="Optional fuzzer dictionary for honggfuzz.")
    parser.add_argument("--iterations", type=int, help="Number of iterations to fuzz for.")
    parser.add_argument("--keep_output", action="store_true", help="Output fuzzing feedback during execution.")
    parser.add_argument("--clear_env", action="store_true", help="Clear envvars before execution.")
    parser.add_argument("--save_all", action="store_true", help="Save all test-cases prepended with timestamps.")
    parser.add_argument("--sanitizers", action="store_true", help="Enable sanitizers when fuzzing.")

    # Instrumentation options
    parser.add_argument("--no_inst", type=str, help="Black-box fuzzing with honggfuzz without compile-time instrumentation.")
    parser.add_argument("--persistent", action="store_true", help="Set persistent mode when fuzzing.")

    # Hardware-related features for branch counting/coverage, etc.
    parser.add_argument("--keep_aslr", action="store_true", help="Don't disable ASLR randomization during execution.")
    parser.add_argument("--perf_instr", action="store_true", help="Allow PERF_COUNT_HW_INSTRUCTIONS.")
    parser.add_argument("--perf_branch", action="store_true", help="Allow PERF_COUNT_BRANCH_INSTRUCTIONS.")

    # Misc. options
    parser.add_argument("--post_stats", action="store_true", help="Output post-fuzzing stats.")

    cls.parser = parser
    return super(Honggfuzz, cls).parse_args()


  def compile(self):
    lib_path = "/usr/local/lib/libdeepstate_hfuzz.a"
    L.debug(f"Static library path: {lib_path}")

    if not os.path.isfile(lib_path):
      flags = ["-ldeepstate"]
    else:
      flags = ["-ldeepstate_hfuzz"]

    if self.compiler_args:
      flags += [arg for arg in self.compiler_args.split(" ")]

    compiler_args = ["-std=c++11", self.compile_test] + flags + \
                    ["-o", self.out_test_name + ".hfuzz"]
    super().compile(compiler_args)


  def pre_exec(self):
    super().pre_exec()

    if not self.no_inst:
      if not self.input_seeds:
        raise FrontendError("No -i/--input_seeds provided.")

      if not os.path.exists(self.input_seeds):
        os.mkdir(self.input_seeds)
        raise FrontendError("Seed path doesn't exist. Creating empty seed directory and exiting.")

      if len([name for name in os.listdir(self.input_seeds)]) == 0:
        raise FrontendError(f"No seeds present in directory {self.input_seeds}.")


  @property
  def cmd(self):
    cmd_dict = {
      "--input": self.input_seeds,
      "--workspace": self.output_test_dir,
      "--timeout": str(self.timeout),
    }

    if self.dictionary:
      cmd_dict["--dict"] = self.dictionary
    if self.iterations:
      cmd_dict["--iterations"] = str(self.iterations)

    if self.persistent:
      cmd_dict["--persistent"] = None
    if self.no_inst:
      cmd_dict["--noinst"] = None
    if self.keep_output:
      cmd_dict["--keep_output"] = None
    if self.sanitizers:
      cmd_dict["--sanitizers"] = None
    if self.clear_env:
      cmd_dict["--clear_env"] = None
    if self.save_all:
      cmd_dict["--save_all"] = None
    if self.keep_aslr:
      cmd_dict["--linux_keep_aslr"] = None

    # TODO: autodetect hardware features
    if self.perf_instr:
      cmd_dict["--linux_perf_instr"] = None
    if self.perf_branch:
      cmd_dict["--linux_perf_branch"] = None

    return self.build_cmd(cmd_dict, input_symbol="___FILE___")


  @property
  def stats(self):
    """
    Retrieves and parses the stats file produced by Honggfuzz
    """
    out_dir = os.path.abspath(self.output_test_dir) + "/"
    report_file = "HONGGFUZZ.REPORT.TXT"

    stat_file = out_dir + report_file
    with open(stat_file, "r") as sf:
      lines = sf.readlines()

    stats = {
      "mutationsPerRun": None,
      "externalCmd": None,
      "fuzzStdin": None,
      "timeout": None,
      "ignoreAddr": None,
      "ASLimit": None,
      "RSSLimit": None,
      "DATALimit": None,
      "wordlistFile": None,
      "fuzzTarget": None,
      "ORIG_FNAME": None,
      "FUZZ_FNAME": None,
      "PID": None,
      "SIGNAL": None,
      "FAULT ADDRESS": None,
      "INSTRUCTION": None,
      "STACK HASH": None,
    }

    # strip first 4 and last 5 lines to make a parseable file
    lines = lines[4:][:-5]

    for l in lines:
      for k in stats.keys():
        if k in l:
          stats[k] = l.split(":")[1].strip()

    # add crash metrics
    crashes = len([name for name in os.listdir(out_dir) if name != report_file])
    stats.update({
      "CRASHES": crashes
    })

    return stats


  def reporter(self):
    """
    Report a summarized version of statistics, ideal for ensembler output.
    """
    return dict({
      "Unique Crashes": self.stats["CRASHES"],
      "Mutations Per Run": self.stats["mutationsPerRun"]
    })


  def post_exec(self):
    if self.post_stats:
      print("\n")
      for k, v in self.stats.items():
        print(f"{k} : {v}")


def main():
  fuzzer = Honggfuzz()

  # parse user arguments and build object
  fuzzer.parse_args()
  fuzzer.init_fuzzer()

  # run fuzzer with parsed attributes
  fuzzer.run()
  return 0


if __name__ == "__main__":
  exit(main())
