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
    args = self._ARGS

    lib_path = "/usr/local/lib/libdeepstate_hfuzz.a"
    L.debug(f"Static library path: {lib_path}")

    if not os.path.isfile(lib_path):
      flags = ["-ldeepstate"]
    else:
      flags = ["-ldeepstate_hfuzz"]

    if args.compiler_args:
      flags += [arg for arg in args.compiler_args.split(" ")]

    compiler_args = ["-std=c++11", args.compile_test] + flags + \
                    ["-o", args.out_test_name + ".hfuzz"]
    super().compile(compiler_args)


  def pre_exec(self):
    super().pre_exec()
    args = self._ARGS

    if not args.no_inst:
      if not args.input_seeds:
        raise FrontendError("No -i/--input_seeds provided.")

      if not os.path.exists(args.input_seeds):
        os.mkdir(args.input_seeds)
        raise FrontendError("Seed path doesn't exist. Creating empty seed directory and exiting.")

      if len([name for name in os.listdir(args.input_seeds)]) == 0:
        raise FrontendError(f"No seeds present in directory {args.input_seeds}.")


  @property
  def cmd(self):
    args = self._ARGS

    cmd_dict = {
      "--input": args.input_seeds,
      "--workspace": args.output_test_dir,
      "--timeout": str(args.timeout),
    }

    if args.dictionary:
      cmd_dict["--dict"] = args.dictionary
    if args.iterations:
      cmd_dict["--iterations"] = str(args.iterations)

    if args.persistent:
      cmd_dict["--persistent"] = None
    if args.no_inst:
      cmd_dict["--noinst"] = None
    if args.keep_output:
      cmd_dict["--keep_output"] = None
    if args.sanitizers:
      cmd_dict["--sanitizers"] = None
    if args.clear_env:
      cmd_dict["--clear_env"] = None
    if args.save_all:
      cmd_dict["--save_all"] = None
    if args.keep_aslr:
      cmd_dict["--linux_keep_aslr"] = None

    # TODO: autodetect hardware features
    if args.perf_instr:
      cmd_dict["--linux_perf_instr"] = None
    if args.perf_branch:
      cmd_dict["--linux_perf_branch"] = None

    cmd_dict.update({
      "--": args.binary,
      "--input_test_file": "___FILE___",
      "--abort_on_fail": None,
      "--no_fork": None
    })

    if args.which_test:
      cmd_dict["--input_which_test"] = args.which_test

    return cmd_dict

  @property
  def stats(self):
    """
    Retrieves and parses the stats file produced by Honggfuzz
    """
    args = self._ARGS
    out_dir = os.path.abspath(args.output_test_dir) + "/"
    report_f = "HONGGFUZZ.REPORT.TXT"

    stat_file = out_dir + report_f
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
    crashes = len([name for name in os.listdir(out_dir) if name != report_f])
    stats.update({
      "CRASHES": crashes
    })

    return stats


  def reporter(self):
    """
    Report a summarized version of statistics, ideal for ensembler output.
    """
    return dict({
      "Unique Crashes": self.stats["CRASHES"]
    })


  def post_exec(self):
    if self._ARGS.post_stats:
      print("\n")
      for k, v in self.stats.items():
        print(f"{k} : {v}")


def main():
  fuzzer = Honggfuzz()
  args = fuzzer.parse_args()

  fuzzer.run()
  return 0


if __name__ == "__main__":
  exit(main())
