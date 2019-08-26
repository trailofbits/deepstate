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


L = logging.getLogger("deepstate.frontend.libfuzzer")
L.setLevel(os.environ.get("DEEPSTATE_LOG", "INFO").upper())


class LibFuzzer(DeepStateFrontend):

  FUZZER = "clang++"    # placeholder, since we don't use an executable
  COMPILER = "clang++"


  @classmethod
  def parse_args(cls):
    parser = argparse.ArgumentParser(description="Use libFuzzer as a backend for DeepState")

    # Execution options
    parser.add_argument("--mem_limit", type=int, default=50, help="Child process memory limit in MB (default is 50).")
    parser.add_argument("--runtime", type=int, default=0, help="Total time to run fuzzer for (default is 0 for indefinite).")
    parser.add_argument("--dictionary", type=str, help="Optional fuzzer dictionary for libFuzzer.")
    parser.add_argument("--use_counters", action="store_true", help="Use perf counters.")
    parser.add_argument("--use_ascii", action="store_true", help="Use only ASCII characters for generated input seeds.")
    parser.add_argument("--print_pcs", action="store_true", help="Print program counters during fuzzer execution.")

    # Misc. post-processing
    parser.add_argument("--minimize_crash", action="store_true", help="Automatically minimize crashing testcases after fuzzer execution.")
    parser.add_argument("--post_stats", action="store_true", help="Output post-fuzzing stats.")

    cls.parser = parser
    return super(LibFuzzer, cls).parse_args()


  def compile(self):
    args = self._ARGS

    lib_path = "/usr/local/lib/libdeepstate_LF.a"
    L.debug(f"Static library path: {lib_path}")

    if not os.path.isfile(lib_path):
      raise RuntimeError("no LibFuzzer-instrumented DeepState static library found in {}".format(lib_path))

    flags = ["-ldeepstate_LF"]
    if args.compiler_args:
      flags += [arg for arg in args.compiler_args.split(" ")]

    compiler_args = ["-std=c++11", "-fsanitize=fuzzer", args.compile_test] + flags + \
                    ["-o", args.out_test_name + ".libfuzzer"]
    super().compile(compiler_args)


  def pre_exec(self):
    """
    Perform argparse and environment-related sanity checks.
    """
    super().pre_exec()

    args = self._ARGS
    seeds = args.input_seeds

    # check if seeds are present if specified
    if os.path.exists(seeds):
      if len([name for name in os.listdir(seeds)]) == 0:
        raise FrontendError(f"Seeds path specified but none present in directory.")


  @property
  def cmd(self):
    """
    Initializes a command for an in-process libFuzzer instance that runs
    indefinitely until an interrupt.
    """
    args = self._ARGS

    cmd_dict = {
      "-max_len": str(args.max_input_size),
      "-timeout": str(args.timeout),
      "-rss_limit_mb": str(args.mem_limit),
      "-max_total_time": str(args.runtime),
      "-artifact_prefix": "deepstate_"
    }

    if args.dictionary is not None:
      cmd_dict["-dict"] = args.dictionary
    if args.use_counters:
      cmd_dict["-use_counters"] = args.use_counters
    if args.use_ascii:
      cmd_dict["-only_ascii"] = "1"
    if args.print_pcs:
      cmd_dict["-print_pcs"] = "1"
    if args.post_stats:
      cmd_dict["-print_final_stats"] = "1"
    if args.minimize_crash:
      cmd_dict["-minimize_crash"] = "1"

    cmd_dict['--'] = args.binary

    # if not specified, set DeepState flags to help LibFuzzer
    if len(args.args) == 0:
      cmd_dict["--input_test_file"] = "@@"
      cmd_dict["--abort_on_fail"] = None
      cmd_dict["--no_fork"] = None

    if args.which_test:
      cmd_dict["--input_which_test"] = args.which_test

    return cmd_dict


def main():
  fuzzer = LibFuzzer()
  fuzzer.parse_args()
  fuzzer.run()
  return 0


if __name__ == "__main__":
  exit(main())
