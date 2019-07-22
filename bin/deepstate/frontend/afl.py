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
import argparse

from .frontend import DeepStateFrontend, FrontendError


class AFL(DeepStateFrontend):
  """ Defines default AFL fuzzer frontend """

  FUZZER = "afl-fuzz"
  COMPILER = "afl-clang++"

  @classmethod
  def parse_args(cls):
    parser = argparse.ArgumentParser(description="Use AFL as a back-end for DeepState.")

    compile_group = parser.add_argument_group("compilation and instrumentation arguments")
    compile_group.add_argument("--compile_test", type=str, help="Path to DeepState test harness for compilation.")
    compile_group.add_argument("--compiler_args", default=[], nargs='+', help="Compiler flags (excluding -o) to pass to compiler.")
    compile_group.add_argument("--out_test_name", type=str, default="out", help="Set name of generated instrumented binary.")

    parser.add_argument("--dictionary", type=str, help="Optional fuzzer dictionary for AFL.")
    parser.add_argument("--mem_limit", type=int, default=50, help="Child process memory limit in MB (default is 50).")
    parser.add_argument("--file", type=str, help="Input file read by fuzzed program, if any.")

    parser.add_argument("--dirty_mode", action='store_true', help="Fuzz without deterministic steps.")
    parser.add_argument("--dumb_mode", action='store_true', help="Fuzz without instrumentation.")
    parser.add_argument("--qemu_mode", action='store_true', help="Fuzz with QEMU mode.")
    parser.add_argument("--crash_explore", action='store_true', help="Fuzz with crash exploration.")

    cls.parser = parser
    return super(AFL, cls).parse_args()


  def compile(self):
    args = self._ARGS

    lib_path = "/usr/local/lib/"
    if not os.path.isfile(lib_path + "libdeepstate_AFL.a"):
      raise RuntimeError("no AFL-instrumented DeepState static library found in {}".format(lib_path))

    compiler_args = [args.compile_test, "-std=c++11"] + args.compiler_args + \
                    ["-ldeepstate_AFL", "-o", args.out_test_name + ".afl"]
    super().compile(compiler_args)


  def pre_exec(self):
    super().pre_exec()

    args = self._ARGS

    if args.compile_test:
      self.compile()
      sys.exit(0)

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
      "-i": args.input_seeds,
      "-o": args.output_test_dir,
      "-t": str(args.timeout),
      "-m": str(args.mem_limit)
    }

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
    pass

  # TODO
  def ensemble(self):

    # get original stats
    orig_stats = self.stats

    # update stored stats at current point of execution
    self._update_stats()

    if stats["last_update"] != orig_stats["last_update"]:
      self.sync_seeds()
    else:
      self.get_seeds()



def main():
  fuzzer = AFL()
  args = fuzzer.parse_args()
  fuzzer.run()
  return 0


if __name__ == "__main__":
  exit(main())
