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
import sys
import argparse

from .frontend import DeepStateFrontend

class Angora(DeepStateFrontend):


  @classmethod
  def parse_args(cls):
    parser = argparse.ArgumentParser(description="Use Angora as back-end for DeepState.")

    compile_group = parser.add_argument_group("compilation and instrumentation arguments")
    compile_group.add_argument("--compile_test", type=str, help="Path to DeepState test harness for compilation.")
    compile_group.add_argument("--ignored_taints", type=str, help="Path to ignored function calls for taint analysis.")
    compile_group.add_argument("--compiler_args", default=[], nargs='+', help="Compiler flags (excluding -o) to pass to compiler.")
    compile_group.add_argument("--out_test_name", type=str, default="test", help="Set name for generated *.taint and *.fast binaries.")

    parser.add_argument("taint_binary", type=str, help="Path to binary compiled with taint tracking.")
    parser.add_argument("--mode", type=str, default="llvm", help="Specifies binary instrumentation framework used (either llvm or pin).")
    parser.add_argument("--no_afl", action='store_true', help="Disables AFL mutation strategies being used.")
    parser.add_argument("--no_exploration", action='store_true', help="Disables context-sensitive input bytes mutation.")

    cls.parser = parser
    return super(Angora, cls).parse_args()


  def compile(self):
    args = self._args
    no_taints = args.ignored_taints

    env = os.environ.copy()

    # check if static libraries exist
    lib_path = "/usr/local/lib/"
    if not os.path.isfile(lib_path + "libdeepstate_fast.a"):
      raise RuntimeError("no Angora branch-instrumented DeepState static library found in {}".format(lib_path))
    if not os.path.isfile(lib_path + "libdeepstate_taint.a"):
      raise RuntimeError("no Angora taint-tracked DeepState static library found in {}".format(lib_path))

    # set envvar to file with ignored lib functions for taint tracking
    if no_taints:
      if os.path.isfile(no_taints):
        env["ANGORA_TAINT_RULE_LIST"] = os.path.abspath(no_taints)

    # generate instrumented binary
    fast_args = [args.compile_test] + args.compiler_args + \
                ["-ldeepstate_fast", "-o", args.out_test_name + ".fast"]
    super().compile(compiler_args=fast_args, env=env)

    # make a binary with taint tracking information
    if args.mode == "pin":
      env["USE_PIN"] = "1"
    else:
      env["USE_TRACK"] = "1"

    taint_args = [args.compile_test] + args.compiler_args + \
                 ["-ldeepstate_taint", "-o", args.out_test_name + ".taint"]
    super().compile(compiler_args=taint_args, env=env)
    return 0


def main():
  fuzzer = Angora("angora_fuzzer", compiler="bin/angora-clang++", envvar="ANGORA")
  args = fuzzer.parse_args()

  if args.compile_test:
    print("COMPILING DEEPSTATE HARNESS FOR FUZZING...")
    fuzzer.compile()
    sys.exit(0)

  # we do not require for the sake of the compilation arg group
  if not args.seeds or not args.output_test_dir:
    print("Error: --seeds and/or --output_test_dir required for fuzzing.")
    sys.exit(1)

  seeds = os.path.abspath(args.seeds)

  if args.fuzzer_help:
    fuzzer.print_help()
    sys.exit(0)

  if not os.path.exists(seeds):
    print("CREATING INPUT SEED DIRECTORY...")
    os.mkdir(seeds)

  if len([name for name in os.listdir(seeds)]) == 0:
    print("Error: no seeds present in directory", args.seeds)
    sys.exit(1)

  cmd_dict = {
    "--time_limit": str(args.timeout),
    "--mode": args.mode,
    "--input": seeds,
    "--output": args.output_test_dir,
    "--jobs": str(args.jobs),
    "--track": os.path.abspath(args.taint_binary),
  }

  if args.no_afl:
    cmd_dict['--disable_afl_mutation'] = None

  if args.no_exploration:
    cmd_dict['--disable_exploitation'] = None

  cmd_dict['--'] = os.path.abspath(args.binary)

  # default args if none provided
  if len(args.args) == 0:
    cli_other = ["--input_test_file", "@@"]
  else:
    cli_other = args.args

  fuzzer.cli_command(cmd_dict, cli_other=cli_other)

  print("EXECUTING FUZZER...")
  fuzzer.execute_fuzzer()
  return 0


if __name__ == "__main__":
  exit(main())
