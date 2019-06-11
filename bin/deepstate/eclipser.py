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

import glob
import os
import shutil
import subprocess
import sys

from .frontend import DeepStateFrontend

class Eclipser(DeepStateFrontend):
  """
  Eclipser front-end implemented with a base DeepStateFrontend object
  in order to interface the executable DLL for greybox concolic testing
  """

  def print_help(self):
    subprocess.call(["dotnet", self.fuzzer, "fuzz", "--help"])

  def cli_command(self, cmd_dict, compiler="dotnet", cli_other=None):
    super().cli_command(cmd_dict, compiler=compiler, cli_other=cli_other)

  def post_processing(self, out):
    subprocess.call(["dotnet", self.fuzzer, "decode", "-i", out + "/run/testcase", "-o", out + "/decoded"])
    subprocess.call(["dotnet", self.fuzzer, "decode", "-i", out + "/run/crash", "-o", out + "/decoded"])
    for f in glob.glob(out + "/decoded/decoded_files/*"):
      shutil.copy(f, out)
    shutil.rmtree(out + "/decoded")



def main():
  fuzzer = Eclipser("build/Eclipser.dll", envvar="ECLIPSER_HOME")
  args = fuzzer.parse_args()
  out = args.output_test_dir

  if args.fuzzer_help:
    fuzzer.print_help()
    sys.exit(0)

  if not os.path.exists(out):
    print("CREATING OUTPUT DIRECTORY...")
    os.mkdir(out)

  if not os.path.isdir(out):
    print("Error:", out, "is not a directory!")
    sys.exit(1)

  deepargs = "--input_test_file eclipser.input --abort_on_fail --no_fork"
  if args.which_test is not None:
    deepargs += " --input_which_test " + args.which_test

  cmd_dict = {
    "fuzz": None,
    "-p": args.binary,
    "-t": str(args.timeout),
    "-o": out + "/run",
    "--src": "file",
    "--fixfilepath": "eclipser.input",
    "--initarg": deepargs,
    "--maxfilelen": str(args.max_input_size),
  }

  if args.seeds is not None:
    cmd_dict["-i"] = args.seeds

  fuzzer.cli_command(cmd_dict, cli_other=args.args)

  print("EXECUTING FUZZER...")
  fuzzer.execute_fuzzer()

  print("DECODING THE TESTS...")
  fuzzer.post_processing(out)
  return 0


if "__main__" == __name__:
  exit(main())
