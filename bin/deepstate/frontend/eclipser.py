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

from .frontend import DeepStateFrontend, FrontendError

class Eclipser(DeepStateFrontend):
  """
  Eclipser front-end implemented with a base DeepStateFrontend object
  in order to interface the executable DLL for greybox concolic testing.
  """

  FUZZER = "Eclipser.dll"


  def print_help(self):
    """
    Overrides default interface for calling for help.
    """
    subprocess.call(["dotnet", self.fuzzer, "fuzz", "--help"])


  def pre_exec(self):
    super().pre_exec()

    args = self._ARGS

    out = args.output_test_dir
    if not os.path.exists(out):
      print("Creating output directory.")
      os.mkdir(out)


  @property
  def cmd(self):
    args = self._ARGS

    # initialize DeepState flags if none
    if len(args.args) == 0:
      deepargs = ["--input_test_file", "eclipser.input",
   		  "--no_fork", "--abort_on_fail"]
    else:
      deepargs = args.args

    if args.which_test is not None:
      deepargs += ["--input_which_test", args.which_test]

    cmd_dict = {
      "fuzz": None,
      "-p": args.binary,
      "-t": str(args.timeout),
      "-o": args.output_test_dir + "/run",
      "--src": "file",
      "--fixfilepath": "eclipser.input",
      "--initarg": " ".join(deepargs),
      "--maxfilelen": str(args.max_input_size),
    }

    if args.input_seeds is not None:
      cmd_dict["-i"] = args.input_seeds

    return cmd_dict


  def post_exec(self):
    """
    Decode and minimize testcases after fuzzing.
    """
    out = self._ARGS.output_test_dir

    subprocess.call(["dotnet", self.fuzzer, "decode", "-i", out + "/run/testcase", "-o", out + "/decoded"])
    subprocess.call(["dotnet", self.fuzzer, "decode", "-i", out + "/run/crash", "-o", out + "/decoded"])
    for f in glob.glob(out + "/decoded/decoded_files/*"):
      shutil.copy(f, out)
    shutil.rmtree(out + "/decoded")



def main():
  fuzzer = Eclipser(envvar="ECLIPSER_HOME")
  fuzzer.parse_args()
  fuzzer.run(compiler="dotnet")
  return 0


if "__main__" == __name__:
  exit(main())
