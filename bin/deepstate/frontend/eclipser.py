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
import glob
import shutil
import logging
import subprocess

from .frontend import DeepStateFrontend, FrontendError


L = logging.getLogger("deepstate.frontend.eclipser")
L.setLevel(os.environ.get("DEEPSTATE_LOG", "INFO").upper())


class Eclipser(DeepStateFrontend):
  """
  Eclipser front-end implemented with a base DeepStateFrontend object
  in order to interface the executable DLL for greybox concolic testing.
  """

  FUZZER = "Eclipser.dll"


  def print_help(self):
    subprocess.call(["dotnet", self.fuzzer, "fuzz", "--help"])


  def pre_exec(self):
    super().pre_exec()

    out = self._ARGS.output_test_dir
    L.debug(f"Output test directory: {out}")

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
      "-o": args.output_test_dir,
      "--src": "file",
      "--fixfilepath": "eclipser.input",
      "--initarg": " ".join(deepargs),
      "--maxfilelen": str(args.max_input_size),
    }

    if args.input_seeds is not None:
      cmd_dict["--initseedsdir"] = args.input_seeds

    return cmd_dict


  def ensemble(self):
    local_queue = self._ARGS.output_test_dir + "/testcase/"
    super().ensemble(local_queue)


  def post_exec(self):
    """
    Decode and minimize testcases after fuzzing.
    """
    out = self._ARGS.output_test_dir

    L.info("Performing post-processing decoding on testcases and crashes")
    subprocess.call(["dotnet", self.fuzzer, "decode", "-i", out + "/testcase", "-o", out + "/decoded"])
    subprocess.call(["dotnet", self.fuzzer, "decode", "-i", out + "/crash", "-o", out + "/decoded"])
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
