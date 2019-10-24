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
  COMPILER = "clang++" 	 # for regular compilation

  def print_help(self):
    subprocess.call(["dotnet", self.fuzzer, "fuzz", "--help"])


  def compile(self):
    """
    Eclipser actually doesn't need instrumentation, but we still implement
    for consistency.
    """
    lib_path = "/usr/local/lib/libdeepstate.a"
    L.debug(f"Static library path: {lib_path}")

    if not os.path.isfile(lib_path):
      raise RuntimeError("no DeepState static library found in {}".format(lib_path))

    flags = ["-ldeepstate"]
    if self.compiler_args:
      flags += [arg for arg in self.compiler_args.split(" ")]

    compiler_args = ["-std=c++11", self.compile_test] + flags + \
                    ["-o", self.out_test_name + ".eclipser"]
    super().compile(compiler_args)


  def pre_exec(self):
    super().pre_exec()

    out = self.output_test_dir
    L.debug(f"Output test directory: {out}")

    if not os.path.exists(out):
      print("Creating output directory.")
      os.mkdir(out)

    seeds = self.input_seeds
    if seeds:
      if os.path.exists(seeds):
        if len([name for name in os.listdir(seeds)]) == 0:
          raise FrontendError(f"Seeds path specified but none present in directory.")


  @property
  def cmd(self):

    # initialize DeepState flags
    deepargs = ["--input_test_file", "eclipser.input",
   		"--no_fork", "--abort_on_fail"]

    if self.which_test is not None:
      deepargs += ["--input_which_test", self.which_test]

    cmd_dict = {
      "fuzz": None,
      "-p": self.binary,
      "-t": str(self.timeout),
      "-o": self.output_test_dir,
      "--src": "file",
      "--fixfilepath": "eclipser.input",
      "--initarg": " ".join(deepargs),
      "--maxfilelen": str(self.max_input_size),
    }

    if self.input_seeds is not None:
      cmd_dict["--initseedsdir"] = self.input_seeds

    # no call to helper build_cmd
    return cmd_dict


  def ensemble(self):
    local_queue = self.output_test_dir + "/testcase/"
    super().ensemble(local_queue)


  def post_exec(self):
    """
    Decode and minimize testcases after fuzzing.
    """
    out = self.output_test_dir

    L.info("Performing post-processing decoding on testcases and crashes")
    subprocess.call(["dotnet", self.fuzzer, "decode", "-i", out + "/testcase", "-o", out + "/decoded"])
    subprocess.call(["dotnet", self.fuzzer, "decode", "-i", out + "/crash", "-o", out + "/decoded"])
    for f in glob.glob(out + "/decoded/decoded_files/*"):
      shutil.copy(f, out)
    shutil.rmtree(out + "/decoded")


  def reporter(self):
    num_crashes = len([crash for crash in os.listdir(self.output_test_dir + "/crash")
                       if os.path.isfile(crash)])
    return dict({
        "Unique Crashes": num_crashes
    })


def main():
  fuzzer = Eclipser(envvar="ECLIPSER_HOME")

  # parse user arguments and build object
  fuzzer.parse_args()
  fuzzer.init_fuzzer()

  # run fuzzer with parsed attributes
  fuzzer.run(compiler="dotnet")
  return 0


if __name__ == "__main__":
  exit(main())
