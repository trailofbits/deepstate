#!/usr/bin/env python
# Copyright (c) 2018 Trail of Bits, Inc.
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

from __future__ import print_function
import argparse
import os
import subprocess

def main():
  parser = argparse.ArgumentParser(description="Use Eclipser back-end")

  parser.add_argument(
    "binary", type=str, help="Path to the test binary to run.")
  
  parser.add_argument(
    "--output_test_dir", default="out", type=str, required=False,
    help="Directory where tests will be saved.")

  parser.add_argument(
    "--timeout", type=int, help="How long to fuzz using Eclipser.",
    default=3600)

  parser.add_argument(
    "--which_test", type=str, help="Which test to run (equivalent to --input_which_test).", default=None)

  args = parser.parse_args()

  deepstate = args.binary
  out = args.output_test
  whichTest = args.which_test
  try:
    os.mkdir(out)
  except BaseException:
    pass
  cmd = ["dotnet", "$ECLISPER_HOME/build/Eclipser.dll", "fuzz", "-p", deepstate, "-v", "1"]
  cmd += [str(args.timeout), "-o", out + "/eclipser.run", "--src", "file"]
  cmd += ["--initarg"]
  cmd += ["--input_test_file " + out + "/" + "eclipser.input --abort_on_fail --input_which_test " + whichTest]
  cmd += ["--fixfilepath", out + "/" + "eclipser.input", "--maxfilelen", "8192"]
  subprocess.call(cmd)
  decodeCmd = ["dotnet", "$ECLISPER_HOME/build/Eclipser.dll", "decode"]
  decodeCmd += ["-i", out + "/eclipser.run", "-o", out + "/tests"]
  subprocess.call(decodeCmd)
  
  return 0

if "__main__" == __name__:
  exit(main())
