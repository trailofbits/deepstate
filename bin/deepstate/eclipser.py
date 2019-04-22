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
import shutil
import subprocess
import sys


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
    "--maxInputSize", type=int, help="Maximum input size.",
      default=8192)

  parser.add_argument(
    "--which_test", type=str, help="Which test to run (equivalent to --input_which_test).", default=None)

  args = parser.parse_args()

  deepstate = args.binary
  out = args.output_test_dir
  whichTest = args.which_test

  ehome = os.getenv("ECLIPSER_HOME")
  if ehome is None:
    print("Error: ECLIPSER_HOME not set!")
    sys.exit(1)
  eclipser = ehome + "/build/Eclipser.dll"
  
  cmd = ["dotnet", eclipser, "fuzz"]
  cmd += ["-p", deepstate, "-v", "1"]
  cmd += [str(args.timeout), "-o", out + ".eclipser.run", "--src", "file"]
  deepargs = "--input_test_file eclipser.input --abort_on_fail"
  if whichTest is not None:
      deepargs += " --input_which_test " + whichTest
  cmd += ["--initarg", deepargs]
  cmd += ["--fixfilepath", "eclipser.input", "--maxfilelen", str(args.maxInputSize)]
  subprocess.call(cmd)
  
  decodeCmd = ["dotnet", eclipser, "decode"]
  decodeCmd += ["-i", out + ".eclipser.run", "-o", out + ".eclipser.decoded"]
  subprocess.call(decodeCmd)

  shutil.move(out + "eclipser.decoded/decoded_files", out)
  
  return 0

if "__main__" == __name__:
  exit(main())
