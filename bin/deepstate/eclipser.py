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

from __future__ import print_function
import argparse
import glob
import os
import shutil
import subprocess
import sys


def main():
  parser = argparse.ArgumentParser(description="Use Eclipser as back-end for DeepState.")

  parser.add_argument("binary", type=str, help="Path to the test binary to run.")
  
  parser.add_argument("--output_test_dir", type=str, default="out", help="Directory where tests will be saved.")

  parser.add_argument("--timeout", type=int, default=3600, help="How long to fuzz using Eclipser.")

  parser.add_argument("--seeds", type=str, help="Directory with seed inputs.")

  parser.add_argument("--which_test", type=str, help="Which test to run (equivalent to --input_which_test).")

  parser.add_argument("--max_input_size", type=int, default=8192, help="Maximum input size.")

  parser.add_argument("--eclipser_help", action='store_true', help="Show Eclipser fuzzer command line options.")

  parser.add_argument("--args", default=[], nargs=argparse.REMAINDER, help="Other arguments to pass to eclipser.",)

  args = parser.parse_args()
  out = args.output_test_dir

  ehome = os.getenv("ECLIPSER_HOME")
  if ehome is None:
    print("Error: ECLIPSER_HOME not set!")
    sys.exit(1)
  eclipser = ehome + "/build/Eclipser.dll"

  if args.eclipser_help:
    subprocess.call(["dotnet", eclipser, "fuzz", "--help"])
    sys.exit(0)

  if not os.path.exists(out):
    print("CREATING OUTPUT DIRECTORY...")
    os.mkdir(out)

  if not os.path.isdir(out):
    print("Error:", out, "is not a directory!")
    sys.exit(1)

  cmd = ["dotnet", eclipser, "fuzz", "-p", args.binary, "-t", str(args.timeout)]
  cmd += ["-o", out + "/run", "--src", "file", "--fixfilepath", "eclipser.input"]
  deepargs = "--input_test_file eclipser.input --abort_on_fail --no_fork"
  if args.which_test is not None:
      deepargs += " --input_which_test " + args.which_test
  cmd += ["--initarg", deepargs, "--maxfilelen", str(args.max_input_size)]
  cmd += args.args
  try:
    r = subprocess.call(cmd)
    print ("Eclipser finished with exit code", r)
  except BaseException as e: # catch any failure, and still put the tests we got into raw format
    print("Eclipser run interrupted due to exception:", e)

  print("DECODING THE TESTS...")
  subprocess.call(["dotnet", eclipser, "decode", "-i", out + "/run/testcase", "-o", out + "/decoded"])
  subprocess.call(["dotnet", eclipser, "decode", "-i", out + "/run/crash", "-o", out + "/decoded"])
  for f in glob.glob(out + "/decoded/decoded_files/*"):
    shutil.copy(f, out)
  shutil.rmtree(out + "/decoded")

  return 0

if "__main__" == __name__:
  exit(main())
