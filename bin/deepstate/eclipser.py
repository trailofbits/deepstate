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
    "--seeds", default=None, type=str, required=False,
    help="Directory with seed inputs.")

  parser.add_argument(
    "--max_input_size", type=int, help="Maximum input size.",
      default=8192)

  parser.add_argument(
    "--which_test", type=str, help="Which test to run (equivalent to --input_which_test).", default=None)

  parser.add_argument(
    "--verbose", type=int, help="Verbosity level.",
      default=1)

  parser.add_argument(
    "--exectimeout", type=int, help="Execution timeout (ms) for Eclipser fuzz runs.",
    default=500)

  parser.add_argument(
    "--nsolve", type=int, help="Number of branches to flip in grey-box concolic testing.",
    default=None)

  parser.add_argument(
    "--nspawn", type=int, help="Number of byte values to initially spawn in grey-box concolic testing.",
    default=None)

  parser.add_argument(
    "--greyconcoliconly", action='store_true',
    help="Perform grey-box concolic testing only.")

  parser.add_argument(
    "--randfuzzonly", action='store_true',
    help="Perform random fuzzing only.")

  parser.add_argument(
    "--eclipser_help", action='store_true',
    help="Show Eclipser fuzzer command line options.")

  args = parser.parse_args()

  deepstate = args.binary
  out = args.output_test_dir
  whichTest = args.which_test

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

  cmd = ["dotnet", eclipser, "fuzz"]
  cmd += ["-p", deepstate, "-v", str(args.verbose)]
  cmd += ["-t", str(args.timeout), "-o", out + "/eclipser.run", "--src", "file"]
  deepargs = "--input_test_file eclipser.input --abort_on_fail"
  if whichTest is not None:
      deepargs += " --input_which_test " + whichTest
  cmd += ["--initarg", deepargs]
  cmd += ["--fixfilepath", "eclipser.input", "--maxfilelen", str(args.max_input_size)]
  cmd += ["--exectimeout", str(args.exectimeout)]
  if args.nsolve is not None:
    cmd += ["--nsolve", str(args.nsolve)]
  if args.nspawn is not None:
    cmd += ["--nspawn", str(args.nspawn)]
  if args.greyconcoliconly:
    cmd += ["--greyconcoliconly"]
  if args.randfuzzonly:
    cmd += ["--randfuzzonly"]
  if args.seeds is not None:
    cmd += ["-i", args.seeds]
  subprocess.call(cmd)
  
  decodeCmd = ["dotnet", eclipser, "decode"]
  decodeCmd += ["-i", out + "/eclipser.run/testcase", "-o", out + "/eclipser.decoded"]
  subprocess.call(decodeCmd)

  decodeCmd = ["dotnet", eclipser, "decode"]
  decodeCmd += ["-i", out + "/eclipser.run/crash", "-o", out + "/eclipser.decoded"]
  subprocess.call(decodeCmd)

  for f in glob.glob(out + "/eclipser.decoded/decoded_files/*"):
    shutil.copy(f, out)
  return 0

if "__main__" == __name__:
  exit(main())
