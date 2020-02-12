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
import logging
import argparse

from typing import List

from deepstate.core import FuzzerFrontend, FuzzFrontendError

L = logging.getLogger(__name__)

class LibFuzzer(FuzzerFrontend):

  NAME = "libFuzzer"
  EXECUTABLES = {"FUZZER": "clang++",  # placeholder
                  "COMPILER": "clang++"
                  }

  @classmethod
  def parse_args(cls) -> None:
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
      description="Use libFuzzer as a backend for DeepState")

    cls.parser = parser
    super(LibFuzzer, cls).parse_args()


  def compile(self) -> None: # type: ignore
    lib_path: str = "/usr/local/lib/libdeepstate_LF.a"

    flags: List[str] = ["-ldeepstate_LF", "-fsanitize=fuzzer,undefined"]
    if self.compiler_args:
      flags += [arg for arg in self.compiler_args.split(" ")]
    super().compile(lib_path, flags, self.out_test_name + ".lfuzz")


  def pre_exec(self) -> None:
    """
    Perform argparse and environment-related sanity checks.
    """
    # first, redefine and override fuzzer as harness executable
    if self.binary:
      self.binary = os.path.abspath(self.binary)
      self.fuzzer_exe = self.binary # type: ignore

    super().pre_exec()

    # again, because we may had run compiler
    self.binary = os.path.abspath(self.binary)
    self.fuzzer_exe = self.binary # type: ignore

    if self.blackbox is True:
      raise FuzzFrontendError("Blackbox fuzzing is not supported by libFuzzer.")

    self.push_dir = os.path.join(self.output_test_dir, "sync_dir")
    self.pull_dir = self.push_dir
    self.crash_dir = os.path.join(self.output_test_dir, "crashes")

    # resuming fuzzing
    if len(os.listdir(self.output_test_dir)) > 0:
      if not os.path.isdir(self.push_dir):
        raise FuzzFrontendError(f"Can't resume with output directory `{self.output_test_dir}`. "
                                  "No `sync_dir` directory inside.")
      if not os.path.isdir(self.crash_dir):
        raise FuzzFrontendError(f"Can't resume with output directory `{self.output_test_dir}`. "
                                  "No `crashes` directory inside.")

      self.input_seeds = None
      L.info(f"Resuming fuzzing using seeds from {self.push_dir} (skipping --input_seeds option).")
    else:
      os.mkdir(self.push_dir)
      os.mkdir(self.crash_dir)


  @property
  def cmd(self):
    """
    Initializes a command for an in-process libFuzzer instance that runs
    indefinitely until an interrupt.
    """
    cmd_list: List[str] = list()

    # guaranteed arguments
    cmd_list.extend([
      "-rss_limit_mb={}".format(self.mem_limit),
      "-max_len={}".format(self.max_input_size),
      "-artifact_prefix={}".format(self.crash_dir + "/"),
      # "-jobs={}".format(2),  # crashes deepstate ;/
      "-workers={}".format(1)
    ])

    for key, val in self.fuzzer_args:
      if val is not None:
        cmd_list.append('-{}={}'.format(key, val))
      else:
        cmd_list.append('-{}'.format(key))

    # optional arguments:
    if self.dictionary:
      cmd_list.append("-dict={}".format(self.dictionary))

    if self.exec_timeout:
      cmd_list.append("-timeout={}".format(self.exec_timeout / 1000))

    if self.post_stats:
      cmd_list.append("-print_final_stats={}".format(1))

    # must be here, this are positional args
    cmd_list.append(self.push_dir)  # no auto-create, reusable

    # not required, if provided: not auto-create and not require any files inside
    if self.input_seeds:
      cmd_list.append(self.input_seeds)

    return cmd_list


def main():
  fuzzer = LibFuzzer(envvar="LIBFUZZER_HOME")
  return fuzzer.main()


if __name__ == "__main__":
  exit(main())
