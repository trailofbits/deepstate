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

from typing import ClassVar, List, Dict, Optional

from deepstate.core import FuzzerFrontend, FuzzFrontendError

L = logging.getLogger("deepstate.frontend.libfuzzer")
L.setLevel(os.environ.get("DEEPSTATE_LOG", "INFO").upper())


class LibFuzzer(FuzzerFrontend):

  NAME: ClassVar[str] = "clang++"    # placeholder, set as harness binary later
  COMPILER: ClassVar[str] = "clang++"


  @classmethod
  def parse_args(cls) -> None:
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
      description="Use libFuzzer as a backend for DeepState")

    cls.parser = parser
    super(LibFuzzer, cls).parse_args()


  def compile(self) -> None: # type: ignore
    lib_path: str = "/usr/local/lib/libdeepstate_LF.a"

    flags: List[str] = ["-ldeepstate_LF"]
    if self.compiler_args:
      flags += [arg for arg in self.compiler_args.split(" ")]
    super().compile(lib_path, flags, self.out_test_name + ".lfuzz")


  def pre_exec(self) -> None:
    """
    Perform argparse and environment-related sanity checks.
    """
    super().pre_exec()

    # first, redefine and override fuzzer as harness executable
    self.fuzzer = self.binary # type: ignore
    seeds: str = self.input_seeds # type: ignore

    # check if seeds are present if specified
    if seeds:
      if os.path.exists(seeds):
        if len([name for name in os.listdir(seeds)]) == 0:
          raise FuzzFrontendError(f"Seeds path specified but none present in directory.")


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
      "-max_len={}".format(self.max_input_size)
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

    cmd_list.append("-artifact_prefix={}".format("deepstate_"))

    # must be here, this are positional args
    cmd_list.append(self.output_test_dir)

    if self.input_seeds:
      cmd_list.append(self.input_seeds)

    return cmd_list


def main():
  fuzzer = LibFuzzer()
  return fuzzer.main()


if __name__ == "__main__":
  exit(main())
