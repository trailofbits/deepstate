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

  ENVVAR = "LIBFUZZER_HOME"
  REQUIRE_SEEDS = False

  PUSH_DIR = os.path.join("sync_dir", "queue")
  PULL_DIR = os.path.join("sync_dir", "queue")
  CRASH_DIR = os.path.join("the_fuzzer", "crashes")

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
    super().compile(lib_path, flags, self.out_test_name)


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
    if not self.binary:
      raise FuzzFrontendError("Binary not set.")
    self.binary = os.path.abspath(self.binary)
    self.fuzzer_exe = self.binary # type: ignore

    if self.blackbox is True:
      raise FuzzFrontendError("Blackbox fuzzing is not supported by libFuzzer.")

    # resuming fuzzing
    if len(os.listdir(self.output_test_dir)) > 0:
      self.check_required_directories([self.push_dir, self.pull_dir, self.crash_dir])
      self.input_seeds = None
      L.info(f"Resuming fuzzing using seeds from {self.push_dir} (skipping --input_seeds option).")
    else:
      self.setup_new_session([self.pull_dir, self.crash_dir])


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
      # "-jobs={}".format(0),
      # "-workers={}".format(1),
      # "-fork=1",
      "-reload=1",
      "-runs=-1",
      "-print_final_stats=1"
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

    # must be here, this are positional args
    cmd_list.append(self.push_dir)  # no auto-create, reusable

    # not required, if provided: not auto-create and not require any files inside
    if self.input_seeds:
      cmd_list.append(self.input_seeds)

    return cmd_list


  def populate_stats(self):
    super().populate_stats()

    if not os.path.isfile(self.output_file):
      return

    with open(self.output_file, "rb") as f:
      for line in f:
        # libFuzzer under DeepState have broken output
        # splitted into multiple lines, preceded with "EXTERNAL:"
        if line.startswith(b"EXTERNAL: "):
          line = line.split(b":", 1)[1].strip()
          if line.startswith(b"#"):
            # new event code
            self.stats["execs_done"] = line.split()[0].strip(b"#").decode()

          elif b":" in line:
            line = line.split(b":", 1)[1].strip()
            if b":" in line:
              key, value = line.split(b":", 1)
              if key == b"exec/s":
                self.stats["execs_per_sec"] = value.strip().decode()
              elif key == b"units":
                self.stats["paths_total"] = value.strip().decode()
              elif key == b"cov":
                self.stats["bitmap_cvg"] = value.strip().decode()


  def _sync_seeds(self, src, dest, excludes=[]) -> None:
    excludes += ["*.cur_input", ".state"]
    super()._sync_seeds(src, dest, excludes=excludes)


  def post_exec(self):
    # TODO: remove crashes from seeds dir and from sync_dir
    pass


def main():
  fuzzer = LibFuzzer()
  return fuzzer.main()


if __name__ == "__main__":
  exit(main())
