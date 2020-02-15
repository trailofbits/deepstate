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
import glob
import shutil
import logging
import subprocess

from typing import List, Dict

from deepstate.core import FuzzerFrontend, FuzzFrontendError


L = logging.getLogger(__name__)


class Eclipser(FuzzerFrontend):
  """
  Eclipser front-end implemented with a base FuzzerFrontend object
  in order to interface the executable DLL for greybox concolic testing.
  """

  NAME = "Eclipser"
  SEARCH_DIRS = ["build"]
  EXECUTABLES = {"FUZZER": "Eclipser.dll",
                  "COMPILER": "clang++",  # for regular compilation
                  "RUNNER": "dotnet"
                  }

  REQUIRE_SEEDS = False

  PUSH_DIR = os.path.join("sync_dir", "queue")
  PULL_DIR = os.path.join("sync_dir", "queue")
  CRASH_DIR = os.path.join("the_fuzzer", "crashes")


  def print_help(self):
    subprocess.call([self.EXECUTABLES["RUNNER"], self.fuzzer_exe, "fuzz", "--help"])


  def compile(self) -> None: # type: ignore
    """
    Eclipser actually doesn't need instrumentation, but we still implement
    for consistency.
    """
    lib_path: str = "/usr/local/lib/libdeepstate.a"

    flags: List[str] = ["-ldeepstate"]
    if self.compiler_args:
      flags += [arg for arg in self.compiler_args.split(" ")]
    super().compile(lib_path, flags, self.out_test_name)


  def pre_exec(self) -> None:
    super().pre_exec()

    # TODO handle that somehow
    L.warning("Eclipser doesn't limit child processes memory.")

    self.encoded_testcases_dir: str = os.path.join(self.output_test_dir, "the_fuzzer", "testcase")
    self.encoded_crash_dir: str = os.path.join(self.output_test_dir, "the_fuzzer", "crash")

    # resume fuzzing
    if len(os.listdir(self.output_test_dir)) > 1:
      self.check_required_directories([self.push_dir, self.crash_dir,
                                       self.encoded_crash_dir, self.encoded_testcases_dir])
      L.info(f"Resuming fuzzing using seeds from {self.pull_dir} (skipping --input_seeds option).")
      self.decode_testcases()
      self.input_seeds = self.push_dir
    else:
      self.setup_new_session([self.crash_dir, self.push_dir])

    if self.blackbox == True:
      L.info("Blackbox option is redundant. Eclipser works on non-instrumented binaries using QEMU by default.")

    if self.dictionary:
      L.error("Eclipser can't use dictionaries.")
        

  @property
  def cmd(self):
    cmd_list: List[str] = list()

    # get deepstate args and remove "-- binary"
    deepstate_args = self.build_cmd([], input_symbol='eclipser.input')
    binary_index = deepstate_args.index('--')
    deepstate_args.pop(binary_index)
    deepstate_args.pop(binary_index)

    # guaranteed arguments
    cmd_list.extend([
      "fuzz",
      "--program", self.binary,
      "--src", "file",
      "--fixfilepath", "eclipser.input",
      "--initarg", " ".join(deepstate_args),
      "--outputdir", os.path.join(self.output_test_dir, "the_fuzzer"), # auto-create, reusable
    ])

    if self.max_input_size == 0:
      cmd_list.extend(["--maxfilelen", "1099511627776"])  # use 1TiB as unlimited
    else:
      cmd_list.extend(["--maxfilelen", str(self.max_input_size)])

    # some timeout is required by eclipser
    if self.timeout and self.timeout != 0:
      timeout = self.timeout
    else:
      timeout = 99999
    cmd_list.extend(["--timelimit", str(timeout)])

    for key, val in self.fuzzer_args:
      if len(key) == 1:
        cmd_list.append('-{}'.format(key))
      else:
        cmd_list.append('--{}'.format(key))
      if val is not None:
        cmd_list.append(val)

    # optional arguments:
    if self.exec_timeout:
      cmd_list.extend(["--exectimeout", str(self.exec_timeout)])

    # not required, if provided: not auto-create and require any file inside
    if self.input_seeds:
      cmd_list.extend(["--initseedsdir", self.input_seeds])

    # no call to helper build_cmd
    return cmd_list


  def ensemble(self) -> None: # type: ignore
    """
    Overrides queue path for ensemble-fuzz
    """
    local_queue: str = os.path.join(self.output_test_dir, "testcase/")
    super().ensemble(local_queue)


  def decode_testcases(self):
    L.info("Performing decoding on testcases and crashes")
    decoded_path: str = os.path.join(self.output_test_dir, "decoded")

    subprocess.call([self.EXECUTABLES["RUNNER"], self.fuzzer_exe, "decode",
                        "-i", self.encoded_crash_dir, "-o", decoded_path],
                    stdout=subprocess.PIPE)
    for f in glob.glob(os.path.join(decoded_path, "decoded_files", "*")):
      shutil.copy(f, self.crash_dir)
    shutil.rmtree(decoded_path)

    subprocess.call([self.EXECUTABLES["RUNNER"], self.fuzzer_exe, "decode",
                        "-i", self.encoded_testcases_dir, "-o", decoded_path],
                    stdout=subprocess.PIPE)
    for f in glob.glob(os.path.join(decoded_path, "decoded_files", "*")):
      shutil.copy(f, self.pull_dir)
    shutil.rmtree(decoded_path)


  def manage(self):
    self.decode_testcases()
    super().manage()


  def post_exec(self) -> None:
    """
    Decode and minimize testcases after fuzzing.
    """
    self.decode_testcases()


  def populate_stats(self):
    super().populate_stats()


  def reporter(self) -> Dict[str, int]:
    """
    TODO: report more metrics
    """

    num_crashes: int = len([crash for crash in os.listdir(self.output_test_dir + "/crash")
                       if os.path.isfile(crash)])
    return dict({
        "Unique Crashes": num_crashes
    })


def main():
  try:
    fuzzer = Eclipser(envvar="ECLIPSER_HOME")
    fuzzer.parse_args()
    fuzzer.run(runner=fuzzer.EXECUTABLES["RUNNER"])
    return 0
  except FuzzFrontendError as e:
    L.error(e)
    return 1


if __name__ == "__main__":
  exit(main())
