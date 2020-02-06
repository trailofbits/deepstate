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

from typing import ClassVar, List, Dict

from deepstate.core import FuzzerFrontend, FuzzFrontendError


L = logging.getLogger("deepstate.frontend.eclipser")
L.setLevel(os.environ.get("DEEPSTATE_LOG", "INFO").upper())


class Eclipser(FuzzerFrontend):
  """
  Eclipser front-end implemented with a base FuzzerFrontend object
  in order to interface the executable DLL for greybox concolic testing.
  """

  NAME: ClassVar[str] = "Eclipser.dll"
  COMPILER: ClassVar[str] = "clang++" 	 # for regular compilation


  def print_help(self):
    subprocess.call(["dotnet", self.fuzzer, "fuzz", "--help"])


  def compile(self) -> None: # type: ignore
    """
    Eclipser actually doesn't need instrumentation, but we still implement
    for consistency.
    """
    lib_path: str = "/usr/local/lib/libdeepstate.a"

    flags: List[str] = ["-ldeepstate"]
    if self.compiler_args:
      flags += [arg for arg in self.compiler_args.split(" ")]
    super().compile(lib_path, flags, self.out_test_name + ".eclipser")


  def pre_exec(self) -> None:
    super().pre_exec()

    out: str = self.output_test_dir
    L.debug(f"Output test directory: {out}")

    if not os.path.exists(out):
      print("Creating output directory.")
      os.mkdir(out)

    seeds: str = self.input_seeds # type: ignore
    if seeds:
      if os.path.exists(seeds):
        if len([name for name in os.listdir(seeds)]) == 0:
          raise FuzzFrontendError(f"Seeds path specified but none present in directory.")
      else:
        raise FuzzFrontendError(f"Seeds path `{seeds}` not found.")


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
      "--outputdir", self.output_test_dir,
      "--src", "file",
      "--fixfilepath", "eclipser.input",
      "--initarg", " ".join(deepstate_args),
      "--maxfilelen", str(self.max_input_size)
    ])

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


  def post_exec(self) -> None:
    """
    Decode and minimize testcases after fuzzing.
    """
    out: str = self.output_test_dir

    L.info("Performing post-processing decoding on testcases and crashes")
    subprocess.call(["dotnet", self.fuzzer, "decode", "-i", out + "/testcase", "-o", out + "/decoded"])
    subprocess.call(["dotnet", self.fuzzer, "decode", "-i", out + "/crash", "-o", out + "/decoded"])
    for f in glob.glob(out + "/decoded/decoded_files/*"):
      shutil.copy(f, out)
    shutil.rmtree(out + "/decoded")


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
    fuzzer.run(compiler="dotnet")
    return 0
  except FuzzFrontendError as e:
    L.error(e)
    return 1


if __name__ == "__main__":
  exit(main())
