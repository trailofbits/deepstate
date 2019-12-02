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

import argparse
import configparser

from typing import Dict, ClassVar, Optional, Union


class AnalysisBackend(object):
  """
  Defines the root base object to inherit attributes and methods for any frontends that
  enable us to build any DeepState-backing executor or auxiliary tool using a builder pattern
  for instantiation.
  """

  # name of tool executable, should be implemented by subclass
  NAME: ClassVar[Optional[str]] = None

  # name of compiler executable, should be implemented by subclass
  COMPILER: ClassVar[Optional[str]] = None

  # path to incomplete DeepState path, should be modified
  LIB_PATH: ClassVar[Optional[str]] = "/usr/local/lib/libdeepstate"

  # temporary attribute for argparsing, and should be used to build up object attributes
  _ARGS: ClassVar[Optional[argparse.Namespace]] = None

  # temporary attribute for parser instantiation, should be used to check if user parsed args
  parser: ClassVar[Optional[argparse.ArgumentParser]] = None


  @classmethod
  def parse_args(cls) -> argparse.Namespace:
    """
    Base root-level argument parser. After the executors initializes its application-specific arguments, and the frontend
    builds up further with analysis-specific arguments, this base parse_args finalizes with all other required args every
    executor should consume.
    """
    parser = cls.parser

    # Compilation/instrumentation support, only if COMPILER is set
    # TODO: symex engines extends an interface that "compiles" source to
    # binary, IR format, or boolean expressions for symbolic engine to reason with
    if cls.COMPILER:
      L.debug("Adding compilation support since a compiler was specified")

      compile_group = parser.add_argument_group("Compilation and Instrumentation")
      compile_group.add_argument("--compile_test", type=str, help="Path to DeepState test harness for compilation.")
      compile_group.add_argument("--compiler_args", type=str, help="Linker flags (space seperated) to include for external libraries.")
      compile_group.add_argument("--out_test_name", type=str, default="out", help="Set name of generated instrumented binary.")

    # Target binary (not required, since user may pass in source for compilation)
    parser.add_argument("binary", nargs="?", type=str, help="Path to the test binary to run.")

    # Configurations for Analysis
    analysis_group = parser.add_argument_group("Analysis Execution")
    analysis_group.add_argument("-o", "--output_test_dir", type=str, default="{}_out".format(str(cls())), help="Directory where tests will be saved.")
    analysis_group.add_argument("-c", "--configuration", type=str, help="Configuration file to be consumed instead of arguments.")

    # DeepState-related options
    exec_group = parser.add_argument_group("DeepState Test Configuration")
    exec_group.add_argument("--which_test", type=str, help="DeepState test to run (equivalent to `--input_which_test`).")
    exec_group.add_argument("--prog_args", default=[], nargs=argparse.REMAINDER, help="Other DeepState flags to pass to \
      harness before execution, in format `--arg=val`.")

    return parser.parse_args()


  def init_from_dict(self, _args: Optional[Dict[str, str]] = None) -> None:
    """
    Builder initialization routine used to instantiate the attributes of the frontend object, either from the stored
    _ARGS namespace, or manual arguments passed in (not ideal, but useful for ensembler orchestration).

    :param _args: optional dictionary with parsed arguments to set as attributes.
    """
    args: Dict[str, str] = vars(self._ARGS) if _args is None else _args
    for key, value in args.items():
      setattr(self, key, value)


  def fallback_compile(self) -> None:
    """
    Defines a fallback compilation routine for executors. This should be used as the default method
    for symex executors, or for grey/black-box fuzzers that don't mutate or instrument code with a compiler wrapper.
    """
    pass
