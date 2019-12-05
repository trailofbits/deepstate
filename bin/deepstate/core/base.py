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

import logging
logging.basicConfig()

import os
import argparse
import configparser

from typing import Dict, ClassVar, Optional, Union, List


L = logging.getLogger("deepstate.core.base")
L.setLevel(os.environ.get("DEEPSTATE_LOG", "INFO").upper())


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

  # temporary attribute for argparsing, and should be used to build up object attributes
  _ARGS: ClassVar[Optional[Dict[str, str]]] = None

  # temporary attribute for parser instantiation, should be used to check if user parsed args
  parser: ClassVar[Optional[argparse.ArgumentParser]] = None


  def __init__(self):
    pass


  @classmethod
  def parse_args(cls) -> None:
    """
    Base root-level argument parser. After the executors initializes its application-specific arguments, and the frontend
    builds up further with analysis-specific arguments, this base parse_args finalizes with all other required args every
    executor should consume.
    """
    parser = cls.parser

    # Compilation/instrumentation support, only if COMPILER is set
    # TODO: extends compilation interface for symex engines that "compile" source to
    # binary, IR format, or boolean expressions for symbolic VM to reason with
    if cls.COMPILER:
      L.debug("Adding compilation support since a compiler was specified")

      compile_group = parser.add_argument_group("Compilation and Instrumentation")
      compile_group.add_argument("--compile_test", type=str,
        help="Path to DeepState test source for compilation and instrumentation by analysis tool.")

      # TODO: instead of parsing out arguments, we should consume JSON compilation databases instead
      compile_group.add_argument("--compiler_args", type=str,
        help="Linker flags (space seperated) to include for external libraries.")

      compile_group.add_argument("--out_test_name", type=str, default="out",
        help="Set name of generated instrumented binary (default is `out.{FUZZER}`).")


    # Target binary (not required, since user may pass in source for compilation)
    parser.add_argument("binary", nargs="?", type=str,
      help="Path to the test binary compiled with DeepState to run under analysis tool.")

    # Analysis-related configurations
    parser.add_argument(
      "-o", "--output_test_dir", type=str, default="{}_out".format(cls.NAME),
      help="Output directory where tests will be saved (default is `{FUZZER}_out`).")

    parser.add_argument(
      "-c", "--config", type=str,
      help="Configuration file to be consumed instead of arguments.")

    parser.add_argument(
      "-t", "--timeout", default=240, type=int,
      help="Time to kill analysis workers, in seconds (default 240).")


    # DeepState-related options
    exec_group = parser.add_argument_group("DeepState Test Configuration")
    exec_group.add_argument(
      "--which_test", type=str,
      help="DeepState unit test to run (equivalent to `--input_which_test`).")

    exec_group.add_argument(
      "--prog_args", default=[], nargs=argparse.REMAINDER,
      help="Other DeepState flags to pass to harness before execution, in format `--arg=val`.")


    args: Dict[str, str] = vars(parser.parse_args())

    # if configuration is specified, parse and replace argument instantiations
    if args["config"]:
      args.update(cls.build_from_config(args["config"]))
      del args["config"]

    cls._ARGS = args


  ConfigType = Dict[str, Dict[str, Union[str, List[str]]]]

  @classmethod
  def build_from_config(cls, config: str, include_sections: bool = False) -> Union[ConfigType, Dict[str, str]]:
    """
    Simple auxiliary helper that does safe and correct parsing of DeepState configurations. This can be used
    in the following manners:

    * Baked-in usage with AnalysisBackend, allowing us to take input user configurations and initialize attributes for
    our frontend executors.
    * Used externally as API for reasoning with configurations as part of auxiliary tools or test runners.

    :param config: path to configuration file
    :param include_sections: if true, will return a ConfigType where keys are section names
    """

    context = dict()

    # define tokens that are allowed for a configuration. This way users will not be able to
    # populate an executor with unnecessary attributes that do not contribute to execution.
    allowed_sections: List[str] = ["compile", "test", "manifest"]

    allowed_keys: List[str] = vars(cls)

    parser = configparser.SafeConfigParser()
    parser.read(config)

    for section, kv in parser._sections.items():
      if section not in allowed_sections:
        continue

      _context = context[section] if include_sections else context
      for key, val in kv.items():
        if key in allowed_keys:
          if isinstance(val, list):
            _context[key].append(val)
          else:
            _context[key] = val

    return context


  def init_from_dict(self, _args: Optional[Dict[str, str]] = None) -> None:
    """
    Builder initialization routine used to instantiate the attributes of the frontend object, either from the stored
    _ARGS namespace, or manual arguments passed in (not ideal, but useful for ensembler orchestration).

    :param _args: optional dictionary with parsed arguments to set as attributes.
    """
    args: Dict[str, str] = self._ARGS if _args is None else _args
    for key, value in args.items():
      setattr(self, key, value)
