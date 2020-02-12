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
import os
import argparse
import configparser

from typing import Dict, ClassVar, Optional, Union, List, Any, Tuple

from deepstate import LOG_LEVEL_INT_TO_STR


L = logging.getLogger(__name__)


class AnalysisBackendError(Exception):
  """
  Defines our custom exception class for AnalysisBackend
  """
  pass


class AnalysisBackend(object):
  """
  Defines the root base object to inherit attributes and methods for any frontends that
  enable us to build any DeepState-backing executor or auxiliary tool using a builder pattern
  for instantiation.
  """

  # name of tool executable, should be implemented by subclass
  NAME: ClassVar[str] = ''

  # dict of executable files, should be implemented by subclass
  EXECUTABLES: ClassVar[Dict[str,str]] = {}

  # compiler executable
  compiler_exe: ClassVar[Optional[str]] = None

  # temporary attribute for argparsing, and should be used to build up object attributes
  _ARGS: ClassVar[Optional[argparse.Namespace]] = None

  # temporary attribute for parser instantiation, should be used to check if user parsed args
  parser: ClassVar[Optional[argparse.ArgumentParser]] = None


  def __init__(self):
    """
    Create and store variables:
      - name (name for pretty printing)
      - compiler_exe (compiler executable, optional)

    User must define NAME members in inherited class.
    """

    # in case name supplied as `bin/fuzzer`, strip executable name
    self.name: str = self.NAME
    if not self.name:
      raise AnalysisBackendError("AnalysisBackend.NAME not set")
    L.debug("Analysis backend name: %s", self.name)

    AnalysisBackend.compiler_exe = self.EXECUTABLES.pop("COMPILER", None)

    # parsed argument attributes
    self.binary: str = None
    self.output_test_dir: Optional[str] = None
    self.timeout: int = 0
    self.num_workers: int = 1
    self.mem_limit: int = 50
    self.min_log_level: int = 2

    self.compile_test: Optional[str] = None
    self.compiler_args: Optional[str] = None
    self.out_test_name: str = "out"

    self.no_exit_compile: bool = False
    self.which_test: Optional[str] = None
    self.target_args: List[Any] = []


  @classmethod
  def parse_args(cls) -> Optional[argparse.Namespace]:
    """
    Base root-level argument parser. After the executors initializes its application-specific arguments, and the frontend
    builds up further with analysis-specific arguments, this base parse_args finalizes with all other required args every
    executor should consume.
    """

    if cls._ARGS:
      L.debug("Returning already-parsed arguments")
      return cls._ARGS

    # checks if frontend executor already implements an argparser, since we want to extend on that.
    if cls.parser is not None:
      parser: argparse.ArgumentParser = cls.parser
    else:
      parser = argparse.ArgumentParser(description="Use {} as a backend for DeepState".format(cls.NAME))

    # Compilation/instrumentation support, only if COMPILER is set in EXECUTABLES
    # TODO: extends compilation interface for symex engines that "compile" source to
    # binary, IR format, or boolean expressions for symbolic VM to reason with
    if cls.compiler_exe:
      L.debug("Adding compilation support since a compiler was specified")

      # type: ignore
      compile_group = parser.add_argument_group("Compilation and Instrumentation")
      compile_group.add_argument("--compile_test", type=str,
        help="Path to DeepState test source for compilation and instrumentation by analysis tool.")

      # TODO: instead of parsing out arguments, we should consume JSON compilation databases instead
      compile_group.add_argument("--compiler_args", type=str,
        help="Linker flags (space seperated) to include for external libraries.")

      compile_group.add_argument("--out_test_name", type=str,
        help=("Set name of generated instrumented binary. Default is `out`. "
        "Automatically add `.frontend_name_lowercase` suffix."))

      compile_group.add_argument("--no_exit_compile", action="store_true",
        help="Continue execution after compiling a harness (set as default if `--config` is set).")

    # Target binary (not required, since user may pass in source for compilation)
    parser.add_argument("binary", nargs="?", type=str,
      help="Path to the test binary compiled with DeepState to run under analysis tool.")

    # Analysis-related configurations
    parser.add_argument(
      "-o", "--output_test_dir", type=str,
      help="Output directory where tests will be saved. Must be empty. Required.")

    parser.add_argument(
      "-c", "--config", type=str,
      help="Configuration file to be consumed instead of arguments.")

    parser.add_argument(
      "-t", "--timeout", default=0, type=int,
      help="Time to kill analysis worker processes, in seconds (default is 0 for none).")

    parser.add_argument(
      "-w", "--num_workers", default=1, type=int,
      help="Number of worker jobs to spawn for analysis (default is 1).")

    parser.add_argument("--mem_limit", type=int, default=50,
      help="Child process memory limit in MiB (default is 50). 0 for unlimited.")

    parser.add_argument(
        "--min_log_level", default=2, type=int,
        help="Minimum DeepState log level to print (default: 2), 0-6 (debug, trace, info, warning, error, external, critical).")

    # DeepState-related options
    exec_group = parser.add_argument_group("DeepState Test Configuration")
    exec_group.add_argument(
      "--which_test", type=str,
      help="DeepState unit test to run (equivalent to `--input_which_test`).")

    exec_group.add_argument(
      "--target_args", default=[], nargs='*',
      help="Other DeepState flags to pass to harness before execution. Format: `a arg=val` -> `-a --arg1 val`.")

    args = parser.parse_args()

    # from parsed arguments, modify dict copy if configuration is specified
    _args: Dict[str, Any] = vars(args)

    # parse target_args
    target_args_parsed: List[Tuple[str, Optional[str]]] = []
    for arg in _args['target_args']:
      vals = arg.split("=", 1)
      key = vals[0]
      val = None
      if len(vals) == 2:
        val = vals[1]
      target_args_parsed.append((key, val))
    _args['target_args'] = target_args_parsed

    # if configuration is specified, parse and replace argument instantiations
    if args.config:
      _args.update(cls.build_from_config(args.config)) # type: ignore

      # Cleanup: force --no_exit_compile to be on, meaning if user specifies a `[test]` section,
      # execution will continue. Delete config as well
      _args["no_exit_compile"] = True # type: ignore
      del _args["config"]

    # log level fixing
    if os.environ.get("DEEPSTATE_LOG", None) is None:
      if _args["min_log_level"] < 0 or _args["min_log_level"] > 6:
        raise AnalysisBackendError(f"`--min_log_level` is in invalid range, should be in 0-6 "
                                    "(debug, trace, info, warning, error, external, critical).")

      logger = logging.getLogger("deepstate")
      logger.setLevel(LOG_LEVEL_INT_TO_STR[_args["min_log_level"]])
    else:
      L.info("Using log level from $DEEPSTATE_LOG.")
      
    cls._ARGS = args
    return cls._ARGS


  @staticmethod
  def build_from_config(config: str, allowed_keys: Optional[List[str]] = None, include_sections: bool = False) -> Union[Dict[str, Dict[str, Any]], Dict[str, Any]]:
    """
    Simple auxiliary helper that does safe and correct parsing of DeepState configurations. This can be used
    in the following manners:

    * Baked-in usage with AnalysisBackend, allowing us to take input user configurations and initialize attributes for
    our frontend executors.
    * Used externally as API for reasoning with configurations as part of auxiliary tools or test runners.

    :param config: path to configuration file
    :param allowed_keys: contains allowed keys that should be parsed
    :param include_sections: if true, parse all sections, and return a Dict[str, Dict[str, Any]] where keys are section names
    """

    context: Dict[str, Dict[str, Any]] = dict() # type: ignore

    # reserved sections are ignored by executors, but can be used by other auxiliary tools
    # to reason about with.
    reserved_sections: List[str] = [
      "manifest",   # contains "metadata" for a configuration
      "internal"    # write-only by auxiliary tools, and should store anything not used by DeepState
    ]

    # define tokens that are allowed for a configuration. This way users will not be able to
    # populate an executor with unnecessary attributes that do not contribute to execution.
    allowed_sections: List[str] = [
      "compile",    # specifies configuration for compiling a test
      "test"        # configurations for harness execution under analysis tool
    ]

    parser = configparser.SafeConfigParser()
    parser.read(config)

    for section, kv in parser._sections.items(): # type: ignore

      # if `include_sections` is not set, parse only from allowed_sections
      if not include_sections:
        if section not in allowed_sections:
          continue
        elif section in reserved_sections:
          continue

      # if `include_sections`, keys are now all section names
      if include_sections:
        _context = context[section] = dict()
      else:
        _context = context

      for key, val in kv.items():

        # check if key should be parsed
        if allowed_keys is not None:
          if key not in allowed_keys:
            continue

        if isinstance(val, list):
          _context[key].append(val)
        else:
          _context[key] = val

    return context # type: ignore


  def init_from_dict(self, _args: Optional[Dict[str, str]] = None) -> None:
    """
    Builder initialization routine used to instantiate the attributes of the frontend object, either from the stored
    _ARGS namespace, or manual arguments passed in (not ideal, but useful for ensembler orchestration).

    :param _args: optional dictionary with parsed arguments to set as attributes.
    """
    args: Dict[str, str] = vars(self._ARGS) if _args is None else _args
    for key, value in args.items():
      setattr(self, key, value)
