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

import sys
import pkgutil
import importlib

from .frontend import DeepStateFrontend

def import_fuzzers(pkg_name):
  """
  dynamically load fuzzer frontends using importlib
  """
  package = sys.modules[pkg_name]
  return [
    importlib.import_module(pkg_name + '.' + submod)
    for _, submod, _ in pkgutil.walk_packages(package.__path__)
  ]

__all__ = import_fuzzers(__name__)
