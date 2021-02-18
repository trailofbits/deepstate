#!/usr/bin/env python
# Copyright (c) 2017 Trail of Bits, Inc.
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

import distutils.core
import os
import setuptools

DEEPSTATE_DIR = os.path.dirname(os.path.realpath(__file__))

setuptools.setup(
    name="deepstate",
    version="0.1",
    package_dir={"": "/home/iroh/Documents/CS486/alpha/deepstate/bin"},
    packages=['deepstate'],
    description="DeepState augments C/C++ Test-Driven Development with Symbolic Execution",
    url="https://github.com/trailofbits/deepstate",
    author="Peter Goodman",
    author_email="peter@trailofbits.com",
    license="Apache-2.0",
    keywords="tdd testing symbolic execution",
    install_requires=['angr', 'manticore'],
    entry_points={
        'console_scripts': [
            'deepstate = deepstate.main_manticore:main',
            'deepstate-angr = deepstate.main_angr:main',
            'deepstate-manticore = deepstate.main_manticore:main',
            'deepstate-reduce = deepstate.reducer:main',
            'deepstate-add-standalone = deepstate.standalone:main',
            'deepstate-extract-standalone = deepstate.extract:main',
            'deepstate-eclipser = deepstate.eclipser:main',
        ]
    })
