#!/usr/bin/env python
# Copyright (c) 2018 Adrian Herrera
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

from s2e_env.manage import call_command
from s2e_env.commands.new_project import Command as NewProjectCommand
from s2e_env.utils import log as s2e_log

from deepstate.common import LOG_LEVEL_DEBUG, LOG_LEVEL_TRACE, LOG_LEVEL_INFO, \
        LOG_LEVEL_WARNING, LOG_LEVEL_ERROR, LOG_LEVEL_FATAL
from .common import DeepState
from .s2e.project import DeepStateProject


L = logging.getLogger("deepstate.s2e")
L.setLevel(logging.INFO)

LOG_LEVEL_TO_LOGGING_LEVEL = {
    LOG_LEVEL_DEBUG: logging.DEBUG,
    LOG_LEVEL_TRACE: 15,
    LOG_LEVEL_INFO: logging.INFO,
    LOG_LEVEL_WARNING: logging.WARNING,
    LOG_LEVEL_ERROR: logging.ERROR,
    LOG_LEVEL_FATAL: logging.CRITICAL,
}


def get_s2e_env():
    s2e_env_dir = os.getenv("S2EDIR")
    if not s2e_env_dir:
        raise Exception("S2EDIR environment variable not specified. Ensure "
                        "that s2e_activate.sh has been sourced")
    if not os.path.isdir(s2e_env_dir):
        raise Exception("S2EDIR {} is invalid".format(s2e_env_dir))

    return s2e_env_dir


def main():
    """
    Create an s2e-env project that is suitable for analyzing a DeepState test.
    """
    args = DeepState.parse_args()

    # Sync S2E and DeepState logging levels
    s2e_log.configure_logging(level=LOG_LEVEL_TO_LOGGING_LEVEL[args.verbosity])

    try:
        s2e_env_path = get_s2e_env()
        proj_name = "{}-deepstate".format(os.path.basename(args.binary))

        call_command(NewProjectCommand(), args.binary, env=s2e_env_path,
                     name=proj_name, project_class=DeepStateProject,
                     **vars(args))
    except Exception as e:
        L.critical("Cannot create an S2E project for %s: %s", args.binary, e)
        return 1

    return 0


if __name__ == '__main__':
    exit(main())
