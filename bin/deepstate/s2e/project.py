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


import datetime
import logging
import os
import shutil

from s2e_env.command import CommandError
from s2e_env.commands.project_creation.abstract_project import AbstractProject
from s2e_env.utils.templates import render_template


L = logging.getLogger('deepstate.s2e')
L.setLevel(logging.INFO)

# Only Linux targets are supported
ARCH_TO_IMAGE = {
    'i386': 'debian-9.2.1-i386',
    'x86_64': 'debian-9.2.1-x86_64',
}

DEEPSTATE_TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), 'templates')

INSTRUCTIONS = """
Your DeepState project is available in {project_dir}.

This is a simplified version of a regular S2E analysis project. To start the
analysis:

    * cd {project_dir} && ./launch-s2e.sh

This will run the DeepState-enabled program in an S2E guest VM. The generated
tests will appear in the s2e-last/tests directory. The tests can be run using
the `--input_test_files_dir` option on a **NON** S2E-compiled program (running
an S2E-compiled program **outside** of S2E will result in an illegal
instruction error).

Customization
=============

* By default, your analysis will run with {num_workers} worker(s). This can be
  changed by modifying the S2E_MAX_PROCESSES variable in launch-s2e.sh
* If your target program depends on other files (e.g., shared libraries, etc.),
  then these should be retrieved in bootstrap.sh by adding a call to ${{S2EGET}}
* Only the minimum plugins required to generate tests have been enabled. To
  enable more, edit s2e-config.lua
"""


class DeepStateProject(AbstractProject):
    """A simplified S2E analysis project for DeepState-compiled programs."""

    def _configure(self, target, *args, **options):
        """
        Generate the S2E analysis project configuration.
        """
        if target.is_empty():
            raise CommandError('Cannot use an empty target for a DeepState '
                               'project')

        # Decide on the image to use
        image = ARCH_TO_IMAGE.get(target.arch)
        if not image:
            raise CommandError('Unable to find a suitable image for %s' %
                               target.path)
        img_desc = self._select_image(target, image, download_image=False)
        L.info('Using %s', img_desc['name'])

        # Determine if guestfs is available for this image
        guestfs_path = self._select_guestfs(img_desc)
        if not guestfs_path:
            L.warn('No guestfs available. The VMI plugin may not run optimally')

        # Return the project config dict
        return {
            'creation_time': str(datetime.datetime.now()),
            'project_dir': self.env_path('projects', options['name']),
            'image': img_desc,
            'has_guestfs': guestfs_path is not None,
            'guestfs_path': guestfs_path,
            'target_path': target.path,
            'target_arch': target.arch,
            'num_workers': options['num_workers'],
        }

    def _create(self, config, force=False):
        """
        Create the S2E analysis project, based on the given configuration.
        """
        project_dir = config['project_dir']

        # The force option is not exposed on the command-line for a DeepState
        # project, so fail if the project directory already exists
        if os.path.isdir(project_dir):
            raise CommandError('Project directory %s already exists' %
                               project_dir)

        os.mkdir(project_dir)

        try:
            # Create a symlink to the analysis target
            self._symlink_project_files(project_dir, config['target_path'])

            # Create a symlink to the guest tools directory
            self._symlink_guest_tools(project_dir, config['image'])

            # Create a symlink to the guestfs (if it exists)
            if config['guestfs_path']:
                self._symlink_guestfs(project_dir, config['guestfs_path'])

            # Render the templates
            self._create_launch_script(project_dir, config)
            self._create_lua_config(project_dir, config)
            self._create_bootstrap(project_dir, config)
        except Exception:
            # If anything goes wrong during project creation, remove anything
            # incomplete
            shutil.rmtree(project_dir)
            raise

        return project_dir

    def _get_instructions(self, config):
        """
        Generate instructions.
        """
        return INSTRUCTIONS.format(**config)

    def _create_launch_script(self, project_dir, config):
        """
        Create the S2E launch script.
        """
        L.info('Creating launch script')

        img_desc = config['image']
        context = {
            'creation_time': config['creation_time'],
            'env_dir': self.env_path(),
            'rel_image_path': os.path.relpath(img_desc['path'], self.env_path()),
            'max_processes': config['num_workers'],
            'qemu_arch': img_desc['qemu_build'],
            'qemu_memory': img_desc['memory'],
            'qemu_snapshot': img_desc['snapshot'],
            'qemu_extra_flags': img_desc['qemu_extra_flags'],
        }

        output_file = 'launch-s2e.sh'
        output_path = os.path.join(project_dir, output_file)

        render_template(context, '%s.j2' % output_file, output_path,
                        templates_dir=DEEPSTATE_TEMPLATES_DIR, executable=True)

    def _create_lua_config(self, project_dir, config):
        """
        Create the S2E Lua config.
        """
        L.info('Creating S2E configuration')

        self._copy_lua_library(project_dir)

        context = {
            'creation_time': config['creation_time'],
            'project_dir': config['project_dir'],
            'target_process': os.path.basename(config['target_path']),
            'has_guestfs': config['has_guestfs'],
            'guestfs_path': config['guestfs_path'],
        }

        output_file = 's2e-config.lua'
        output_path = os.path.join(project_dir, output_file)

        render_template(context, '%s.j2' % output_file, output_path,
                        templates_dir=DEEPSTATE_TEMPLATES_DIR)

    def _create_bootstrap(self, project_dir, config):
        """
        Create the S2E bootstrap script.
        """
        L.info('Creating S2E bootstrap script')

        context = {
            'creation_time': config['creation_time'],
            'target': os.path.basename(config['target_path']),
        }

        output_file = 'bootstrap.sh'
        output_path = os.path.join(project_dir, output_file)

        render_template(context, '%s.j2' % output_file, output_path,
                        templates_dir=DEEPSTATE_TEMPLATES_DIR)
