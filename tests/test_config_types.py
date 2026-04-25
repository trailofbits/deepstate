from __future__ import print_function
import configparser
from unittest.mock import patch

from deepstate.core.base import AnalysisBackend
import deepstate_base


INI_DATA = """
[test]
timeout = 36000
mem_limit = 100
min_log_level = 2
float_value = 3.14
output_test_dir = /tmp/deepstate_out
"""


def fake_read(self, *args, **kwargs):
    self.read_string(INI_DATA)
    return []

class ConfigParseTest(deepstate_base.DeepStateTestCase):
    def run_deepstate(self, deepstate):
        # Not actually invoking deepstate, just reusing the test harness structure

        with patch("deepstate.core.base.configparser.ConfigParser.read", fake_read):
            result = AnalysisBackend.build_from_config("dummy_path")

        self.assertIsInstance(result["timeout"], int)
        self.assertIsInstance(result["mem_limit"], int)
        self.assertIsInstance(result["min_log_level"], int)
        self.assertIsInstance(result["float_value"], float)
        self.assertIsInstance(result["output_test_dir"], str)

        self.assertEqual(result["timeout"], 36000)
        self.assertEqual(result["mem_limit"], 100)
        self.assertEqual(result["min_log_level"], 2)
        self.assertEqual(result["float_value"], 3.14)
        self.assertEqual(result["output_test_dir"], "/tmp/deepstate_out")
