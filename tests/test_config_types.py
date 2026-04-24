import argparse
import unittest

from deepstate.core.base import AnalysisBackend, AnalysisBackendError


def make_parser():
  p = argparse.ArgumentParser()
  p.add_argument("--timeout", type=int, default=0)
  p.add_argument("--ratio", type=float, default=0.0)
  p.add_argument("--blackbox", action="store_true")
  return p


class ConfigTypesTest(unittest.TestCase):

  def test_int(self):
    args = {"timeout": "3600"}
    AnalysisBackend._coerce_config_types(make_parser(), args)
    self.assertEqual(args["timeout"], 3600)
    self.assertIsInstance(args["timeout"], int)

  def test_float(self):
    args = {"ratio": "0.25"}
    AnalysisBackend._coerce_config_types(make_parser(), args)
    self.assertEqual(args["ratio"], 0.25)

  def test_bool_true(self):
    args = {"blackbox": "true"}
    AnalysisBackend._coerce_config_types(make_parser(), args)
    self.assertTrue(args["blackbox"])

  def test_bool_false(self):
    args = {"blackbox": "false"}
    AnalysisBackend._coerce_config_types(make_parser(), args)
    self.assertFalse(args["blackbox"])

  def test_invalid_int_raises(self):
    args = {"timeout": "not a number"}
    with self.assertRaises(AnalysisBackendError):
      AnalysisBackend._coerce_config_types(make_parser(), args)


if __name__ == "__main__":
  unittest.main()
