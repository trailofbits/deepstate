from __future__ import print_function
from unittest import TestCase


class DeepStateTestCase(TestCase):
  def test_angr(self):
    self.run_deepstate("deepstate-angr")

  def test_manticore(self):
    self.run_deepstate("deepstate-manticore")

  def run_deepstate(self, deepstate):
    print("define an actual test of DeepState here.")
