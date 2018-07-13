from __future__ import print_function
import os
import subprocess
import glob
from unittest import TestCase


class TestBasicFunctionality(TestCase):
    def test_basic_functionality(self):
        deepstate = os.getenv("DEEPSTATE_CMD")

        with open("deepstate.out", 'w') as outf:
            r = subprocess.call([deepstate, "examples/IntegerArithmetic"], stdout = outf, stderr = outf)
        self.assertEqual(r, 0)

        with open("deepstate.out", 'r') as outf:
            result = outf.read()

        self.assertTrue("Passed: Arithmetic_AdditionIsCommutative" in result)
        self.assertTrue("Passed: Arithmetic_AdditionIsAssociative" in result)
        self.assertTrue("Passed: Arithmetic_InvertibleMultiplication_CanFail" in result)
        self.assertTrue("Failed: Arithmetic_InvertibleMultiplication_CanFail" in result)                
