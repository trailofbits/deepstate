from __future__ import print_function
import os
import subprocess
from unittest import TestCase


class TestBasicFunctionality(TestCase):
    def test_basic_functionality(self):
        deepstate = os.getenv("DEEPSTATE_CMD")

        r = subprocess.call([deepstate + " build/examples/IntegerArithmetic | tee deepstate.out"],
                                shell=True)
        self.assertEqual(r, 0)

        with open("deepstate.out", 'r') as outf:
            result = outf.read()

        print ("RESULT:", result)

        self.assertTrue("Passed: Arithmetic_AdditionIsCommutative" in result)
        self.assertTrue("Passed: Arithmetic_AdditionIsAssociative" in result)
        self.assertTrue("Passed: Arithmetic_InvertibleMultiplication_CanFail" in result)
        self.assertTrue("Failed: Arithmetic_InvertibleMultiplication_CanFail" in result)                
