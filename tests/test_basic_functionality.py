from __future__ import print_function
import os
from unittest import TestCase
import logrun


class TestBasicFunctionality(TestCase):
    def test_basic_functionality(self):
        deepstate = os.getenv("DEEPSTATE_CMD")
        if deepstate is None:
            deepstate = "deepstate-angr" # default to angr in an environment without a defined command

        (r, output) = logrun.logrun([deepstate, "build/examples/IntegerArithmetic"],
                                     "deepstate.out", 1800)
        self.assertEqual(r, 0)

        self.assertTrue("Passed: Arithmetic_AdditionIsCommutative" in output)
        self.assertTrue("Passed: Arithmetic_AdditionIsAssociative" in output)
        self.assertTrue("Passed: Arithmetic_InvertibleMultiplication_CanFail" in output)
        self.assertTrue("Failed: Arithmetic_InvertibleMultiplication_CanFail" in output)                
