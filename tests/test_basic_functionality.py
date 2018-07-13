from __future__ import print_function
import os
import subprocess
import glob
from unittest import TestCase


class TestBasicFunctionality(TestCase):
    def test_basic_functionality(self):
        outf = open("deepstate.out", 'w')

        class Unbuffered:
            def __init__(self, stream):
                self.stream = stream

            def write(self, data):
                self.stream.write(data)
                self.stream.flush()
                outf.write(data)
        
        deepstate = os.getenv("DEEPSTATE_CMD")

        with open("deepstate.out", 'w') as outf:
            r = subprocess.call([deepstate, "build/examples/IntegerArithmetic"],
                                    stdout = Unbuffered(sys.stdout),
                                    stderr = Unbuffered(sys.stdout))
        self.assertEqual(r, 0)

        with open("deepstate.out", 'r') as outf:
            result = outf.read()

        self.assertTrue("Passed: Arithmetic_AdditionIsCommutative" in result)
        self.assertTrue("Passed: Arithmetic_AdditionIsAssociative" in result)
        self.assertTrue("Passed: Arithmetic_InvertibleMultiplication_CanFail" in result)
        self.assertTrue("Failed: Arithmetic_InvertibleMultiplication_CanFail" in result)                
