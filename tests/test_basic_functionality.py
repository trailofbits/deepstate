from __future__ import print_function
import os
from unittest import TestCase
import logrun


class TestBasicFunctionality(TestCase):
    def test_basic_functionality(self):
        deepstate = os.getenv("DEEPSTATE_CMD")
        if deepstate is None:
            deepstate = "deepstate-angr" # default to angr in an environment without a defined command

        if os.getenv("TASK") is None or os.getenv("TASK") == "PRIMES":
            (r, output) = logrun.logrun([deepstate, "build/examples/Primes"],
                                        "deepstate.out", 1800)
            
            self.assertEqual(r, 0)

            self.assertTrue("Failed: PrimePolynomial_OnlyGeneratesPrimes" in output)
            self.assertTrue("Failed: PrimePolynomial_OnlyGeneratesPrimes_NoStreaming" in output)

            self.assertTrue("Passed: PrimePolynomial_OnlyGeneratesPrimes" in output)
            self.assertTrue("Passed: PrimePolynomial_OnlyGeneratesPrimes_NoStreaming" in output)

        if os.getenv("TASK") is None or os.getenv("TASK") == "ONEOF":
            (r, output) = logrun.logrun([deepstate, "build/examples/OneOf"],
                                        "deepstate.out", 1800)
            
            self.assertEqual(r, 0)

            self.assertTrue("Failed: OneOfExample_ProduceSixtyOrHigher" in output)
            self.assertTrue("Passed: OneOfExample_ProduceSixtyOrHigher" in output)

        if os.getenv("TASK") is None or os.getenv("TASK") == "ARITHMETIC":
            (r, output) = logrun.logrun([deepstate, "build/examples/IntegerArithmetic", "--num_workers", "4"],
                                        "deepstate.out", 1800)

            self.assertTrue("Failed: Arithmetic_InvertibleMultiplication_CanFail" in output)
            self.assertTrue("Passed: Arithmetic_AdditionIsCommutative" in output)
            self.assertTrue("Passed: Arithmetic_AdditionIsAssociative" in output)
            self.assertTrue("Passed: Arithmetic_InvertibleMultiplication_CanFail" in output)
