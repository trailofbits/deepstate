from __future__ import print_function
import os
from unittest import TestCase
import logrun


class TestBasicFunctionality(TestCase):
    def test_basic_functionality(self):
        if os.getenv("DEEPSTATE_CMD") is not None:
            deepstates = [os.getenv("DEEPSTATE_CMD")]
        if deepstate is None:
            deepstates = ["deepstate-angr", "deepstate-manticore"]

        for deepstate in deepstates:
            if os.getenv("TASK") is None or os.getenv("TASK") == "CRASH":
                (r, output) = logrun.logrun([deepstate, "build/examples/Crash"],
                                            "deepstate.out", 1800)
                self.assertEqual(r, 0)

                self.assertTrue("Passed: Crash_SegFault" in output)
                foundCrashSave = False
                for line in output.split("\n"):
                    if ("Saving input to" in line) and (".crash" in line):
                        foundCrashSave = True
                self.assertTrue(foundCrashSave)

            if os.getenv("TASK") is None or os.getenv("TASK") == "KLEE":
                (r, output) = logrun.logrun([deepstate, "build/examples/Klee", "--klee"],
                                            "deepstate.out", 1800)
                self.assertEqual(r, 0)            

                self.assertTrue("zero" in output)
                self.assertTrue("positive" in output)
                self.assertTrue("negative" in output)

            if os.getenv("TASK") is None or os.getenv("TASK") == "PRIMES":
                (r, output) = logrun.logrun([deepstate, "build/examples/Primes"],
                                            "deepstate.out", 1800)
                self.assertEqual(r, 0)

                self.assertTrue("Failed: PrimePolynomial_OnlyGeneratesPrimes" in output)
                self.assertTrue("Failed: PrimePolynomial_OnlyGeneratesPrimes_NoStreaming" in output)

                self.assertTrue("Passed: PrimePolynomial_OnlyGeneratesPrimes" in output)
                self.assertTrue("Passed: PrimePolynomial_OnlyGeneratesPrimes_NoStreaming" in output)

            if os.getenv("TASK") is None or os.getenv("TASK") == "LISTS":
                (r, output) = logrun.logrun([deepstate, "build/examples/Lists"],
                                            "deepstate.out", 1800)
                self.assertEqual(r, 0)            

                self.assertTrue("Passed: Vector_DoubleReversal" in output)
                self.assertFalse("Failed: Vector_DoubleReversal" in output)             

            if os.getenv("TASK") is None or os.getenv("TASK") == "ONEOF":
                (r, output) = logrun.logrun([deepstate, "build/examples/OneOf"],
                                            "deepstate.out", 1800)
                self.assertEqual(r, 0)

                self.assertTrue("Failed: OneOfExample_ProduceSixtyOrHigher" in output)
                self.assertTrue("Passed: OneOfExample_ProduceSixtyOrHigher" in output)

            if os.getenv("TASK") is None or os.getenv("TASK") == "ARITHMETIC":
                (r, output) = logrun.logrun([deepstate, "build/examples/IntegerArithmetic", "--num_workers", "4"],
                                            "deepstate.out", 1800)
                self.assertEqual(r, 0)

                self.assertTrue("Failed: Arithmetic_InvertibleMultiplication_CanFail" in output)
                self.assertTrue("Passed: Arithmetic_AdditionIsCommutative" in output)
                self.assertFalse("Failed: Arithmetic_AdditionIsCommutative" in output)            
                self.assertTrue("Passed: Arithmetic_AdditionIsAssociative" in output)
                self.assertFalse("Failed: Arithmetic_AdditionIsAssociative" in output)            
                self.assertTrue("Passed: Arithmetic_InvertibleMultiplication_CanFail" in output)

