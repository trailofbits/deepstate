from __future__ import print_function
from unittest import TestCase
import logrun


class DeepStateTestCase(TestCase):
  def test_angr(self):
    self.run_deepstate("deepstate-angr")

  def test_manticore(self):
    self.run_deepstate("deepstate-manticore")


class CrashTest(DeepStateTestCase):
  def run_deepstate(self, deepstate):
    (r, output) = logrun.logrun([deepstate, "build/examples/Crash"],
                  "deepstate.out", 1800)
    self.assertEqual(r, 0)

    self.assertTrue("Passed: Crash_SegFault" in output)
    foundCrashSave = False
    for line in output.split("\n"):
      if ("Saving input to" in line) and (".crash" in line):
        foundCrashSave = True
    self.assertTrue(foundCrashSave)


class KleeTest(DeepStateTestCase):
  def run_deepstate(self, deepstate):
    (r, output) = logrun.logrun([deepstate, "build/examples/Klee", "--klee"],
                  "deepstate.out", 1800)
    self.assertEqual(r, 0)

    self.assertTrue("zero" in output)
    self.assertTrue("positive" in output)
    self.assertTrue("negative" in output)


class PrimesTest(DeepStateTestCase):
  def run_deepstate(self, deepstate):
    (r, output) = logrun.logrun([deepstate, "build/examples/Primes"],
                  "deepstate.out", 1800)
    self.assertEqual(r, 0)

    self.assertTrue("Failed: PrimePolynomial_OnlyGeneratesPrimes" in output)
    self.assertTrue("Failed: PrimePolynomial_OnlyGeneratesPrimes_NoStreaming" in output)

    self.assertTrue("Passed: PrimePolynomial_OnlyGeneratesPrimes" in output)
    self.assertTrue("Passed: PrimePolynomial_OnlyGeneratesPrimes_NoStreaming" in output)


class TakeOverTest(DeepStateTestCase):
  def run_deepstate(self, deepstate):
    (r, output) = logrun.logrun([deepstate, "build/examples/TakeOver", "--take_over"],
                  "deepstate.out", 1800)
    self.assertEqual(r, 0)

    self.assertTrue("hi" in output)
    self.assertTrue("bye" in output)
    self.assertTrue("was not greater than" in output)

    foundPassSave = False
    for line in output.split("\n"):
      if ("Saving input to" in line) and (".pass" in line):
        foundPassSave = True
    self.assertTrue(foundPassSave)


class FixtureTest(DeepStateTestCase):
  def run_deepstate(self, deepstate):
    (r, output) = logrun.logrun([deepstate, "build/examples/Fixture"],
                  "deepstate.out", 1800)
    self.assertEqual(r, 0)

    self.assertTrue("Passed: MyTest_Something" in output)
    self.assertFalse("Failed: MyTest_Something" in output)

    self.assertTrue("Setting up!" in output)
    self.assertTrue("Tearing down!" in output)


class ListsTest(DeepStateTestCase):
  def run_deepstate(self, deepstate):
    (r, output) = logrun.logrun([deepstate, "build/examples/Lists"],
                  "deepstate.out", 3000)
    self.assertEqual(r, 0)

    self.assertTrue("Passed: Vector_DoubleReversal" in output)
    self.assertFalse("Failed: Vector_DoubleReversal" in output)


class StreamingAndFormattingTest(DeepStateTestCase):
  def run_deepstate(self, deepstate):
    (r, output) = logrun.logrun([deepstate, "build/examples/StreamingAndFormatting"],
                  "deepstate.out", 1800)
    #self.assertEqual(r, 0)

    self.assertTrue("Failed: Streaming_BasicLevels" in output)
    self.assertTrue("This is a debug message" in output)
    self.assertTrue("This is an info message" in output)
    self.assertTrue("This is a warning message" in output)
    self.assertTrue("This is a error message" in output)
    self.assertTrue("This is a info message again" in output)
    self.assertTrue(": 97" in output)
    self.assertTrue(": 1" in output)
    self.assertTrue(": 1.000000" in output)
    self.assertTrue(": string" in output)
    self.assertTrue("hello string=world" in output)
    self.assertTrue("hello again!" in output)
    self.assertTrue("Passed: Formatting_OverridePrintf" in output)
    self.assertFalse("Failed: Formatting_OverridePrintf" in output)


class OneOfTest(DeepStateTestCase):
  def run_deepstate(self, deepstate):
    (r, output) = logrun.logrun([deepstate, "build/examples/OneOf"],
                  "deepstate.out", 1800)
    self.assertEqual(r, 0)

    self.assertTrue("Failed: OneOfExample_ProduceSixtyOrHigher" in output)
    self.assertTrue("Passed: OneOfExample_ProduceSixtyOrHigher" in output)


class OverflowTest(DeepStateTestCase):
  def run_deepstate(self, deepstate):
    (r, output) = logrun.logrun([deepstate, "build/examples/IntegerOverflow"],
                  "deepstate.out", 1800)
    self.assertEqual(r, 0)

    self.assertTrue("Failed: SignedInteger_AdditionOverflow" in output)
    self.assertTrue("Passed: SignedInteger_AdditionOverflow" in output)
    self.assertTrue("Failed: SignedInteger_MultiplicationOverflow" in output)
    self.assertTrue("Passed: SignedInteger_MultiplicationOverflow" in output)


class ArithmeticTest(DeepStateTestCase):
  def run_deepstate(self, deepstate):
    (r, output) = logrun.logrun([deepstate, "build/examples/IntegerArithmetic", "--num_workers", "4"],
                  "deepstate.out", 1800)
    self.assertEqual(r, 0)

    self.assertTrue("Failed: Arithmetic_InvertibleMultiplication_CanFail" in output)
    self.assertTrue("Passed: Arithmetic_AdditionIsCommutative" in output)
    self.assertFalse("Failed: Arithmetic_AdditionIsCommutative" in output)
    self.assertTrue("Passed: Arithmetic_AdditionIsAssociative" in output)
    self.assertFalse("Failed: Arithmetic_AdditionIsAssociative" in output)
    self.assertTrue("Passed: Arithmetic_InvertibleMultiplication_CanFail" in output)
