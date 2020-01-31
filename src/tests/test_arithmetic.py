from __future__ import print_function
import logrun
import deepstate_base


class ArithmeticTest(deepstate_base.DeepStateTestCase):
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
