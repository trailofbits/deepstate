from __future__ import print_function
import logrun
import deepstate_base


class OverflowTest(deepstate_base.DeepStateTestCase):
  def run_deepstate(self, deepstate):
    (r, output) = logrun.logrun([deepstate, "build/examples/IntegerOverflow"],
                  "deepstate.out", 1800)
    self.assertEqual(r, 0)

    self.assertTrue("Failed: SignedInteger_AdditionOverflow" in output)
    self.assertTrue("Passed: SignedInteger_AdditionOverflow" in output)
    self.assertTrue("Failed: SignedInteger_MultiplicationOverflow" in output)
    self.assertTrue("Passed: SignedInteger_MultiplicationOverflow" in output)
