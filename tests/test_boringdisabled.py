from __future__ import print_function
import logrun
import deepstate_base

class BoringDisabledTest(deepstate_base.DeepStateTestCase):
  def run_deepstate(self, deepstate):
    (r, output) = logrun.logrun([deepstate, "build/examples/BoringDisabled"],
                  "deepstate.out", 1800)
    self.assertEqual(r, 0)

    self.assertTrue("Failed: CharTest_VerifyCheck" in output)
    self.assertTrue("Passed: CharTest_BoringVerifyCheck" in output)


