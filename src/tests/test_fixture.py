from __future__ import print_function
import logrun
import deepstate_base


class FixtureTest(deepstate_base.DeepStateTestCase):
  def run_deepstate(self, deepstate):
    (r, output) = logrun.logrun([deepstate, "build/examples/Fixture"],
                  "deepstate.out", 1800)
    self.assertEqual(r, 0)

    self.assertTrue("Passed: MyTest_Something" in output)
    self.assertFalse("Failed: MyTest_Something" in output)

    self.assertTrue("Setting up!" in output)
    self.assertTrue("Tearing down!" in output)
