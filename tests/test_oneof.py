from __future__ import print_function
import logrun
import deepstate_base


class OneOfTest(deepstate_base.DeepStateTestCase):
  def run_deepstate(self, deepstate):
    (r, output) = logrun.logrun([deepstate, "build/examples/OneOf"],
                  "deepstate.out", 1800)
    self.assertEqual(r, 0)

    self.assertTrue("Failed: OneOfExample_ProduceSixtyOrHigher" in output)
    self.assertTrue("Passed: OneOfExample_ProduceSixtyOrHigher" in output)
