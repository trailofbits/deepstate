from __future__ import print_function
import deepstate_base
import logrun


class KleeTest(deepstate_base.DeepStateTestCase):
  def run_deepstate(self, deepstate):
    (r, output) = logrun.logrun([deepstate, "build/examples/Klee", "--klee"],
                  "deepstate.out", 1800)
    self.assertEqual(r, 0)

    self.assertTrue("zero" in output)
    self.assertTrue("positive" in output)
    self.assertTrue("negative" in output)
