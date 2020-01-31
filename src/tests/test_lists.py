from __future__ import print_function
import logrun
import deepstate_base


class ListsTest(deepstate_base.DeepStateTestCase):
  def run_deepstate(self, deepstate):
    if deepstate == "deepstate-manticore":
       return # Just skip for now, we know it's too slow
    (r, output) = logrun.logrun([deepstate, "build/examples/Lists"],
                  "deepstate.out", 3000)
    self.assertEqual(r, 0)

    self.assertTrue("Passed: Vector_DoubleReversal" in output)
    self.assertFalse("Failed: Vector_DoubleReversal" in output)
