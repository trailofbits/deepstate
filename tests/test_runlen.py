from __future__ import print_function
import deepstate_base
import logrun


class RunlenTest(deepstate_base.DeepStateTestCase):
  def run_deepstate(self, deepstate):
    (r, output) = logrun.logrun([deepstate, "build/examples/Runlen"],
                  "deepstate.out", 2700)
    self.assertEqual(r, 0)

    self.assertTrue("Passed: Runlength_EncodeDecode" in output)
    foundFailSave = False
    for line in output.split("\n"):
      if ("Saving input to" in line) and (".fail" in line):
        foundFailSave = True
    self.assertTrue(foundFailSave)

