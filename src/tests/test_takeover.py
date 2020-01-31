from __future__ import print_function
import logrun
import deepstate_base


class TakeOverTest(deepstate_base.DeepStateTestCase):
  def run_deepstate(self, deepstate):
    (r, output) = logrun.logrun([deepstate, "build/examples/TakeOver", "--take_over"],
                  "deepstate.out", 1800)
    self.assertEqual(r, 0)

    self.assertTrue("hi" in output)
    self.assertTrue("bye" in output)
    self.assertTrue("was not greater than" in output)

    foundPassSave = False
    for line in output.split("\n"):
      if ("Saved test case" in line) and (".pass" in line):
        foundPassSave = True
    self.assertTrue(foundPassSave)
