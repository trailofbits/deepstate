from __future__ import print_function
import deepstate_base
import logrun


class CrashTest(deepstate_base.DeepStateTestCase):
  def run_deepstate(self, deepstate):
    (r, output) = logrun.logrun([deepstate, "build/examples/Crash"],
                  "deepstate.out", 1800)
    self.assertEqual(r, 0)

    self.assertTrue("Passed: Crash_SegFault" in output)
    foundCrashSave = False
    for line in output.split("\n"):
      if ("Saving input to" in line) and (".crash" in line):
        foundCrashSave = True
        crashLocation = line.split()[-1]
    self.assertTrue(foundCrashSave)

    (r, output) = logrun.logrun(["build/examples/Crash", "--input_test_file", crashLocation],
                                "deepstate.out", 30)
    self.assertEqual(r, 0)
    self.assertTrue("ERROR: Crashed: Crash_SegFault" in output)
