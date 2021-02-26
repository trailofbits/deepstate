from __future__ import print_function
import os
import deepstate_base
import logrun


class SanityCheck(deepstate_base.DeepStateTestCase):
  def run_deepstate(self, deepstate):
    if deepstate != "--fuzz":
      return
    os.mkdir("OneOf_out")
    (r, output) = logrun.logrun(["build/examples/OneOf",
                                  "--fuzz",
                                  "--timeout", "30",
                                  "--no_fork",
                                  "--output_test_dir", "OneOf_out",
                                  "--min_log_level", "2",
                                   ],
                  "deepstate.out", 1800)

    self.assertTrue("Failed: OneOfExample_ProduceSixtyOrHigher" in output)
    self.assertTrue("Saved test case in file" in output)
    foundFinish = False
    for line in output.split("\n"):
      if "Done fuzzing!" in line:
        foundFinish = True
        perSecond = int(line.split(" tests/second")[0].split("(")[1])
        self.assertTrue(perSecond > 5000)
    self.assertTrue(foundFinish)

