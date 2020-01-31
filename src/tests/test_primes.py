from __future__ import print_function
import logrun
import deepstate_base


class PrimesTest(deepstate_base.DeepStateTestCase):
  def run_deepstate(self, deepstate):
    (r, output) = logrun.logrun([deepstate, "--timeout", "15", "build/examples/Primes"],
                  "deepstate.out", 1800)
    self.assertEqual(r, 0)

    self.assertTrue("Failed: PrimePolynomial_OnlyGeneratesPrimes" in output)
    self.assertTrue("Failed: PrimePolynomial_OnlyGeneratesPrimes_NoStreaming" in output)

    # TODO(alan): determine why passed cases aren't being logged to stdout
    #self.assertTrue("Passed: PrimePolynomial_OnlyGeneratesPrimes" in output)
    #self.assertTrue("Passed: PrimePolynomial_OnlyGeneratesPrimes_NoStreaming" in output)
