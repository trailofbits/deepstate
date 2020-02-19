# Swarm Testing

[Swarm testing](https://agroce.github.io/issta12.pdf) is an approach
to test generation that [modifies the distributions of finite choices](https://blog.regehr.org/archives/591)
(e.g., string generation and `OneOf` choices of which functions to
call).  It has a long history of improving compiler testing, and
usually (but not always) API testing.  The Hypothesis Python testing
tool
[recently added swarm to its' stable of heuristics](https://github.com/HypothesisWorks/hypothesis/pull/2238).

The basic idea is simple.  Let's say we are generating tests of a
stack that overflows when a 64th item is pushed on the stack, due to a
typo in the overflow check.  Our tests are
256 calls to push/pop/top/clear.  Obviously the odds of getting 64
pushes in a row, without popping or clearing, are very low (for a dumb
fuzzer, the odds are astronomically low).
Coverage-feedback and various byte-copying heuristics in AFL and
libFuzzer etc. can sometimes work around such problems, but in other,
more complex cases, they are stumped.  Swarm testing "flips a coin"
before each test, and only includes API calls in the test if the coin
came up heads for that test.  That means we just need some test to run
with heads for push and tails for pop and clear.

DeepState supports fully automated swarm testing.  Just compile your
harness with `-DDEEPSTATE_PURE_SWARM` and all your `OneOf`s _and_
DeepState string generation functions will use swarm testing.  This is
a huge help for the built-in fuzzer (for example, it more than doubles
the fault detection rate for the `Runlen` example above).  Eclipser
can get "stuck" with swarm testing, but AFL and libFuzzer can
certainly sometimes benefit from swarm testing.  There is also an option
`-DDEEPSTATE_MIXED_SWARM` that mixes swarm and regular generation.  It
flips an additional coin for each potentially swarmable thing, and
decides to use swarm or not for that test.  This can produce a mix of
swarm and regular generation that is unique to DeepState.  If you
aren't finding any bugs using a harness that involves `OneOf` or
generating strings, it's a good idea to try both swarm methods before
declaring the code bug-free! There is another, more experimental,
swarm-like method, `-DDEEPSTATE_PROB_SWARM`, that is of possible interest.
Instead of pure binary inclusion/exclusion of choices, this varies the
actual distribution of choices.  However, because this often ends up behaving
more like a non-swarm selection, it may not be as good at ferreting out
unusual behaviors due to extreme imbalance of choices.

Note that tests produced under a particular swarm option are _not_
binary compatible with other settings for swarm, due to the added coin flips.
