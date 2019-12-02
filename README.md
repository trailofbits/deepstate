# DeepState

[![Slack Chat](http://empireslacking.herokuapp.com/badge.svg)](https://empireslacking.herokuapp.com/)

[![Build Status](https://travis-ci.org/trailofbits/deepstate.svg?branch=master)](https://travis-ci.org/trailofbits/deepstate)

DeepState is a framework that provides C and C++ developers with a common interface to various symbolic execution and fuzzing engines. Users can write one test harness using a Google Test-like API, then execute it using multiple backends without having to learn the complexities of the underlying engines. It supports writing unit tests and API sequence tests, as well as automatic test generation. Read more about the goals and design of DeepState in our [paper](https://agroce.github.io/bar18.pdf).

The
[2018 IEEE Cybersecurity Development Conference](https://secdev.ieee.org/2018/home)
included a
[full tutorial](https://github.com/trailofbits/publications/tree/master/workshops/DeepState:%20Bringing%20vulnerability%20detection%20tools%20into%20the%20development%20lifecycle%20-%20SecDev%202018)
on effective use of DeepState.

## Articles describing DeepState

* [Fuzzing an API with DeepState (Part 1)](https://blog.trailofbits.com/2019/01/22/fuzzing-an-api-with-deepstate-part-1)
* [Fuzzing an API with DeepState (Part 2)](https://blog.trailofbits.com/2019/01/23/fuzzing-an-api-with-deepstate-part-2)
* [Fuzzing Unit Tests with DeepState and Eclipser](https://blog.trailofbits.com/2019/05/31/fuzzing-unit-tests-with-deepstate-and-eclipser)
* [DeepState Now Supports Ensemble Fuzzing](https://blog.trailofbits.com/2019/09/03/deepstate-now-supports-ensemble-fuzzing/)
* [Everything You Ever Wanted To Know About Test-Case Reduction, But Didn’t Know to Ask](https://blog.trailofbits.com/2019/11/11/test-case-reduction/)

## Overview of Features

* Tests look like Google Test, but can use symbolic execution/fuzzing to generate data (parameterized unit testing)
  * Easier to learn than binary analysis tools/fuzzers, but provides similar functionality
* Already supports Manticore, Angr, libFuzzer, file-based fuzzing with
  e.g., AFL or Eclipser; more back-ends likely in future
  * Switch test generation tool without re-writing test harness
    * Work around show-stopper bugs
    * Find out which tool works best for your code under test
    * Different tools find different bugs/vulnerabilities
    * Fair way to benchmark/bakeoff tools
* Provides test replay for regression [plus effective automatic test case reduction to aid debugging](https://blog.trailofbits.com/2019/11/11/test-case-reduction/)
* Supports API-sequence generation with extensions to Google Test interface
  * Concise readable way (OneOf) to say "run one of these blocks of code"
  * Same construct supports fixed value set non-determinism
  * E.g., writing a POSIX file system tester is pleasant, not painful as in pure Google Test idioms
* Provides high-level strategies for improving symbolic execution/fuzzing effectiveness
  * Pumping (novel to DeepState) to pick concrete values when symbolic execution is too expensive
  * Automatic decomposition of integer compares to guide coverage-driven fuzzers
  * Stong support for automated [swarm testing](https://agroce.github.io/issta12.pdf)

To put it another way, DeepState sits at the intersection of
*property-based testing*, *traditional unit testing*, *fuzzing*, and
*symbolic execution*.  It lets you perform property-based unit testing
using fuzzing or symbolic execution as a back end to generate data, and saves the
results so that what DeepState finds can easily be used in
deterministic settings such as regression testing or CI.

## Supported Platforms

DeepState currently targets Linux, with macOS support in progress
(the fuzzers work fine, but symbolic execution is not well-supported
yet, without a painful cross-compilation process).

## Dependencies

Build:

- CMake
- GCC and G++ with multilib support
- Python 3.6 (or newer)
- Setuptools

Runtime:

- Python 3.6 (or newer)
- Z3 (for the Manticore backend)

## Building on Ubuntu 16.04 (Xenial)

First make sure you install [Python 3.6 or greater](https://askubuntu.com/a/865569). Then use this command line to install additional requirements and compile DeepState:

```shell
sudo apt update && sudo apt-get install build-essential gcc-multilib g++-multilib cmake python3-setuptools libffi-dev z3
git clone https://github.com/trailofbits/deepstate deepstate
mkdir deepstate/build && cd deepstate/build
cmake ../
make
```

## Installing

Assuming the DeepState build resides in `$DEEPSTATE`, run the following commands to install the DeepState python package:

```shell
virtualenv venv
. venv/bin/activate
python $DEEPSTATE/build/setup.py install
```

The `virtualenv`-enabled `$PATH` should now include two executables: `deepstate` and `deepstate-angr`. These are _executors_, which are used to run DeepState test binaries with specific backends (automatically installed as Python dependencies). The `deepstate` or `deepstate-manticore` executor uses the Manticore backend while `deepstate-angr` uses angr. They share a common interface where you may specify a number of workers and an output directory for saving backend-generated test cases.

If you try using Manticore, and it doesn't work, but you definitely have the latest Manticore installed, check the `.travis.yml` file.  If that grabs a Manticore other than the master version, you can try using the version of Manticore we use in our CI tests.  Sometimes Manticore makes a breaking change, and we are behind for a short time.

You can check your build using the test binaries that were (by default) built and emitted to `deepstate/build/examples`. For example, to use angr to symbolically execute the `IntegerOverflow` test harness with 4 workers, saving generated test cases in a directory called `out`, you would invoke:

```shell
deepstate-angr --num_workers 4 --output_test_dir out $DEEPSTATE/build/examples/IntegerOverflow
```

 The resulting `out` directory should look something like:

 ```
 out
└── IntegerOverflow.cpp
    ├── SignedInteger_AdditionOverflow
    │   ├── a512f8ffb2c1bb775a9779ec60b699cb.fail
    │   └── f1d3ff8443297732862df21dc4e57262.pass
    └── SignedInteger_MultiplicationOverflow
        ├── 6a1a90442b4d898cb3fac2800fef5baf.fail
        └── f1d3ff8443297732862df21dc4e57262.pass
```

To run these tests, you can just use the native executable, e.g.:

```shell
$DEEPSTATE/build/examples/IntegerOverflow --input_test_dir out
```

to run all the generated tests, or

```shell
$DEEPSTATE/build/examples/IntegerOverflow --input_test_files_dir out/IntegerOverflow.cpp/SignedInteger_AdditionOverflow --input_which_test SignedInteger_AdditionOverflow
```

to run the tests in one directory (in this case, you want to specify
which test to run, also).  You can also run a single test, e.g.:

```shell
$DEEPSTATE/build/examples/IntegerOverflow --input_test_file out/IntegerOverflow.cpp/SignedInteger_AdditionOverflow/a512f8ffb2c1bb775a9779ec60b699cb.fail--input_which_test SignedInteger_AdditionOverflow
```

In the absence of an `--input_which_test` argument, DeepState defaults
to the first-defined test.  Run the native executable with the `--help`
argument to see all DeepState options.

If you want to use DeepState in C/C++ code, you will likely want to run `sudo make install` from the `$DEEPSTATE/build` directory as well.  The examples mentioned below (file system, databases) assume this has already been done.

### Docker

You can also try out Deepstate with Docker, which is the easiest way
to get all the fuzzers and tools up and running on any system.

```bash
$ docker build -t deepstate . -f docker/Dockerfile
$ docker run -it deepstate bash
user@0f7cccd70f7b:~/deepstate/build/examples$ cd deepstate/build/examples
user@0f7cccd70f7b:~/deepstate/build/examples$ deepstate-angr ./Runlen
user@0f7cccd70f7b:~/deepstate/build/examples$ deepstate-eclipser ./Runlen --timeout 30
user@0f7cccd70f7b:~/deepstate/build/examples$ ./Runlen_LF -max_total_time=30
user@0f7cccd70f7b:~/deepstate/build/examples$ mkdir foo; echo foo > foo/foo
user@0f7cccd70f7b:~/deepstate/build/examples$ afl-fuzz -i foo -o afl_Runlen -- ./Runlen_AFL --input_test_file @@ --no_fork --abort_on_fail
```

## Usage

DeepState consists of a static library, used to write test harnesses,
and command-line _executors_ written in Python. At this time, the best
documentation is in the [examples](/examples) and in our
[paper](https://agroce.github.io/bar18.pdf).  A more extensive
example, using DeepState and libFuzzer to test a user-mode file
system, is available [here](https://github.com/agroce/testfs); in
particular the
[Tests.cpp](https://github.com/agroce/testfs/blob/master/Tests.cpp)
file and CMakeLists.txt show DeepState usage.  Another extensive
example is a [differential tester that compares Google's leveldb and
Facebook's rocksdb](https://github.com/agroce/testleveldb).

## Example Code

```cpp
#include <deepstate/DeepState.hpp>

using namespace deepstate;

/* Simple, buggy, run-length encoding that creates "human readable"
  * encodings by adding 'A'-1 to the count, and splitting at 26.
  * e.g., encode("aaabbbbbc") = "aCbEcA" since C=3 and E=5 */

char* encode(const char* input) {
  unsigned int len = strlen(input);
  char* encoded = (char*)malloc((len*2)+1);
  int pos = 0;
  if (len > 0) {
    unsigned char last = input[0];
    int count = 1;
    for (int i = 1; i < len; i++) {
      if (((unsigned char)input[i] == last) && (count < 26))
	count++;
      else {
	encoded[pos++] = last;
	encoded[pos++] = 64 + count;
	last = (unsigned char)input[i];
	count = 1;
      }
    }
    encoded[pos++] = last;
    encoded[pos++] = 65; // Should be 64 + count
  }
  encoded[pos] = '\0';
  return encoded;
}

char* decode(const char* output) {
  unsigned int len = strlen(output);
  char* decoded = (char*)malloc((len/2)*26);
  int pos = 0;
  for (int i = 0; i < len; i += 2) {
    for (int j = 0; j < (output[i+1] - 64); j++) {
      decoded[pos++] = output[i];
    }
  }
  decoded[pos] = '\0';
  return decoded;
}

// Can be (much) higher (e.g., > 1024) if we're using fuzzing, not symbolic execution
#define MAX_STR_LEN 6

TEST(Runlength, BoringUnitTest) {
  ASSERT_EQ(strcmp(encode(""), ""), 0);
  ASSERT_EQ(strcmp(encode("a"), "aA"), 0);
  ASSERT_EQ(strcmp(encode("aaabbbbbc"), "aCbEcA"), 0);
}

TEST(Runlength, EncodeDecode) {
  char* original = DeepState_CStrUpToLen(MAX_STR_LEN, "abcdef0123456789");
  char* encoded = encode(original);
  ASSERT_LE(strlen(encoded), strlen(original)*2) << "Encoding is > length*2!";
  char* roundtrip = decode(encoded);
  ASSERT_EQ(strncmp(roundtrip, original, MAX_STR_LEN), 0) <<
    "ORIGINAL: '" << original << "', ENCODED: '" << encoded <<
    "', ROUNDTRIP: '" << roundtrip << "'";
}
```

The code above (which can be found
[here](https://github.com/trailofbits/deepstate/blob/master/examples/Runlen.cpp))
shows an example of a DeepState test harness.  Most of the code is
just the functions to be tested.  Using DeepState to test them requires:

- Including the DeepState C++ header and using the DeepState namespace

- Defining at least one TEST, with names

- Calling some DeepState APIs that produce data
   - In this example, we see the `DeepState_CStrUpToLen` call tells
     DeepState to produce a string that has up to `MAX_STR_LEN`
     characters, chosen from those present in hex strings.

- Optionally making some assertions about the correctness of the
results
   - In `Runlen.cpp` this is the `ASSERT_LE` and `ASSERT_EQ` checks.
   - In the absence of any properties to check, DeepState can still
     look for memory safety violations, crashes, and other general
     categories of undesirable behavior, like any fuzzer.

DeepState will also run the "BoringUnitTest," but it (like a
traditional hand-written unit test) is simply a test of fixed inputs
devised by a programmer.  These inputs do not expose the bug in
`encode`.  Nor do the default values (all zero bytes) for the DeepState test:

```
~/deepstate/build/examples$ ./Runlen
TRACE: Running: Runlength_EncodeDecode from /Users/alex/deepstate/examples/Runlen.cpp(55)
TRACE: Passed: Runlength_EncodeDecode
TRACE: Running: Runlength_BoringUnitTest from /Users/alex/deepstate/examples/Runlen.cpp(49)
TRACE: Passed: Runlength_BoringUnitTest
```

Using DeepState, however, it is easy to find the bug.  Just
go into the `$DEEPSTATE/build/examples` directory and try:

```shell
deepstate-angr ./Runlen
```

or

```shell
./Runlen --fuzz --exit_on_fail
```

The fuzzer will output something like:

```
INFO: Starting fuzzing
WARNING: No seed provided; using 1546631311
WARNING: No test specified, defaulting to last test defined (Runlength_EncodeDecode)
CRITICAL: /Users/alex/deepstate/examples/Runlen.cpp(60): ORIGINAL: '91c499', ENCODED: '9A1AcA4A9A', ROUNDTRIP: '91c49'
ERROR: Failed: Runlength_EncodeDecode
```

If you're using the DeepState docker, it's easy to also try libFuzzer
and AFL on the Runlen example:

```shell
mkdir libfuzzer_runlen
./Runlen_LF libfuzzer_runlen -max_total_time=30
./Runlen --input_test_files_dir libfuzzer_runlen
```

And you'll see a number of failures, e.g.:
```
WARNING: No test specified, defaulting to last test defined (Runlength_EncodeDecode)
CRITICAL: /home/user/deepstate/examples/Runlen.cpp(60): ORIGINAL: '4af4aa', ENCODED: '4AaAfA4AaA', ROUNDTRIP: '4af4a'
ERROR: Failed: Runlength_EncodeDecode
ERROR: Test case libfuzzer_runlen//9e266f6cb627ce3bb7d717a6e569ade6b3633f23 failed
CRITICAL: /home/user/deepstate/examples/Runlen.cpp(60): ORIGINAL: 'aaaaaa', ENCODED: 'aA', ROUNDTRIP: 'a'
ERROR: Failed: Runlength_EncodeDecode
ERROR: Test case libfuzzer_runlen//d8fc60ccdd8f555c1858b9f0820f263e3d2b58ec failed
CRITICAL: /home/user/deepstate/examples/Runlen.cpp(60): ORIGINAL: '4aaa', ENCODED: '4AaA', ROUNDTRIP: '4a'
ERROR: Failed: Runlength_EncodeDecode
ERROR: Test case libfuzzer_runlen//3177c75208f2d35399842196dc8093243d5a8243 failed
CRITICAL: /home/user/deepstate/examples/Runlen.cpp(60): ORIGINAL: 'aaa', ENCODED: 'aA', ROUNDTRIP: 'a'
ERROR: Failed: Runlength_EncodeDecode
ERROR: Test case libfuzzer_runlen//9842926af7ca0a8cca12604f945414f07b01e13d failed
CRITICAL: /home/user/deepstate/examples/Runlen.cpp(60): ORIGINAL: 'aaa', ENCODED: 'aA', ROUNDTRIP: 'a'
ERROR: Failed: Runlength_EncodeDecode
ERROR: Test case libfuzzer_runlen//85e53271e14006f0265921d02d4d736cdc580b0b failed
CRITICAL: /home/user/deepstate/examples/Runlen.cpp(60): ORIGINAL: 'aaaaa', ENCODED: 'aA', ROUNDTRIP: 'a'
ERROR: Failed: Runlength_EncodeDecode
ERROR: Test case libfuzzer_runlen//241cbd6dfb6e53c43c73b62f9384359091dcbf56 failed
CRITICAL: /home/user/deepstate/examples/Runlen.cpp(60): ORIGINAL: 'aa', ENCODED: 'aA', ROUNDTRIP: 'a'
ERROR: Failed: Runlength_EncodeDecode
ERROR: Test case libfuzzer_runlen//05a79f06cf3f67f726dae68d18a2290f6c9a50c9 failed
CRITICAL: /home/user/deepstate/examples/Runlen.cpp(60): ORIGINAL: '25aaaa', ENCODED: '2A5AaA', ROUNDTRIP: '25a'
ERROR: Failed: Runlength_EncodeDecode
ERROR: Test case libfuzzer_runlen//419c3b754bacd6fc14ff9a932c5e2089d6dfcab5 failed
CRITICAL: /home/user/deepstate/examples/Runlen.cpp(60): ORIGINAL: 'aaaa', ENCODED: 'aA', ROUNDTRIP: 'a'
ERROR: Failed: Runlength_EncodeDecode
ERROR: Test case libfuzzer_runlen//bb589d0621e5472f470fa3425a234c74b1e202e8 failed
CRITICAL: /home/user/deepstate/examples/Runlen.cpp(60): ORIGINAL: '97aa', ENCODED: '9A7AaA', ROUNDTRIP: '97a'
ERROR: Failed: Runlength_EncodeDecode
ERROR: Test case libfuzzer_runlen//ca61c43b0e3ff0a8eccf3136996c9f1d9bfd627c failed
INFO: Ran 16 tests; 10 tests failed
```

Using AFL is similarly easy:

```shell
mkdir afl_seeds
echo "ok" >& seeds/seed
afl-fuzz -i seeds -o afl_runlen -- ./Runlen_AFL --input_test_file @@ --no_fork --abort_on_fail
```

You'll have to stop this with Ctrl-C.  The `afl_runlen/crashes`
directory will contain crashing inputs AFL found.

## Log Levels

By default, DeepState is not very verbose about testing activity,
other than failing tests.  The `--min_log_level` argument lowers the
threshold for output, with 0 = `DEBUG`, 1 = `TRACE` (output from the
tests, including from `printf`), 2 = INFO (DeepState messages, the default), 3 = `WARNING`,
4 = `ERROR`, 5 = `EXTERNAL` (output from other programs such as
libFuzzer), and 6 = `CRITICAL` messages.  Lowering the `min_log_level` can be very
useful for understanding what a DeepState harness is actually doing;
often, setting `--min_log_level 1` in either fuzzing or symbolic
execution will give sufficient information to debug your test harness.


## Built-In Fuzzer

Every DeepState executable provides a simple built-in fuzzer that
generates tests using completely random data.  Using this fuzzer is as
simple as calling the native executable with the `--fuzz` argument.
The fuzzer also takes a `seed` and `timeout` (default of two minutes)
to control the fuzzing.   By default fuzzing saves
only failing and crashing tests, and these only when given an output
directory.  If you want to actually save the test cases
generated, you need to add a `--output_test_dir` argument to tell
DeepState where to put the generated tests, and if you want the
(totally random and unlikely to be high-quality) passing tests, you
need to add `--fuzz_save_passing`.

Note that while symbolic execution only works on Linux, without a
fairly complex cross-compilation process, the brute force fuzzer works
on macOS or (as far as we know) any Unix-like system.

## A Note on MacOS and Forking

Normally, when running a test for replay or fuzzing, DeepState forks
in order to cleanly handle crashes of a test.  Unfortunately, `fork()`
on macOS is _extremely_ slow.  When using the built-in fuzzer or
replaying more than a few tests, it is highly recommended to add the `--no_fork`
option on macOS, unless you need the added crash handling (that is,
only when things aren't working without that option).

## Fuzzing with libFuzzer

If you install clang 6.0 or later, and run `cmake` when you install
with the `BUILD_LIBFUZZER` environment variable defined, you can
generate tests using libFuzzer.  Because both DeepState and libFuzzer
want to be `main`, this requires building a different executable for
libFuzzer.  The `examples` directory shows how this can be done: just
compile with a libFuzzer-supporting clang, and add `-fsanitize=fuzzer`
as an option, and link to the right DeepState library
(`-ldeepstate_LF`).  The
libFuzzer executable thus produced works like any other libFuzzer executable, and
the tests produced can be replayed using the normal DeepState executable.
For example, generating some tests of the `OneOf` example (up to 5,000
runs), then running those tests to examine the results, would look
like:

```shell
mkdir OneOf_libFuzzer_corpus
./OneOf_LF -runs=5000 OneOf_libFuzzer_corpus
./OneOf --input_test_files_dir OneOf_libFuzzer_corpus
```

Use the `LIBFUZZER_WHICH_TEST`
environment variable to control which test libFuzzer runs, using a
fully qualified name (e.g.,
`Arithmetic_InvertibleMultiplication_CanFail`).  By default, you get
the first test defined (which works fine if there is only one test).
Obviously, libFuzzer may work better if you provide a non-empty
corpus, but fuzzing will work even without an initial corpus, unlike AFL.

One hint when using libFuzzer is to avoid dynamically allocating
memory during a test, if that memory would not be freed on a test
failure.  This will leak memory and libFuzzer will run out of memory
very quickly in each fuzzing session.  Using libFuzzer on macOS
requires compiling DeepState and your program with a clang that
supports libFuzzer (which the Apple built-in probably won't); this can be as simple as doing:

```shell
brew install llvm@7
CC=/usr/local/opt/llvm\@7/bin/clang CXX=/usr/local/opt/llvm\@7/bin/clang++ BUILD_LIBFUZZER=TRUE cmake ..
make install
```

Other ways of getting an appropriate LLVM may also work.

On macOS, libFuzzer's normal output is not visible.  Because libFuzzer
does not fork to execute tests, there is no issue with fork speed on
macOS for this kind of fuzzing.

On any platform,
you can see more about what DeepState under libFuzzer is doing by
setting the `LIBFUZZER_LOUD` environment variable, and tell libFuzzer
to stop upon finding a failing test using `LIBFUZZER_EXIT_ON_FAIL`.

## Test case reduction

While tests generated by symbolic execution are likely to be highly
concise already, fuzzer-generated tests may be much larger than they
need to be.

DeepState provides a test case reducer to shrink tests intelligently,
aware of the structure of a DeepState test.  For example, if your
executable is named `TestFileSystem` and the test you want to reduce
is named `rmdirfail.test` you would use it like this:

```shell
deepstate-reduce ./TestFileSystem create.test mincreate.test
```

In many cases, this will result in finding a different failure or
crash that allows smaller test cases, so you can also provide a string
that controls the criterion for which test outputs are considered valid
reductions (by default, the reducer looks for any test that fails or
crashes).  Only outputs containing the `--criterion` are considered to
be valid reductions (`--regexpCriterion` lets you use a Python regexp
for more complex checks):

```shell
deepstate-reduce ./TestFileSystem create.test mincreate.test --criteria "Assertion failed: ((testfs_inode_get_type(in) == I_FILE)"
```

The output will look something like:

```
Original test has 8192 bytes
Applied 128 range conversions
Last byte read: 527
Shrinking to ignore unread bytes
Writing reduced test with 528 bytes to rnew
================================================================================
Iteration #1 0.39 secs / 2 execs / 0.0% reduction
Structured deletion reduced test to 520 bytes
Writing reduced test with 520 bytes to rnew
0.77 secs / 3 execs / 1.52% reduction

...

Structured swap: PASS FINISHED IN 0.01 SECONDS, RUN: 5.1 secs / 151 execs / 97.54% reduction
Reduced byte 12 from 4 to 1
Writing reduced test with 13 bytes to rnew
5.35 secs / 169 execs / 97.54% reduction
================================================================================
Byte reduce: PASS FINISHED IN 0.5 SECONDS, RUN: 5.6 secs / 186 execs / 97.54% reduction
================================================================================
Iteration #2 5.6 secs / 186 execs / 97.54% reduction
Structured deletion: PASS FINISHED IN 0.03 SECONDS, RUN: 5.62 secs / 188 execs / 97.54% reduction
Structured edge deletion: PASS FINISHED IN 0.03 SECONDS, RUN: 5.65 secs / 190 execs / 97.54% reduction
1-byte chunk removal: PASS FINISHED IN 0.19 SECONDS, RUN: 5.84 secs / 203 execs / 97.54% reduction
4-byte chunk removal: PASS FINISHED IN 0.19 SECONDS, RUN: 6.03 secs / 216 execs / 97.54% reduction
8-byte chunk removal: PASS FINISHED IN 0.19 SECONDS, RUN: 6.22 secs / 229 execs / 97.54% reduction
1-byte reduce and delete: PASS FINISHED IN 0.04 SECONDS, RUN: 6.26 secs / 232 execs / 97.54% reduction
4-byte reduce and delete: PASS FINISHED IN 0.03 SECONDS, RUN: 6.29 secs / 234 execs / 97.54% reduction
8-byte reduce and delete: PASS FINISHED IN 0.01 SECONDS, RUN: 6.31 secs / 235 execs / 97.54% reduction
Byte range removal: PASS FINISHED IN 0.76 SECONDS, RUN: 7.06 secs / 287 execs / 97.54% reduction
Structured swap: PASS FINISHED IN 0.01 SECONDS, RUN: 7.08 secs / 288 execs / 97.54% reduction
================================================================================
Completed 2 iterations: 7.08 secs / 288 execs / 97.54% reduction
Padding test with 23 zeroes
Writing reduced test with 36 bytes to mincreate.test
```

You can use `--which_test <testname>` to specify which test to
run, as with the `--input_which_test` options to test replay.  If you
find that test reduction is taking too long, you can try the `--fast`
option to get a quick-and-dirty reduction, and later use the default
settings, or even `--slowest` setting to try to reduce it further.

Test case reduction should work on any OS.

## Fuzzing with AFL

DeepState can also be used with a file-based fuzzer (e.g. AFL).   If
you compile using `afl-clang++` and `afl-clang`, and link with
`-ldeepstate_AFL` when working with AFL. `deepstate-afl` then gives
you an easy front-end for running AFL.

For example, to fuzz the `OneOf`
example, if we were in the `deepstate/build/examples` directory (and had
built an AFL executable for it), you
would do something like:

```shell
deepstate-afl ./OneOf_afl -i corpus --output_test_dir afl_OneOf_out
```

where `corpus` contains at least one file to start fuzzing from.  The
file needs to be smaller than the DeepState input size limit, but has
few other limitations (for AFL it should also not cause test
failure).  The `abort_on_fail` flag makes DeepState crashes and failed
tests appear as crashes to the fuzzer.  
To replay the tests from AFL:

```shell
./OneOf --input_test_files_dir afl_OneOf_out/crashes
./OneOf --input_test_files_dir afl_OneOf_out/queue
```

Finally, if an example has more than one test, you need to specify,
with a fully qualified name (e.g.,
`Arithmetic_InvertibleMultiplication_CanFail`), which test to run,
using the `--input_which_test` flag.  By
default, DeepState will run the first test defined.

Because AFL and other file-based fuzzers only rely on the DeepState
native test executable, they should (like DeepState's built-in simple
fuzzer) work fine on macOS and other Unix-like OSes.  On macOS, you
will want to consider doing the work to use [persistent mode](http://lcamtuf.blogspot.com/2015/06/new-in-afl-persistent-mode.html), or even
running inside a VM, due to AFL (unless in persistent mode) relying
extensively on
forks, which are very slow on macOS.

## Fuzzing with Eclipser

[Eclipser](https://github.com/SoftSec-KAIST/Eclipser) is a powerful new fuzzer/grey-box concolic tool
with some of the advantages of symbolic execution, but with more scalability.  DeepState supports Eclipser out of the box.  To use it, you just need to

- Install Eclipser as instructed at https://github.com/SoftSec-KAIST/Eclipser (you'll need to be on Linux)
- Set the `ECLIPSER_HOME` environment variable to where-ever you installed Eclipser (the root, above `build`)
- Make sure you compile your DeepState native without any sanitizers (QEMU, used by Eclipser, doesn't like them)

After that, you can use Eclipser like this:

`deepstate-eclipser <binary> --timeout <how long to test> --output_test_dir <where to put generated tests>`

In our experience, Eclipser is quite effective, often better than
libFuzzer and sometimes better than AFL, despite having a much slower
test throughput than either.

## Which Fuzzer Should I Use?

In fact, since DeepState supports libFuzzer, AFL, and Eclipser (and
others), a natural question is "which is the best fuzzer?"  In
general, it depends!  We suggest using them all, which DeepState makes
easy.  libFuzzer is very fast, and sometimes the CMP breakdown it
provides is very useful; however, it's often bad at finding longer
paths where just covering nodes isn't helpful.  AFL is still an
excellent general-purpose fuzzer, and often beats "improved" versions
over a range of programs.  Finally, Eclipser has some tricks that let
it get traction in some cases where you might think only symbolic
execution (which wouldn't scale) could help.

## Swarm Testing

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
declaring the code bug-free!

Note that tests produced under a particular swarm option are _not_
binary compatible with other settings for swarm, due to the added coin flips.

## Contributing

All accepted PRs are awarded bounties by Trail of Bits. Join the #deepstate channel on the [Empire Hacking Slack](https://empireslacking.herokuapp.com/) to discuss ongoing development and claim bounties. Check the [good first issue](https://github.com/trailofbits/deepstate/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) label for suggested contributions.

## License

DeepState is released under [The Apache License 2.0](LICENSE).
