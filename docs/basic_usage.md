# Basic usage

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


Table of Contents
=================

  * [Writing test harness](#writing-test-harness)
  * [Running the test](#running-the-test)
  * [Tests replay](#tests-replay)
  * [Test case reduction](#test-case-reduction)
  * [Log Levels](#log-levels)


## Writing a test harness

A simple example test harness is included in the `examples` directory,
to test a (rather silly) run length encoding implementation:

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
is a fairly typical DeepState test harness.  Most of the code is
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


## Running the test

```
~/deepstate/build/examples$ ./Runlen
TRACE: Running: Runlength_EncodeDecode from /Users/alex/deepstate/examples/Runlen.cpp(55)
TRACE: Passed: Runlength_EncodeDecode
TRACE: Running: Runlength_BoringUnitTest from /Users/alex/deepstate/examples/Runlen.cpp(49)
TRACE: Passed: Runlength_BoringUnitTest
```

Executing the DeepState executable will run the "BoringUnitTest" and
"EncodeDecode" tests.
The first one is a traditional hand-written unit test and simply tests
fixed inputs chosen by a programmer. The second one uses default (all zero bytes)
values. These inputs do not expose the bug in `encode`.

Using DeepState's built-in brute-force fuzzer, however, it is easy to find the bug. Just try:

```shell
deepstate-angr ./Runlen --output_test_dir out
```

or

```shell
./Runlen --fuzz --exit_on_fail --output_test_dir out
```

The fuzzer will output something like:

```
INFO: Starting fuzzing
WARNING: No seed provided; using 1546631311
WARNING: No test specified, defaulting to last test defined (Runlength_EncodeDecode)
CRITICAL: /Users/alex/deepstate/examples/Runlen.cpp(60): ORIGINAL: '91c499', ENCODED: '9A1AcA4A9A', ROUNDTRIP: '91c49'
ERROR: Failed: Runlength_EncodeDecode
```


## Test replay

To run saved inputs against the test, just run the executable with appropriate arguments:
```shell
./Runlen --input_test_dir ./out
INFO: Ran 0 tests for Runlength_BoringUnitTest; 0 tests failed
CRITICAL: /home/gros/studia/mgr/fuzzing/tools/deepstate/examples/Runlen.cpp(60): ORIGINAL: 'abbbbb', ENCODED: 'aAbA', ROUNDTRIP: 'ab'
ERROR: Failed: Runlength_EncodeDecode
...
INFO: Ran 64 tests for Runlength_EncodeDecode; 31 tests failed
```

Running tests not in a directory structure created by DeepState
requires using the `--input_test_files_dir` option instead.  And, of
course, a single test can be run using `--input_test_file`.

## Test case reduction

While tests generated by symbolic execution are likely to be highly
concise already, fuzzer-generated tests may be much larger than they
need to be.

DeepState provides a (state-of-the-art) test case reducer to shrink tests intelligently,
using knowledge of the structure of a DeepState test.  For example, if your
executable is named `TestFileSystem` and the test you want to reduce
is named `rmdirfail.test` you would use it like this:

```shell
deepstate-reduce ./TestFileSystem rmdirfail.test minrmdirfail.test
```

In many cases, this will result in finding a different failure or
crash that allows smaller test cases, so you can also provide a string
that controls the criterion for which test outputs are considered valid
reductions (by default, the reducer looks for any test that fails or
crashes).  Only outputs containing the `--criterion` are considered to
be valid reductions (`--regexpCriterion` lets you use a Python regexp
for more complex checks):

```shell
deepstate-reduce ./TestFileSystem create.test mincreate.test --criterion "Assertion failed: ((testfs_inode_get_type(in) == I_FILE)"
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


## Log Levels

By default, DeepState is not very verbose about testing activity,
other than failing tests.  The `DEEPSTATE_LOG` environment variable
or the `--min_log_level` argument lowers the threshold for output,
with 0 = `DEBUG`, 1 = `TRACE` (output from the tests, including from `printf`),
2 = INFO (DeepState messages, the default), 3 = `WARNING`,
4 = `ERROR`, 5 = `EXTERNAL` (output from other programs such as
libFuzzer), and 6 = `CRITICAL` messages.  Lowering the `min_log_level` can be very
useful for understanding what a DeepState harness is actually doing;
often, setting `--min_log_level 1` in either fuzzing or symbolic
execution will give sufficient information to debug your test harness.
