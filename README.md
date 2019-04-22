# DeepState

[![Slack Chat](http://empireslacking.herokuapp.com/badge.svg)](https://empireslacking.herokuapp.com/)

[![Build Status](https://travis-ci.org/trailofbits/deepstate.svg?branch=master)](https://travis-ci.org/trailofbits/deepstate) 

DeepState is a framework that provides C and C++ developers with a common interface to various symbolic execution and fuzzing engines. Users can write one test harness using a Google Test-like API, then execute it using multiple backends without having to learn the complexities of the underlying engines. It supports writing unit tests and API sequence tests, as well as automatic test generation. Read more about the goals and design of DeepState in our [paper](https://agroce.github.io/bar18.pdf).

The
[2018 IEEE Cybersecurity Development Conference](https://secdev.ieee.org/2018/home)
included a
[full tutorial](https://github.com/trailofbits/publications/tree/master/workshops/DeepState:%20Bringing%20vulnerability%20detection%20tools%20into%20the%20development%20lifecycle%20-%20SecDev%202018)
on effective use of DeepState.

There are two blog posts on using DeepState: [Part 1](https://blog.trailofbits.com/2019/01/22/fuzzing-an-api-with-deepstate-part-1/) and [Part 2](https://blog.trailofbits.com/2019/01/23/fuzzing-an-api-with-deepstate-part-2/).

## Overview of Features

* Tests look like Google Test, but can use symbolic execution/fuzzing to generate data (parameterized unit testing)
  * Easier to learn than binary analysis tools/fuzzers, but provides similar functionality
* Already supports Manticore, Angr, libFuzzer, S2E, file-based fuzzing with e.g., AFL; more back-ends likely in future
  * Switch test generation tool without re-writing test harness
    * Work around show-stopper bugs
    * Find out which tool works best for your code under test
    * Different tools find different bugs/vulnerabilities
    * Fair way to benchmark/bakeoff tools
* Provides test replay for regression plus effective automatic test case reduction to aid debugging
* Supports API-sequence generation with extensions to Google Test interface
  * Concise readable way (OneOf) to say "run one of these blocks of code"
  * Same construct supports fixed value set non-determinism
  * E.g., writing a POSIX file system tester is pleasant, not painful as in pure Google Test idioms
* Provides high-level strategies for improving symbolic execution/fuzzing effectiveness
  * Pumping (novel to DeepState) to pick concrete values when symbolic execution is too expensive
  * Automatic decomposition of integer compares to guide coverage-driven fuzzers

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

```shell
sudo apt update && sudo apt-get install build-essential gcc-multilib g++-multilib cmake python python3-setuptools libffi-dev z3
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

The `virtualenv`-enabled `$PATH` should now include two executables: `deepstate` and `deepstate-angr`. These are _executors_, which are used to run DeepState test binaries with specific backends (automatically installed as Python dependencies). The `deepstate` executor uses the Manticore backend while `deepstate-angr` uses angr. They share a common interface where you may specify a number of workers and an output directory for saving backend-generated test cases.

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
to the last-defined test.  Run the native executable with the `--help`
argument to see all DeepState options.

If you want to use DeepState in C/C++ code, you will likely want to run `sudo make install` from the `$DEEPSTATE/build` directory as well.  The examples mentioned below (file system, databases) assume this has already been done.

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

```
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

## Log Levels

By default, DeepState is not very verbose about testing activity,
other than failing tests.  The `--log_level` argument lowers the
threshold for output, with 0 = `DEBUG`, 1 = `TRACE` (output from the
tests, including from `printf`), 2 = INFO (DeepState messages, the default), 3 = `WARNING`,
4 = `ERROR`, 5 = `EXTERNAL` (output from other programs such as
libFuzzer), and 6 = `CRITICAL` messages.  Lowering the `log_level` can be very
useful for understanding what a DeepState harness is actually doing;
often, setting `--log_level 1` in either fuzzing or symbolic
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
libFuzzer.  The `examples` directory shows how this can be done.  The
libFuzzer executable works like any other libFuzzer executable, and
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
the last test defined (which works fine if there is only one test).
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
deepstate-reduce ./TestFileSystem rmdirfail.test minrmdirfail.test
```

In many cases, this will result in finding a different failure or
crash that allows smaller test cases, so you can also provide a string
that controls the criteria for which test outputs are considered valid
reductions (by default, the reducer looks for any test that fails or
crashes).  Only outputs containing the `--criteria` are considered to
be valid reductions:

```shell
deepstate-reduce ./TestFileSystem rmdirfail.test minrmdirfail.test --criteria "FATAL: /root/testfs/super.c(252)"
```

The output will look something like:

```
ORIGINAL TEST HAS 119 BYTES
ONEOF REMOVAL REDUCED TEST TO 103 BYTES
ONEOF REMOVAL REDUCED TEST TO 87 BYTES
ONEOF REMOVAL REDUCED TEST TO 67 BYTES
ONEOF REMOVAL REDUCED TEST TO 51 BYTES
BYTE RANGE REMOVAL REDUCED TEST TO 50 BYTES
BYTE RANGE REMOVAL REDUCED TEST TO 49 BYTES
BYTE REDUCTION: BYTE 3 FROM 4 TO 0
BYTE REDUCTION: BYTE 43 FROM 4 TO 0
ONEOF REMOVAL REDUCED TEST TO 33 BYTES
ONEOF REMOVAL REDUCED TEST TO 17 BYTES
BYTE REDUCTION: BYTE 7 FROM 2 TO 1
BYTE REDUCTION: BYTE 15 FROM 2 TO 1
NO REDUCTIONS FOUND
PADDING TEST WITH 3 ZEROS

WRITING REDUCED TEST WITH 20 BYTES TO minrmdirfail.test
```

You can use `--which_test <testname>` to specify which test to
run, as with the `--input_which_test` options to test replay.

Test case reduction should work on any OS.

## Fuzzing with AFL

DeepState can also be used with a file-based fuzzer (e.g. AFL).  There
are a few steps to this.  First, compile DeepState itself with any
needed instrumentation.  E.g., to use it with AFL, you will want to
set the compilers to `afl-gcc` and `afl-g++` or `afl-clang` and
`afl-clang++` when you `cmake` on your DeepState install:

```
CC=afl-clang CXX=afl-clang++ cmake ..
```

Alternatively, you can edit the `CMakeLists.txt` file and add:

```
SET(CMAKE_C_COMPILER /usr/local/bin/afl-gcc)
SET(CMAKE_CXX_COMPILER /usr/local/bin/afl-g++)
```

Do the same for your DeepState
test harness and any code it links to you want instrumented.  Finally, run the fuzzing via the
interface to replay test files.  For example, to fuzz the `OneOf`
example, if we were in the `deepstate/build/examples` directory, you
would do something like:

```shell
afl-fuzz -d -i corpus -o afl_OneOf -- ./OneOf --input_test_file @@ --abort_on_fail
```

where `corpus` contains at least one file to start fuzzing from.  The
file needs to be smaller than the DeepState input size limit, but has
few other limitations (for AFL it should also not cause test
failure).  The `abort_on_fail` flag makes DeepState crashes and failed
tests appear as crashes to the fuzzer.

To replay the tests from AFL:

```shell
./OneOf --input_test_files_dir afl_OneOf/crashes
./OneOf --input_test_files_dir afl_OneOf/queue
```

Finally, if an example has more than one test, you need to specify,
with a fully qualified name (e.g.,
`Arithmetic_InvertibleMultiplication_CanFail`), which test to run,
using the `--input_which_test` flag to the binary.  By
default, DeepState will run the last test defined.

You can compile with `afl-clang-fast` and `afl-clang-fast++` for
deferred instrumentation.  You'll need code like:

```
#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif
```

just before the call to `DeepState_Run()` (which reads the entire
input file) in your `main`.

Because AFL and other file-based fuzzers only rely on the DeepState
native test executable, they should (like DeepState's built-in simple
fuzzer) work fine on macOS and other Unix-like OSes.  On macOS, you
will want to consider doing the work to use [persistent mode](http://lcamtuf.blogspot.com/2015/06/new-in-afl-persistent-mode.html), or even
running inside a VM, due to AFL (unless in persistent mode) relying
extensively on
forks, which are very slow on macOS.

## Test-case Generation with S2E

To enable S2E support, run CMake with the following options:

```shell
cmake -DBUILD_S2E=On -DS2E_ENV_PATH=/path/to/s2e/environment ../
```

Where `S2E_ENV_PATH` is a path to an S2E environment created with [s2e-env](https://github.com/S2E/s2e-env).

The `deepstate-s2e` command will create analysis projects in your S2E
environment. You can then start the S2E analysis by running `launch-s2e.sh`.
Once the analysis completes tests will be available in the `s2e-last/tests/`
directory.

## Contributing

All accepted PRs are awarded bounties by Trail of Bits. Join the #deepstate channel on the [Empire Hacking Slack](https://empireslacking.herokuapp.com/) to discuss ongoing development and claim bounties. Check the [good first issue](https://github.com/trailofbits/deepstate/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) label for suggested contributions.

## License

DeepState is released under [The Apache License 2.0](LICENSE).
