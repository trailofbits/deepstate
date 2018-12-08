# DeepState

[![Slack Chat](http://empireslacking.herokuapp.com/badge.svg)](https://empireslacking.herokuapp.com/)

[![Build Status](https://travis-ci.org/trailofbits/deepstate.svg?branch=master)](https://travis-ci.org/trailofbits/deepstate) 

DeepState is a framework that provides C and C++ developers with a common interface to various symbolic execution and fuzzing engines. Users can write one test harness using a Google Test-like API, then execute it using multiple backends without having to learn the complexities of the underlying engines. It supports writing unit tests and API sequence tests, as well as automatic test generation. Read more about the goals and design of DeepState in our [paper](https://agroce.github.io/bar18.pdf).

The [2018 IEEE Cybersecurity Development Conference](https://secdev.ieee.org/2018/home) included a [full tutorial](https://github.com/trailofbits/publications/tree/master/workshops/DeepState:%20Bringing%20vulnerability%20detection%20tools%20into%20the%20development%20lifecycle%20-%20SecDev%202018) on effective use of DeepState.

## Overview of Features

* Tests look like Google Test, but can use symbolic execution/fuzzing to generate data (parameterized unit testing)
  * Easier to learn than binary analysis tools/fuzzers, but provides similar functionality
* Already supports Manticore, Angr, libFuzzer, file-based fuzzing with e.g., AFL; more back-ends likely in future
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

## Supported Platforms

DeepState currently targets Linux, with macOS support in progress
(some fuzzers work fine, but symbolic execution is not well-supported
yet, without a painful cross-compilation process).

## Dependencies

Build:

- CMake
- GCC and G++ with multilib support
- Python 2.7
- Setuptools

Runtime:

- Python 2.7
- Z3 (for the Manticore backend)

## Building on Ubuntu 16.04 (Xenial)

```shell
sudo apt update && sudo apt-get install build-essential gcc-multilib g++-multilib cmake python python-setuptools libffi-dev z3
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

## Usage

DeepState consists of a static library, used to write test harnesses, and command-line _executors_ written in Python. At this time, the best documentation is in the [examples](/examples) and in our [paper](https://agroce.github.io/bar18.pdf).  A more extensive example, using DeepState and libFuzzer to test a user-mode file system, is available [here](https://github.com/agroce/testfs); in particular the [Tests.cpp](https://github.com/agroce/testfs/blob/master/Tests.cpp) file and CMakeLists.txt show DeepState usage.

## Built-In Fuzzer

Every DeepState executable provides a simple built-in fuzzer that
generates tests using completely random data.  Using this fuzzer is as
simple as calling the native executable with the `--fuzz` argument.
The fuzzer also takes a `seed` and `timeout` (default of two minutes)
to control the fuzzing.  If you want to actually save the test cases
generated, you need to add a `--output_test_dir` arument to tell
DeepState where to put the generated tests.  By default fuzzing saves
only failing and crashing tests.  One more command line argument that
is particularly useful for fuzzing is the `--log_level` argument,
which controls how much output each test produces.  By default, this
is set to show all the logging from your tests, which slows fuzzing,
but setting it to 2 or higher will only show messages produced by
tests failing or crashing.

Note that while symbolic execution only works on Linux, without a 
fairly complex cross-compliation process, the brute force fuzzer works 
on macOS or (as far as we know) any Unix-like system.

## Fuzzing with libFuzzer

If you install clang 6.0 or later, and run `cmake` when you install
with the `BUILD_LIBFUZZER` environment variable defined, you can
generate tests using LlibFuzzer.  Because both DeepState and libFuzzer
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
very quickly in each fuzzing session.  In theory, libFuzzer will work
on macOS, but getting everything to build with the right version of
clang can be difficult, since the Apple-provided LLVM is unlikely to
support libFuzzer on many versions of the operating system.

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
needed instrumentation.  E.g., to use it with AFL, you might want to add
something like:

```
SET(CMAKE_C_COMPILER /usr/local/bin/afl-gcc)
SET(CMAKE_CXX_COMPILER /usr/local/bin/afl-g++)
```

to `deepstate/CMakeLists.txt`.  Second, do the same for your DeepState
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
fuzzer) work fine on macOS and other Unix-like OSes.

## Contributing

All accepted PRs are awarded bounties by Trail of Bits. Join the #deepstate channel on the [Empire Hacking Slack](https://empireslacking.herokuapp.com/) to discuss ongoing development and claim bounties. Check the [good first issue](https://github.com/trailofbits/deepstate/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) label for suggested contributions.

## License

DeepState is released under [The Apache License 2.0](LICENSE).
