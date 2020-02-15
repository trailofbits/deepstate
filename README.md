# DeepState

[![Slack Chat](http://empireslacking.herokuapp.com/badge.svg)](https://empireslacking.herokuapp.com/)

[![Build Status](https://img.shields.io/github/workflow/status/trailofbits/deepstate/CI/master)](https://github.com/trailofbits/deepstate/actions?query=workflow%3ACI)

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
$ docker build -t deepstate-base -f docker/base/Dockerfile docker/base
$ docker build -t deepstate --build-arg make_j=6 -f ./docker/Dockerfile .
$ docker run -it deepstate bash
user@a17bc44fd259:~/deepstate$ export DEEPSTATE_HOME="$HOME/deepstate"
user@a17bc44fd259:~/deepstate$ cd $DEEPSTATE_HOME/build/examples
user@a17bc44fd259:~/deepstate/build/examples$ deepstate-angr ./Runlen
user@a17bc44fd259:~/deepstate/build/examples$ mkdir tmp && deepstate-eclipser ./Runlen -o tmp --timeout 30 --fuzzer_out
user@a17bc44fd259:~/deepstate/build/examples$ cd $DEEPSTATE_HOME/build_libfuzzer/examples
user@a17bc44fd259:~/deepstate/build_libfuzzer/examples$ ./Runlen_LF -max_total_time=30
user@a17bc44fd259:~/deepstate/build_libfuzzer/examples$ cd $DEEPSTATE_HOME/build_afl/examples
user@a17bc44fd259:~/deepstate/build_afl/examples$ mkdir foo && echo x > foo/x && mkdir afl_Runlen2
user@a17bc44fd259:~/deepstate/build_afl/examples$  $AFL_HOME/afl-fuzz -i foo -o afl_Runlen -- ./Runlen_AFL --input_test_file @@ --no_fork --abort_on_fail
user@a17bc44fd259:~/deepstate/build_afl/examples$ deepstate-afl -o afl_Runlen2 ./Runlen_AFL
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

## External fuzzers

DeepState currently support five external fuzzers:
[libFuzzer](https://llvm.org/docs/LibFuzzer.html),
[AFL](http://lcamtuf.coredump.cx/afl),
[HonggFuzz](https://github.com/google/honggfuzz),
[Eclipser](https://github.com/SoftSec-KAIST/Eclipser) and
[Angora](https://github.com/AngoraFuzzer/Angora).

To use one of them as DeepState backend, you need to:
* install it
* compile DeepState with it
* compile target test with it
* run executor with location of installed files provided

To install the fuzzer follow instructions on appropriate webpage.

To compile DeepState with the fuzzer, run `cmake` with
`-DDEEPSTATE_FUZZERNAME=on` (like `-DDEEPSTATE_AFL=on`) option and
`CC/CXX` variables set to the fuzzer's compiler. This will produce
library called `libdeepstate_FUZZERNAME.a`, which you may put to
standard location (`/usr/local/lib/`).

To compile target test, use fuzzer's compiler and link with appropriate
DeepState library (`-ldeepstate_FUZZERNAME`).

To provide location of fuzzer's executables to python executor you may:
* put the executables to some $PATH location
* export `FUZZERNAME_HOME` environment variable (like `ANGORA_HOME`)
with value set to the location of fuzzer's executables
* specify `--home_path` argument when running the executor

All that, rather complicated setup may be simplified with Docker.
Just build the image (changing OS in `./docker/base/Dockerfile` if needed)
and use it with your project. All the fuzzers and evironment variables will be there.

### Fuzzer executors usage

Fuzzer executors (`deepstate-honggfuzz` etc.) are meant to be as uniform
as possible, thus making it easy to compile and run tests.

Compilation: `deepstate-afl --compile_test ./SimpleCrash.cpp --out_test_name SimpleCrash`

Run: `mkdir out && deepstate-afl --output_test_dir out ./SimpleCrash.afl`

The only required arguments are location of output directory and the test.
Optional arguments:
```
--input_seeds     - location of directory with initial inputs 
--max_input_size  - maximal length of inputs
--exec_timeout    - timeout for run on one input file
--timeout         - timeout for whole fuzzing process
--fuzzer_out      - use fuzzer output rather that deepstate (uniform) one
--mem_limit       - memory limit for the fuzzer
--min_log_level   - how much to log (0=DEBUG, 6=CRITICAL)
--blackbox        - fuzz not-instrumented binary
--dictionary      - file with words that may enhance fuzzing (fuzzer dependent format)
```

Each fuzzer creates following files/directories under output directory:
```
* deepstate-stats.txt - some statistic parsed by executor
* fuzzer-output.txt   - all stdout/stderr from the fuzzer
* PUSH_DIR            - fuzzer will take (synchronize) additional inputs from here
* PULL_DIR            - fuzzer will save produced inputs here (may be the same as PUSH_DIR)
* CRASH_DIR           - fuzzer will save crashes here
```

Failed tests are treated as crashes when using fuzzer executors
(because of `--abort_on_fail` flag).

Note that some fuzzers (notably AFL) requires input seeds. When not provided,
executor will create a dumb one, which may be not very efficient for fuzzing.

Input files need to be smaller than the DeepState input size limit (8192 bytes),
which is the default limit in executors. But not all fuzzers support file size
limitation, so if your test cases grown too large, you may need to stop fuzzing
and minimalize them.

Also, there should not be crash-producing files inside input seeds directory.

Because AFL and other file-based fuzzers only rely on the DeepState
native test executable, they should (like DeepState's built-in simple
fuzzer) work fine on macOS and other Unix-like OSes.  On macOS, you
will want to consider doing the work to use [persistent mode](http://lcamtuf.blogspot.com/2015/06/new-in-afl-persistent-mode.html), or even
running inside a VM, due to AFL (unless in persistent mode) relying
extensively on forks, which are very slow on macOS.

#### AFL

```bash
$ cd ./deepstate
$ mkdir -p build_afl && cd build_afl
$ export AFL_HOME="/afl-2.52b"
$ CXX="$AFL_HOME/afl-clang++" CC="$AFL_HOME/afl-clang" cmake -DDEEPSTATE_AFL=ON ../
$ make -j4
$ sudo cp ./libdeepstate_AFL.a /usr/local/lib/
```

Dirs:
* PUSH_DIR  - out/sync_dir/queue
* PULL_DIR  - out/the_fuzzer/queue
* CRASH_DIR - out/the_fuzzer/crashes


#### libFuzzer

It is bundled into newer clang compilers.

```bash
$ cd ./deepstate
$ mkdir -p build_libfuzzer && cd build_libfuzzer
$ CXX=clang++ CC=clang cmake -DDEEPSTATE_LIBFUZZER=ON ../
$ make -j4
$ sudo cp ./libdeepstate_LF.a /usr/local/lib/
```

Dirs:
* PUSH_DIR  - out/sync_dir/queue
* PULL_DIR  - out/sync_dir/queue
* CRASH_DIR - out/the_fuzzer/crashes

Use the `LIBFUZZER_WHICH_TEST`
environment variable to control which test libFuzzer runs, using a
fully qualified name (e.g.,
`Arithmetic_InvertibleMultiplication_CanFail`).  By default, you get
the first test defined (which works fine if there is only one test).

One hint when using libFuzzer is to avoid dynamically allocating
memory during a test, if that memory would not be freed on a test
failure.  This will leak memory and libFuzzer will run out of memory
very quickly in each fuzzing session.  Using libFuzzer on macOS
requires compiling DeepState and your program with a clang that
supports libFuzzer (which the Apple built-in probably won't); this can be as simple as doing:

```shell
brew install llvm@7
CC=/usr/local/opt/llvm\@7/bin/clang CXX=/usr/local/opt/llvm\@7/bin/clang++ DEEPSTATE_LIBFUZZER=TRUE cmake ..
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

#### HonggFuzz

```bash
$ cd ./deepstate
$ mkdir -p build_honggfuzz && cd build_honggfuzz
$ export HONGGFUZZ_HOME="/honggfuzz"
$ CXX="$HONGGFUZZ_HOME/hfuzz_cc/hfuzz-clang++" CC="$HONGGFUZZ_HOME/hfuzz_cc/hfuzz-clang" cmake -DDEEPSTATE_HONGGFUZZ=ON ../
$ make -j4
$ sudo cp ./libdeepstate_HFUZZ.a /usr/local/lib/
```

Dirs:
* PUSH_DIR  - out/sync_dir/queue
* PULL_DIR  - out/sync_dir/queue
* CRASH_DIR - out/the_fuzzer/crashes


#### Eclipser

Eclipser uses QEMU instrumentation and therefore doesn't require
special DeepState compilation. You should just use `libdeepstate.a`
(QEMU doesn't like special instrumentation).

Dirs:
* PUSH_DIR  - out/sync_dir/queue
* PULL_DIR  - out/sync_dir/queue
* CRASH_DIR - out/the_fuzzer/crashes


#### Angora

Angora uses two binaries for fuzzing, one with taint tracking information
and one without. So we need two deepstate libraries and will need to
compile each test two times.

Angora also requires old version of llvm/clang (between 4.0.0 and 7.1.0).
Executor will need to find it, so you may want to put it under `$ANGORA_HOME/clang+llvm/`.

```bash
# for deepstate compilation only
$ export PATH="/clang+llvm/bin:$PATH"
$ export LD_LIBRARY_PATH="/clang+llvm/lib:$LD_LIBRARY_PATH"

$ cd ./deepstate
$ export ANGORA_HOME="/angora"
$ mkdir -p build_angora_taint && cd build_angora_taint
$ export USE_TRACK=1
$ CXX="$ANGORA_HOME/bin/angora-clang++" CC="$ANGORA_HOME/bin/angora-clang" cmake -DDEEPSTATE_ANGORA=ON ../
$ make -j4 -i  # ignore errors, because Angora doesn't support 32bit builds \
$ sudo cp ./libdeepstate_taint.a /usr/local/lib/
$ cd ../

$ mkdir -p build_angora_fast && cd build_angora_fast
$ export USE_FAST=1
$ CXX="$ANGORA_HOME/bin/angora-clang++" CC="$ANGORA_HOME/bin/angora-clang" cmake -DDEEPSTATE_ANGORA=ON ../
$ make -j4 -i
$ sudo cp ./libdeepstate_fast.a /usr/local/lib/
```

```bash
$ mv /clang+llvm $ANGORA_HOME/
$ mkdir out
$ deepstate-angora --compile_test ./SimpleCrash.cpp --out_test_name SimpleCrash
$ deepstate-angora -o out ./SimpleCrash.taint.angora ./SimpleCrash.fast.angora
```

Dirs:
* PUSH_DIR  - out/sync_dir/queue
* PULL_DIR  - out/angora/queue
* CRASH_DIR - out/angora/crashes


### Replay

To run saved inputs against some test, just run it with appropriate arguments:
```
./SimpleCrash --abort_on_fail --input_test_files_dir ./out/output_afl/the_fuzzer/queue
```
No need to use fuzzer specific compilation (so don't use `SimpleCrash_AFL` etc).


### Ensembler (fuzzers synchronization)

You may run as many executors as you want (and have resources). But to synchronize
them, you need to specify `--sync_dir` option pointing to some shared directory.

Each fuzzer will push produced test cases to that directory and pull from it as needed.

Currently, there are some limitations in synchronization for the following fuzzers:
* Eclipser - needs to be restarted to use pulled test cases
* HonggFuzz - same as above
* Angora - pulled files need to have correct, AFL format (`id:00003`) and the id must
be greater that the biggest in Angora's local (pull) directory
* libFuzzer - stops fuzzing after first crash found, so there should be no crashes in `sync_dir`  


## Which Fuzzer Should I Use?

In fact, since DeepState supports libFuzzer, AFL, HonggFuzz, Angora and Eclipser,
a natural question is "which is the best fuzzer?"  In
general, it depends!  We suggest using them all, which DeepState makes
easy. libFuzzer is very fast, and sometimes the CMP breakdown it
provides is very useful; however, it's often bad at finding longer
paths where just covering nodes isn't helpful. AFL is still an
excellent general-purpose fuzzer, and often beats "improved" versions
over a range of programs. Finally, Eclipser has some tricks that let
it get traction in some cases where you might think only symbolic
execution (which wouldn't scale) could help.


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
declaring the code bug-free! There is another, more experimental,
swarm-like method, `-DDEEPSTATE_PROB_SWARM`, that is of possible interest.
Instead of pure binary inclusion/exclusion of choices, this varies the
actual distribution of choices.  However, because this often ends up behaving
more like a non-swarm selection, it may not be as good at ferreting out
unusual behaviors due to extreme imbalance of choices.

Note that tests produced under a particular swarm option are _not_
binary compatible with other settings for swarm, due to the added coin flips.

## Contributing

All accepted PRs are awarded bounties by Trail of Bits. Join the #deepstate channel on the [Empire Hacking Slack](https://empireslacking.herokuapp.com/) to discuss ongoing development and claim bounties. Check the [good first issue](https://github.com/trailofbits/deepstate/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) label for suggested contributions.

## Trophy case

DeepState has not yet been applied to many targets, but was responsible for finding the following confirmed bugs (serious faults are in bold):

- https://github.com/Blosc/c-blosc2/issues/93
- https://github.com/Blosc/c-blosc2/issues/94
- **https://github.com/Blosc/c-blosc2/issues/95** (bug causing compression engine to return incorrect uncompressed data) **FIXED**

## License

DeepState is released under [The Apache License 2.0](LICENSE).
