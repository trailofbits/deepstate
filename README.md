# DeepState

[![Slack Chat](http://empireslacking.herokuapp.com/badge.svg)](https://empireslacking.herokuapp.com/)

DeepState is a framework that provides C and C++ developers with a common interface to various symbolic execution and fuzzing engines. Users can write one test harness using a Google Test-like API, then execute it using multiple backends without having to learn the complexities of the underlying engines. It supports writing unit tests and API sequence tests, as well as automatic test generation. Read more about the goals and design of DeepState in our [paper](https://agroce.github.io/bar18.pdf).

The
[2018 IEEE Cybersecurity Development Conference](https://secdev.ieee.org/2018/home)
included a
[full tutorial](https://github.com/trailofbits/publications/tree/master/workshops/DeepState:%20Bringing%20vulnerability%20detection%20tools%20into%20the%20development%20lifecycle%20-%20SecDev%202018)
on effective use of DeepState.


Table of Contents
=================

  * [Articles describing DeepState](#articles-describing-deepstate)
  * [Overview of Features](#overview-of-features)
  * [Build'n'run](#buildnrun)
     * [Supported Platforms](#supported-platforms)
     * [Dependencies](#dependencies)
     * [Building on Ubuntu 18.04 (Bionic)](#building-on-ubuntu-1804-bionic)
     * [Installing](#installing)
     * [Installation testing](#installation-testing)
     * [Docker](#docker)
  * [Documentation](#documentation)
  * [Contributing](#contributing)
  * [Trophy case](#trophy-case)
  * [License](#license)


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

## Build'n'run

### Supported Platforms

DeepState currently targets Linux, with macOS support in progress
(the fuzzers work fine, but symbolic execution is not well-supported
yet, without a painful cross-compilation process).

### Dependencies

Build:

- CMake
- GCC and G++ with multilib support
- Python 3.6 (or newer)
- Setuptools

Runtime:

- Python 3.6 (or newer)
- Z3 (for the Manticore backend)

### Building on Ubuntu 18.04 (Bionic)

First make sure you install [Python 3.6 or greater](https://askubuntu.com/a/865569). Then use this command line to install additional requirements and compile DeepState:

```shell
sudo apt update && sudo apt-get install build-essential gcc-multilib g++-multilib cmake python3-setuptools python3-dev libffi-dev z3
sudo apt-add-repository ppa:sri-csl/formal-methods
sudo apt-get update
sudo apt-get install yices2
git clone https://github.com/trailofbits/deepstate deepstate
mkdir deepstate/build && cd deepstate/build
cmake ../
make
sudo make install
```

### Installing

Assuming the DeepState build resides in `$DEEPSTATE`, run the following commands to install the DeepState python package:

```shell
virtualenv venv
. venv/bin/activate
python $DEEPSTATE/build/setup.py install
```

The `virtualenv`-enabled `$PATH` should now include two executables: `deepstate` and `deepstate-angr`. These are _executors_, which are used to run DeepState test binaries with specific backends (automatically installed as Python dependencies). The `deepstate` or `deepstate-manticore` executor uses the Manticore backend while `deepstate-angr` uses angr. They share a common interface where you may specify a number of workers and an output directory for saving backend-generated test cases.

If you try using Manticore, and it doesn't work, but you definitely have the latest Manticore installed, check the `.travis.yml` file.  If that grabs a Manticore other than the master version, you can try using the version of Manticore we use in our CI tests.  Sometimes Manticore makes a breaking change, and we are behind for a short time.


### Installation testing

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


### Docker

You can also try out Deepstate with Docker, which is the easiest way
to get all the fuzzers and tools up and running on any system.

The build may take about 40 minutes, because some fuzzers require us
building huge projects like QEMU or LLVM.

```bash
$ docker build -t deepstate-base -f docker/base/Dockerfile docker/base
$ docker build -t deepstate --build-arg make_j=6 -f ./docker/Dockerfile .
$ docker run -it deepstate bash
user@a17bc44fd259:~/deepstate$ cd build/examples
user@a17bc44fd259:~/deepstate/build/examples$ deepstate-angr ./Runlen
user@a17bc44fd259:~/deepstate/build/examples$ mkdir tmp && deepstate-eclipser ./Runlen -o tmp --timeout 30
user@a17bc44fd259:~/deepstate/build/examples$ cd ../../build_libfuzzer/examples
user@a17bc44fd259:~/deepstate/build_libfuzzer/examples$ ./Runlen_LF -max_total_time=30
user@a17bc44fd259:~/deepstate/build_libfuzzer/examples$ cd ../../build_afl/examples
user@a17bc44fd259:~/deepstate/build_afl/examples$ mkdir foo && echo x > foo/x && mkdir afl_Runlen2
user@a17bc44fd259:~/deepstate/build_afl/examples$ $AFL_HOME/afl-fuzz -i foo -o afl_Runlen -- ./Runlen_AFL --input_test_file @@ --no_fork --abort_on_fail
user@a17bc44fd259:~/deepstate/build_afl/examples$ deepstate-afl -o afl_Runlen2 ./Runlen_AFL --fuzzer_out
```

## Documentation

Check out [docs](/docs) folder:

* [Basic usage](/docs/basic_usage.md)
* [Writing a test harness](/docs/test_harness.md)
* [Fuzzing](/docs/fuzzing.md)
* [Swarm testing](/docs/swarm_testing.md)

## External Tools

DeepState can be used to test R packages written using the popular Rcpp package.  The [Rcppdeepstate tool](https://github.com/akhikolla/RcppDeepState) is described in a [paper presented at the 2021 IEEE International Symposium on Software Reliability Engineering](https://agroce.github.io/issre21.pdf).

## Contributing

All accepted PRs are awarded bounties by Trail of Bits. Join the #deepstate channel on the [Empire Hacking Slack](https://empireslacking.herokuapp.com/) to discuss ongoing development and claim bounties. Check the [good first issue](https://github.com/trailofbits/deepstate/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) label for suggested contributions.

## Trophy case

We have not yet applied DeepState to many targets, but it was responsible for finding the following confirmed bugs (serious faults are in bold):

- https://github.com/Blosc/c-blosc2/issues/93
- https://github.com/Blosc/c-blosc2/issues/94
- **https://github.com/Blosc/c-blosc2/issues/95** (bug causing compression engine to return incorrect uncompressed data) **FIXED**

## License

DeepState is released under [The Apache License 2.0](LICENSE).
