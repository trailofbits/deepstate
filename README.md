# DeepState

[![Slack Chat](http://empireslacking.herokuapp.com/badge.svg)](https://empireslacking.herokuapp.com/)

DeepState is a framework that provides C and C++ developers with a common interface to various symbolic execution and fuzzing engines. Users can write one test harness using a Google Test-like API, then execute it using multiple backends without having to learn the complexities of the underlying engines. It supports writing unit tests and API sequence tests, as well as automatic test generation. Read more about the goals and design of DeepState in our [paper](https://www.cefns.nau.edu/~adg326/bar18.pdf).

## Supported Platforms

DeepState currently targets Linux, with macOS support in progress.

## Dependencies

Build:

- CMake
- GCC with multilib support
- Python 2.7
- Setuptools

Runtime:

- Python 2.7
- Z3 (for the Manticore backend)

## Building on Ubuntu 16.04 (Xenial)

```shell
$ sudo apt update && sudo apt-get install build-essential gcc-multilib cmake python python-setuptools
$ git clone https://github.com/trailofbits/deepstate deepstate
$ mkdir deepstate/build
$ cd deepstate/build
$ cmake ../
$ make
```

## Installing

Install the DeepState Python package. For example, from some working directory, with the `virtualenv` tool installed:

```shell
$ virtualenv venv
$ . venv/bin/activate
$ python deepstate/build/setup.py install
```

## Usage

DeepState is a static library, used to write test harnesses, accompanied by command-line _executors_ written in Python.

If you followed the examples above, then your `virtualenv`-enabled `$PATH` should include two executables: `deepstate` and `deepstate-angr`. These are _executors_, which are used to run DeepState test binaries with specific backends (automatically installed as Python dependencies). The `deepstate` executor uses the Manticore backend and requires the Z3 SMT solver to be installed while `deepstate-angr` uses angr. They share a common interface where you may specify a number of workers and an output directory for saving backend-generated test cases.

You can check your build using the test binaries that were (by default) built and emitted to `$DEEPSTATE/build/examples`. For example, to use angr to symbolically execute the `IntegerOverflow` test harness with 4 workers, saving generated test cases in a directory called `out`, you would invoke:

```shell
$ deepstate-angr --num_workers 4 -output_test_dir out $DEEPSTATE/build/examples/IntegerOverflow
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

## License

DeepState is released under [The Apache License 2.0](LICENSE).

## Contributing

All accepted PRs are awarded bounties by Trail of Bits. Join the #deepstate channel on the [Empire Hacking Slack](https://empireslacking.herokuapp.com/) to discuss ongoing development and claim bounties. Check the `[good first issue](https://github.com/trailofbits/deepstate/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)` label for suggested contributions.
