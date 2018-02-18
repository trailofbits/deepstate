# DeepState

DeepState is a framework that provides C and C++ developers with a common interface to various symbolic execution and fuzzing engines. Users can write one test harness using a Google Test-like API, then execute it using multiple backends, without having to learn the complexities of the underlying engines. It supports writing unit tests and API sequence tests, as well as automatic test generation.

More high-level information on DeepState's goals (and design) is available at https://www.cefns.nau.edu/~adg326/bar18.pdf.
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

## Building

DeepState is a static library, used to write test harnesses, accompanied by command-line _executors_ written in Python. Below we describe how to build the library and accompanying Python package.

### Ubuntu 16.04 (Xenial)

Suppose the DeepState project source resides in the directory `$DEEPSTATE`.

First, install the build dependencies:

```shell
$ sudo apt update
$ sudo apt install build-essential gcc-multilib cmake python python-setuptools
```

Set up a build directory and `cd` into it:

```shell
$ mkdir $DEEPSTATE/build
$ cd $DEEPSTATE/build
```

From the build directory, generate Makefiles using CMake:

```shell
$ cmake $DEEPSTATE
```

Finally, build the library and package:

```shell
$ make
```

## Usage

After building, you can use DeepState by installing the resulting Python package, e.g. into a virtualenv. For example, from some working directory, with the `virtualenv` tool installed:

```shell
$ virtualenv venv
$ . venv/bin/activate
$ python $DEEPSTATE/build/setup.py install
```

Now your `virtualenv`-enabled `$PATH` should include two executables: `deepstate` and `deepstate-angr`. These are _executors_, which are used to run DeepState test binaries with specific backends (automatically installed as Python dependencies). The `deepstate` executor uses the Manticore backend, and requires the Z3 SMT solver to be installed, while `deepstate-angr` uses angr. They share a common interface, where you may specify a number of workers and an output directory for saving backend-generated test cases.

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
