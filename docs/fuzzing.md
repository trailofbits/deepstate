# Fuzzing

Table of Contents
=================

  * [Built-In Fuzzer](#built-in-fuzzer)
  * [A Note on MacOS and Forking](#a-note-on-macos-and-forking)
  * [External fuzzers](#external-fuzzers)
     * [Fuzzer executors usage](#fuzzer-executors-usage)
     * [AFL](#afl)
     * [libFuzzer](#libfuzzer)
     * [HonggFuzz](#honggfuzz)
     * [Eclipser](#eclipser)
     * [Angora](#angora)
     * [Ensembler (fuzzers synchronization)](#ensembler-fuzzers-synchronization)
  * [Tests replay](#tests-replay)
  * [Which Fuzzer Should I Use?](#which-fuzzer-should-i-use)


## Built-In Fuzzer

Every DeepState executable provides a simple built-in fuzzer that
generates tests using completely random data.  Using this fuzzer is as
simple as calling the native executable with the `--fuzz` argument.
The fuzzer also takes a `seed` and `timeout` (default of two minutes)
to control the fuzzing.   By default fuzzing saves
only failing and crashing tests, and these only when given an output
directory.  If you want to actually save the test cases
generated, you need to add the `--output_test_dir` argument to tell
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
only when things aren't working without that option).  Using
`--no_fork` can provide a modest speedup on other OS platforms as
well, in our experience.

## External fuzzers

DeepState currently explicitly supports five external fuzzers with 
full-fledged custom front-ends:
[libFuzzer](https://llvm.org/docs/LibFuzzer.html),
[AFL](http://lcamtuf.coredump.cx/afl),
[HonggFuzz](https://github.com/google/honggfuzz),
[Eclipser](https://github.com/SoftSec-KAIST/Eclipser), and
[Angora](https://github.com/AngoraFuzzer/Angora).

Additionally, DeepState can probably be used with most fuzzers that can interact with
a program through a file interface, via `--input_test_file @@` or something similar.
E.g., we have successfully used DeepState with 
[Google's Jackalope](https://github.com/googleprojectzero/Jackalope).
Doing this may take some work:  for Jackalope, we had to run the process 
via sudo to allow the debugger to attach, and turn off forking.

To use one of the fully-supported fuzzers as a DeepState backend, you need to:
* install it
* compile DeepState with it
* compile the target library/codebase with it (this is probably the
  hardest part)
* compile the target test harness with it
* run executor with location of installed files provided

To install a fuzzer follow the instructions on its website or
run Deepstate via Docker, as described in [README.md](/README.md)

To compile DeepState with the fuzzer, run `cmake` with
`-DDEEPSTATE_FUZZERNAME=on` (like `-DDEEPSTATE_AFL=on`) option and
`CC/CXX` variables set to the fuzzer's compiler. This will produce
library called `libdeepstate_FUZZERNAME.a`, which you may put in
a standard location (`/usr/local/lib/`).

To compile a target test, use the fuzzer's compiler and link with the appropriate
DeepState library (`-ldeepstate_FUZZERNAME`).

To provide the location of a fuzzer's executables to the Python executor you may:
* put the executables in some `$PATH` location
* export a `FUZZERNAME_HOME` environment variable (like `ANGORA_HOME`)
with value set to the location of fuzzer's executables
* specify the `--home_path` argument when running the executor

All this  rather complicated setup may be considerably simplified by using Docker.
Just build the image (changing OS in `./docker/base/Dockerfile` if needed)
and use it with your project. All the fuzzers and evironment variables will be there.

### Fuzzer executor usage

Fuzzer executors (`deepstate-honggfuzz` etc.) are meant to be as uniform
as possible, thus making it easy to compile and run tests.

Compilation: `deepstate-afl --compile_test ./SimpleCrash.cpp --out_test_name SimpleCrash`

Run: `mkdir out && deepstate-afl --output_test_dir out ./SimpleCrash.afl`

The only required arguments are the location of output directory and the test.
Optional arguments:
```
--input_seeds     - location of directory with initial inputs 
--max_input_size  - maximal length of inputs
--exec_timeout    - timeout for run on one input file
--timeout         - timeout for whole fuzzing process
--fuzzer_out      - use fuzzer output rather that deepstate (uniform) one
--mem_limit       - memory limit for the fuzzer
--min_log_level   - how much to log (0=DEBUG, 6=CRITICAL)
--blackbox        - fuzz non-instrumented binary
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
(because of the `--abort_on_fail` flag).

Note that some fuzzers (notably AFL) require input seeds. When not
provided, the executor will create a dumb one, which may be not very efficient for fuzzing.

Input files need to be smaller than the DeepState input size limit (8192 bytes),
which is the default limit in executors. But not all fuzzers support a
file size
limitation, so if your test cases grown too large, you may need to stop fuzzing
and minimize them.

Also, there should not be crash-producing files inside the input seeds directory.

To resume a stopped fuzzing session, just run executor again with the same
output directory (the `--input_seeds` argument will be ignored).

Because AFL and other file-based fuzzers only rely on the DeepState
native test executable, they should (like DeepState's built-in simple
fuzzer) work fine on macOS and other Unix-like OSes.  On macOS, you
will want to consider doing the work to use [persistent mode](http://lcamtuf.blogspot.com/2015/06/new-in-afl-persistent-mode.html), or even
running inside a VM, due to AFL (unless in persistent mode) relying
extensively on forks, which are very slow on macOS.


### AFL

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

Synchronization:
* AFL executor (`deepstate-afl`) runs the fuzzer in auto-sync mode (`-M`)
* Test cases pushed to `PUSH_DIR` will be automatically used by the AFL
* Files may need correct names (`id:000001` etc), not implemented by the executor
* AFL's docs suggest to share `fuzzer_stats`, not implemented by the executor

Resuming:
* Executor sets `--input` option to `-`, which is AFL way to resume fuzzing
* AFL creates multiple `out/the_fuzzer/crashes*` dirs, which is not handled by
the executor at the moment

Statistics:
* AFL provides colorful, curses TUI
* If stdout is redirected, then it automatically switches to
more compact output
* Creates `fuzzer_stats` file, which is updated from time to time
* Executor uses the `fuzzer_stats` file


### libFuzzer

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

Synchronization:
* libFuzzer executor runs the fuzzer in auto-sync mode (`-reload=1`)
* Test cases pushed to `PUSH_DIR` will be automatically used by the libFuzzer
* Filenames in `PUSH_DIR` may be arbitrary

Resuming:
* libFuzzer uses test cases from each specified dir,
so the executor just uses `PULL_DIR` to resume fuzzing

Statistics:
* Informations are printed line-by-line
* `-print_final_stats=1` makes the fuzzer output summary once finished
* Executor redirects libFuzzer's stdout to file and parses it

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


### HonggFuzz

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

Synchronization:
* Is [not implemented](https://github.com/google/honggfuzz/issues/125)
* New test cases are moved from `sync_dir` to `PUSH_DIR` by the executor,
so stopping and resuming the fuzzer will make it use new seeds. This needs to
be done manually (executor doesn't implement that at the moment)

Resuming:
* Executor sets `--input` to `PUSH_DIR` to resume fuzzing

Statistics:
* HonggFuzz provides curses TUI
* `--verbose` disables the TUI
* Also prints some informations line-by-line
* Produces HONGGFUZZ.REPORT.TXT (not too much info)
* `--logfile` may redirect stdout to some file
* Executor doesn't parse any of above at the moment


### Eclipser

Eclipser uses QEMU instrumentation and therefore doesn't require
special DeepState compilation. You should just use `libdeepstate.a`
(QEMU doesn't like special instrumentation).

Eclipser stores new test cases and crashes in json and base64 encoding.
Decoding to raw files is done automatically by the executor at the end of
a fuzzing process.

Dirs:
* PUSH_DIR  - out/sync_dir/queue
* PULL_DIR  - out/sync_dir/queue
* CRASH_DIR - out/the_fuzzer/crashes

Synchronization:
* [Probably not implemented](https://github.com/SoftSec-KAIST/Eclipser/issues/12)
* New test cases are moved from `sync_dir` to `PUSH_DIR` by the executor,
so stopping and resuming the fuzzer will make it use new seeds. This needs to
be done manually (executor doesn't implement that at the moment)

Resuming:
* The executor sets `--input` to `PUSH_DIR` to resume fuzzing

Statistics:
* Prints some informations to stdout (rather mysterious)
* Produces some files like `.coverage` (also mysterious)
* Executor doesn't parse any of above at the momen


### Angora

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

Synchronization:
* Synchronization with AFL is implemented by the Angora. The executor uses it
(with Angora's `--sync_afl` option)
* Angora requires filenames to be appropriate to synchronize (use) them.
Each file in `PUSH_DIR` before sync has checked filename for
correct format (`id:000001` etc.) and compared the id (the number) with maximal id
in local directory (`PULL_DIR`). If the id is higher than the maximal local one, then
the test case is incorporated

Resuming:
* Executor sets `--input` option to `-`, which is Angora way to resume fuzzing
* Angora creates multiple `out/angora*` dirs, which is not handled by
the executor at the moment

Statistics:
* Angora provides TUI
* Creates `chart_stat.json` and `angora.log` files with some stats
* Executor uses limited amount of information from `chart_stat.json`
at the moment


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


## Tests replay

To run saved inputs against some test, just run it with appropriate arguments:

```
./Runlen --abort_on_fail --input_test_files_dir ./out/output_afl/the_fuzzer/queue
```

No need to use fuzzer specific compilation (so don't use `SimpleCrash_AFL` etc.
They are slower due to instrumentation).


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
