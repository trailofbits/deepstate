# Test harness


Table of Contents
=================

  * [General structure](#general-structure)
  * [Symbolic variables - inputs](#symbolic-variables---inputs)
    * [Symbolic prefix](#symbolic-prefix)
    * [Strings and bytes](#strings-and-bytes)
    * [ForAll](#forall)
    * [Path to input file](#path-to-input-file)
    * [OneOf](#oneof)
  * [Preconditions - constraints](#preconditions---constraints)
  * [Postconditions - checks](#postconditions---checks)
  * [Logs](#logs)


## General structure


Tests can be defined using `TEST` macro.
This macro takes two arguments: a unit name (`PrimePolynomial`)
and a test name (`OnlyGeneratesPrimes`).

```c
#include <deepstate/DeepState.hpp>

TEST(PrimePolynomial, OnlyGeneratesPrimes) {
    ...
}

TEST(PrimePolynomial, AnotherTest) {
    ...
}
```

Each test in executed separately. If you need
a more complex setup and/or cleanup, `Test Fixtures`
are the way to go. These are C++ classes inherited from
`deepstate:Test` that may implement two methods:
`SetUp` and `TearDown`.

To use the class just pass it as the first argument to `TEST_F` macro.

```cpp
class MyTest : public deepstate:Test {
 public:
  char* someVariable;
  symbolic_int x;

  void SetUp(void) {
    LOG(TRACE) << "Setting up!";
    someVariable = (char*)malloc(10);
  }

  void TearDown(void) {
    LOG(TRACE) << "Tearing down!";
    free(someVariable);
  }

};

TEST_F(MyTest, Something) {
  ASSUME_EQ(x, 1);
  ASSERT_NE(someVariable, 0);
}

TEST_F(MyTest, SomethingElse) {
  ASSUME_EQ(x, 3);
}
```


## Symbolic variables: Inputs

Executors need to know which variables are symbolic,
that is, which are controlled by a symbolic execution tool or fuzzer. Symbolic variables are used
as unknowns in equations during symbolic execution or populated
with "random" data by fuzzers.

There are few ways to declare symbolic variables.

#### Symbolic prefix

For basic data types you may just add `symbolic_` prefix:

```c
symbolic_unsigned x, y, z;
symbolic_char c;
symbolic_int8_t b;
```

Defined types:
* symbolic_char
* symbolic_short
* symbolic_int
* symbolic_unsigned
* symbolic_long
* symbolic_int8_t
* symbolic_uint8_t
* symbolic_int16_t
* symbolic_uint16_t
* symbolic_int32_t
* symbolic_uint32_t
* symbolic_int64_t
* symbolic_uint64_t

#### Getting symbolic values

Rather than declaring a special typed value, it is sometimes easier
(when interfacing other code, or harnesses already using `rand` etc.)
to just use the API to "ask" DeepState for a value.  DeepState defines
functions returning most types of interest:

* DeepState_Int()
* DeepState_UInt()
* DeepState_Size() (for `size_`)
* DeepState_Bool()
* DeepState_Char()
* DeepState_Float()
* DeepState_Double()

The non-boolean types also allow you to request a value in a range, a
frequent need and one not as well supported by `symbolic <type>` decls
(you can use `ASSUME` to do it, but it's much more code, and will be
far less efficient with fuzzers), e.g., `DeepState_IntInRange(low,
high)`.  DeepState ranges are inclusive.

#### Strings and bytes

To create a symbolic string you may use:

`char* DeepState_CStr_C(size_t len, const char* allowed)` which
returns a pointer to an array of symbolic chars.  The`strlen` of returned data
will always be `len`. If `allowed` is NULL, then all bytes except the
null terminator 
will be allowed, otherwise strings will be generated from the given
character alphabet.

`char* DeepState_CStrUpToLen(size_t maxLen, const char* allowed)` is the
same as `DeepState_CStr_C`, except that the length of returned string
may vary, up to `maxLen` (inclusive); the amount of memory allocated,
and the position of a null terminator, are chosen by the
fuzzer/symbolic execution tool.

`void *DeepState_Malloc(size_t num_bytes)` just
allocate `num_bytes` symbolic bytes, of any value.  **Failing to free
this pointer will lead to a memory leak, it's just a normal pointer.**

#### ForAll
`ForAll` 
creates temporary variables which may be used in lambda expressions.
It is declared thusly:
```cpp
template <typename... Args>
inline static void ForAll(void (*func)(Args...)) {
  func(Symbolic<Args>()...);
}

template <typename... Args, typename Closure>
inline static void ForAll(Closure func) {
  func(Symbolic<Args>()...);
}
```

A usage example is:

```cpp
ForAll<int, int>([] (int x, int y) {
  ASSERT_EQ(add(x, y), add(y, x))
      << "Addition of signed integers must commute.";
});

ForAll<std::vector<int>>([] (const std::vector<int> &vec1) {
  std::vector<int> vec2 = vec1;
  std::reverse(vec2.begin(), vec2.end());
  std::reverse(vec2.begin(), vec2.end());
  ASSERT_EQ(vec1, vec2)
      << "Double reverse of vectors must be equal.";
});
```

#### Path to input file
`const char *DeepState_InputPath(char *testcase_path)` -
returns a path to a generated file. The path may be used with standard C++ file handling
functions (like `open` and `read` etc). Useful for fuzzing (when
some API takes a path as an argument rather than raw data). This is
not useful for symbolic execution.


#### OneOf
`OneOf` is an
operator that takes as argument an arbitrary number of lambda
expressions. In each call to `OneOf`, a random lambda is choosen
and executed. This allows you to non-deterministically execute
chunks of code and apply [swarm testing](/docs/swarm_testing.md).

Example:
```cpp
TEST(OneOfTest, Basic) {
  symbolic_int data;
  ctx *context = init_some_api();

  for (int i = 0; i < 10; ++i)
  {
    OneOf(
      [&context, &data, &i] {
        some_api_call(context, data, i);
      },
      [&context, &data] {
        int ret = some_other_call(context, data);
        ASSERT_EQ(ret, 0);
      }
    );
  }

  ASSERT_GT(context->smthing, 0);

  clear_context(context);
  ASSERT_EQ(context, nullptr);
}
```


## Preconditions - constraints

If you want to constrain a symbolic variable, i.e., tell the
executor that it should be less than some value, then use
`ASSUME_*` macros. These macros reduce the search space and
enhance test efficiency, and may be required to avoid invalid
inputs. Usage is simple:

```c
ASSUME_GT(x, 37);
ASSUME_NE(strncmp(y, "hmm...", 7), 0);
```

Fuzzers will abort (but won't fail) if some assumption
happen to be false, which should guide fuzzing to the
expected values.

DeepState provides following the precondition macros, in addition to
the generic `ASSUME` that takes a Boolean argument:

* ASSUME_EQ
* ASSUME_NE
* ASSUME_LT
* ASSUME_LE
* ASSUME_GT
* ASSUME_GE


## Postconditions - checks

Once symbolic variables are declared, constrained,
and used in functions that are tested, you may want
to assert something about the results of testing, as in normal unit
tests. To do that use either the
`ASSERT_*` or `CHECK_*` family of macros.

Macros from the first family will stop execution of the test if
the assertion is false. Macros from the second set will
mark the test as failed, but allow the test to continue.

Fuzzers will treat false `ASSERT`/`CHECK` as crashes
if the `--abort_on_fail` option is set (which is by default
when using most executors).

DeepState provides the following postcondition asserts:
* ASSERT_EQ
* ASSERT_NE
* ASSERT_LT
* ASSERT_LE
* ASSERT_GT
* ASSERT_GE
* ASSERT_TRUE
* ASSERT_FALSE

and checks:

* CHECK_EQ
* CHECK_NE
* CHECK_LT
* CHECK_LE
* CHECK_GT
* CHECK_GE
* CHECK_TRUE
* CHECK_FALSE


## Logs

Printing debug information is easy, and you can use standard `printf`-like
functions. These are reimplemented by DeepState, so they won't
introduce space state explosion (see
[the paper](https://www.trailofbits.com/reports/deepstate-bar18.pdf)). You
may also use `LOG` macros for streaming output to various logging
levels (`printf` defaults to `TRACE` level).  Setting `--min_log_level`
lets you control how much of this output DeepState shows when
replaying tests, or fuzzing.

```c
LOG(INFO) << "Hello " << name;
```

Log levels:
* DEBUG
* TRACE
* INFO
* WARNING
* WARN
* ERROR
* FATAL
* CRITICAL
