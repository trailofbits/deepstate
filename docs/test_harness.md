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


Test can be defined using `TEST` macro.
This macro takes two arguments: unit name (`PrimePolynomial`)
and test name (`OnlyGeneratesPrimes`).

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


## Symbolic variables - inputs

Executors need to know what variables are symbolic,
that is which should be monitored and used by them in order to explore
application state space. Symbolic variables will be used
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

#### Strings and bytes

To create symbolic string you may use:

`char* DeepState_CStr_C(size_t len, const char* allowed)` - 
returns pointer to array of symbolic chars. `strlen` of returned data
will always be `len`. If allowed characters are NULL, then all bytes except nullbyte
will be allowed. **The same holds when fuzzing.**

`char* DeepState_CStrUpToLen(size_t maxLen, const char* allowed)` -
same as `DeepState_CStr_C`, except length of returned string may vary.
That is, it may have nullbyte at arbitrary position.

`void *DeepState_Malloc(size_t num_bytes)` -
allocate `num_bytes` symbolic bytes. **Returned pointer
must be `free`ed**.

#### ForAll
`ForAll` -
Creates temporary variables which may be used in lambda expression.
Here are declarations:
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
And examples:
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
returns path to a file that is used as the input. That is,
either `--input_test file` value or `testcase_path`
(in that order). The path may be used with standard C++ file handling
functions (like `open` and `read` etc). Useful for fuzzing (when
some API takes path as an argument rather than raw data). Completely not
useful for symbolic execution.


#### OneOf
`OneOf` -
operator that takes as argument arbitrary amount of lambda
expressions. In each call to it, random lambda is choosen
and executed. This allows to non-deterministically execute
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

If you want to constraint symbolic variable, i.e. tell
executor that it should be less than some value, then use
`ASSUME_*` macros. This macros will reduce search space and
enhance test efficiency. Use them like that:
```c
ASSUME_GT(x, 37);
ASSUME_NE(strncmp(y, "hmm...", 7), 0);
```

Fuzzers will abort (but won't fail) if some assumption
happen to be false, which should guide fuzzing to the
expected values.

DeepState provides following precondition macros:
* ASSUME_EQ
* ASSUME_NE
* ASSUME_LT
* ASSUME_LE
* ASSUME_GT
* ASSUME_GE


## Postconditions - checks

Once symbolic variables are declared, constrained
and used in functions that are tested, you may want
to assert something about them. To do that use either
`ASSERT_*` or `CHECK_*` family of macros.

Macros from the first family will stop execution of the test if
the assertion is false. Macros from the second one will
mark the test as failed, but will let the test continue.

Fuzzers will treat false `ASSERT`/`CHECK` as a crash
if `--abort_on_fail` option is provided (which is by default
when using executors).

DeepState provides following postcondition asserts:
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

Printing debug informations may be done with standard `printf`-like
functions. They are reimplemented by DeepState, so they won't
introduce space state explosion (see [the paper](https://www.trailofbits.com/reports/deepstate-bar18.pdf)). You may also use `LOG` macros (as a stream):
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
* CRITICAl
