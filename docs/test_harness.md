# Test harness

Table of Contents
=================

  * [General structure](#general-structure)
  * [Symbolic variables - inputs](#symbolic-variables---inputs)
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
class MyTest : public deepstate::Test {
 public:
  char* someVariable;

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
  ASSUME_NE(x, 1);
}

TEST_F(MyTest, SomethingElse) {
  ASSUME_EQ(x, 3);
}
```


## Symbolic variables - inputs

Executors need to know what variables are symbolic,
that is which should be monitored and used by them in order to explore
tested application state space. Symbolic variables will be used
as an unknowns in equations during symbolic execution or populated
with "random" data by fuzzers.

They may be declared like normal data types. Just add `symbolic_` prefix:

```c
symbolic_unsigned x, y, z;
symbolic_char c;
symbolic_int8_t b;
```

For all supported symbolic data types check TODO.


## Preconditions - constraints

If you want to constraint symbolic variable, i.e. tell
executor that it should be less than some value, then use
`ASSUME_*` macros. This macros will reduce search space and
enhance test efficiency. Use them like that:
```c
ASSUME_GT(x, 37);
```

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

Macros from first family will stop execution of the test if
the assertion is false. Macros from second one will
mark the test as failed, but will let the test continue.

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
