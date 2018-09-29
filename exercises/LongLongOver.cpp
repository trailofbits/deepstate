// This code belong to Comdb2 the Bloomberg's distributed RDBMS
// https://github.com/bloomberg/comdb2/blob/b8aad66d3bb48acd89682759f174a7349d673805/tests/int_overflow.test/test.c
// https://github.com/bloomberg/comdb2/blob/b8aad66d3bb48acd89682759f174a7349d673805/util/int_overflow.c 

/*
   Copyright 2017 Bloomberg Finance L.P.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */

/**
 * Signed integer overflow detection utility functions below were derived from
 * CERT Secure Coding standards for operations on signed integers (INT32-C).
 */

#include <limits.h>

/**
 * Checks for overflow will occur when a + b is performed, a and b being long
 * long int.
 * Returns 0 if no overflow will occur.
 *
 * @param long long a
 * @param long long b
 */
int overflow_ll_add(long long a, long long b)
{
    if (((b > 0) && (a > (LLONG_MAX - b))) ||
        ((b < 0) && (a < (LLONG_MIN - b)))) {
        return 1;
    }

    return 0;
}

/**
 * Checks for overflow will occur when a - b is performed, a and b being long
 * long int.
 * Returns 0 if no overflow will occur.
 *
 * @param long long a
 * @param long long b
 */
int overflow_ll_sub(long long a, long long b)
{
    if (((b > 0) && (a < (LLONG_MIN + b))) ||
        ((b < 0) && (a > (LLONG_MAX + b)))) {
        return 1;
    }

    return 0;
}

int test_ll_add()
{
    if (overflow_ll_add(1, 1) != 0) {
        return 1;
    }

    if (overflow_ll_add(-1, 1) != 0) {
        return 1;
    }

    if (overflow_ll_add(LLONG_MAX, 1) != 1) {
        return 1;
    }

    if (overflow_ll_add(1, LLONG_MAX) != 1) {
        return 1;
    }

    if (overflow_ll_add(0, LLONG_MAX) != 0) {
        return 1;
    }

    if (overflow_ll_add(LLONG_MAX, 0) != 0) {
        return 1;
    }

    return 0;
}

int test_ll_sub()
{
    if (overflow_ll_sub(1, 1) != 0) {
        return 1;
    }

    if (overflow_ll_sub(LLONG_MIN, 1) != 1) {
        return 1;
    }

    if (overflow_ll_sub(LLONG_MIN, 0) != 0) {
        return 1;
    }

    if (overflow_ll_sub(1, LLONG_MIN) != 1) {
        return 1;
    }

    if (overflow_ll_sub(0, LLONG_MIN) != 1) {
        return 1;
    }

    if (overflow_ll_sub(1, LLONG_MIN + 2) != 0) {
        return 1;
    }

    if (overflow_ll_sub(0, LLONG_MIN + 1) != 0) {
        return 1;
    }

    return 0;
}

int main(int argc, char *argv[]) {
  return test_ll_add() || test_ll_sub();
}
