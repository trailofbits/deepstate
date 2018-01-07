/*
 * Copyright (c) 2017 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <deepstate/DeepState.hpp>

using namespace deepstate;

bool IsPrime(const unsigned p) {
  for (unsigned i = 2; i <= (p/2); ++i) {
    if (!(p % i)) {
      return i;
    }
  }
  return true;
}

TEST(PrimePolynomial, OnlyGeneratesPrimes) {
  symbolic_unsigned x, y, z;
  ASSUME_GT(x, 0);
  unsigned poly = (x * x) + x + 41;
  ASSUME_GT(y, 1);
  ASSUME_GT(z, 1);
  ASSUME_LT(y, poly);
  ASSUME_LT(z, poly);
  ASSERT_NE(poly, y * z)
      << x << "^2 + " << x << " + 41 is not prime";
  ASSERT(IsPrime(Pump(poly)))
      << x << "^2 + " << x << " + 41 is not prime";
}

int main(int argc, char *argv[]) {
  DeepState_InitOptions(argc, argv);
  return DeepState_Run();
}
