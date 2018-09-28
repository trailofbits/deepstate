/*
 * Copyright (c) 2018 Trail of Bits, Inc.
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

#include <cstdlib>
#include <cstdio>

#include "Wallet.hpp"

static void usage(char *exe) {
  printf("Usage: %s <initial_balance> W|D <amount> [W|D <amount> [...]]\n", exe);
}

int main(int argc, char *argv[]) {
  if (argc < 4) {
    usage(argv[0]);
    return EXIT_FAILURE;
  }

  /* Read a uint16_t value from argv[1] into x */
  uint16_t initial_balance = 0;
  sscanf(argv[1], "%hu", &initial_balance);

  Wallet wallet(initial_balance);

  for (int i = 2; (i + 1) < argc; i += 2) {

    uint16_t amount = 0;
    sscanf(argv[i + 1], "%hu", &amount);

    if (argv[i][0] == 'W') {
      wallet.Withdraw(amount);

    } else if (argv[i][0] == 'D') {
      wallet.Deposit(amount);

    } else {
      usage(argv[0]);
      return EXIT_FAILURE;
    }
  }

  printf("New balance is %hu\n", wallet.Balance());
  return EXIT_SUCCESS;
}
