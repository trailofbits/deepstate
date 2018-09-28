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

#include <cstdint>

#include <functional>
#include <vector>

class Wallet;

struct Cheque {
  uint16_t amount;
  Wallet *dest;
};

class Wallet {
 public:
  Wallet(void)
      : balance(0) {}

  explicit Wallet(uint16_t initial_balance)
      : balance(initial_balance) {}

  void Deposit(uint16_t amount) {
    balance += amount;
  }

  bool Withdraw(uint16_t amount) {
    if (amount <= balance) {
      balance -= amount;
      return true;
    } else {
      return false;
    }
  }

  bool Transfer(Cheque cheque) {
    if (Withdraw(cheque.amount)) {
      cheque.dest->Deposit(cheque.amount);
      return true;
    } else {
      return false;
    }
  }

  bool MultiTransfer(const std::vector<Cheque> &cheques) {
    printf("D");
    //printf("Num cheques = %lu", cheques.size());
    printf("cheques = %p", &cheques);
    uint16_t total_to_withdraw = 0;
    for (auto cheque : cheques) {
      printf("Transferring %hu", cheque.amount);
      total_to_withdraw += cheque.amount;
    }

    if (balance < total_to_withdraw) {
      return false;
    }

    for (auto cheque : cheques) {
      if (!Transfer(cheque)) {
        printf("WTF???");
        abort();
      }
    }

    return true;
  }

  uint16_t Balance(void) const {
    return balance;
  }

 private:
  uint16_t balance;
};
