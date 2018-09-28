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

#include <deepstate/DeepState.hpp>

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
    
    LOG(DEBUG)
        << "Processing " << cheques.size() << " cheques";

    uint16_t total_to_withdraw = 0;
    for (auto cheque : cheques) {
      total_to_withdraw += cheque.amount;
    }

    if (balance < total_to_withdraw) {
      LOG(WARNING)
          << "Insufficient funds! Can't transfer " << total_to_withdraw
          << " from account with balance of " << balance;
      return false;
    }

    LOG(DEBUG)
        << "Withdrawing " << total_to_withdraw << " from account";

    for (auto cheque : cheques) {
      ASSERT(Transfer(cheque))
          << "Insufficient funds! Can't transfer " << cheque.amount
          << " from account with balance of " << balance;
    }

    return true;
  }

  uint16_t Balance(void) const {
    return balance;
  }

 private:
  uint16_t balance;
};
