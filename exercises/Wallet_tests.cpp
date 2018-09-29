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

#include <deepstate/DeepState.hpp>

#include "Wallet.hpp"

using namespace deepstate;

class WalletTests : public deepstate::Test {
 public:
  WalletTests(void)
      : account1(initial_balance1),
        account2(initial_balance2) {}

  uint32_t InitialBalance(void) const {
    return initial_balance1 + initial_balance2;
  }

  uint32_t TotalBalance(void) const {
    return account1.Balance() + account2.Balance();
  }
 protected:

  symbolic_unsigned initial_balance1;
  symbolic_unsigned initial_balance2;

  Wallet account1;
  Wallet account2;

  symbolic_unsigned amount1;
  symbolic_unsigned amount2;
};

TEST_F(WalletTests, WithdrawalDecreasesAccountBalance) {}

TEST_F(WalletTests, FailedWithdrawalPreservesAccountBalance) {}

TEST_F(WalletTests, SelfTransferPreservesAccountBalance) {}

TEST_F(WalletTests, MultiTransferPreservesBankBalance) {}
