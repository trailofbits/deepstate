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

TEST_F(WalletTests, WithdrawalDecreasesAccountBalance) {
  ASSUME_GT(amount1, 0);
  ASSUME(account1.Withdraw(amount1));
  ASSERT_LT(account1.Balance(), initial_balance1);
}

TEST_F(WalletTests, FailedWithdrawalPreservesAccountBalance) {
  ASSUME(!account1.Withdraw(amount1));
  ASSERT_EQ(account1.Balance(), initial_balance1);
}

TEST_F(WalletTests, SelfTransferPreservesAccountBalance) {
  (void) account1.Transfer({amount1, &account1});

  ASSERT_EQ(account1.Balance(), initial_balance1)
      << "Account1's balance has increased with a self transfer of "
      << amount1;
}

TEST_F(WalletTests, MultiTransferPreservesBankBalance) {
  const auto old_balance1 = account1.Balance();
  const auto old_balance2 = account2.Balance();
  
  const auto transfer_succeeded = account1.MultiTransfer({
    {amount1, &account2},
    {amount2, &account2},
  });

  if (!transfer_succeeded) {
    CHECK(old_balance1 == account1.Balance())
        << "Account1's balance has changed from "
        << old_balance1 << " to " << account1.Balance();

    CHECK(old_balance2 == account2.Balance())
        << "Account2's balance has changed from "
        << old_balance2 << " to " << account2.Balance();

  } else {
    CHECK(InitialBalance() == TotalBalance())
        << "Balance in bank has changed from "
        << InitialBalance() << " to " << TotalBalance();
  }
}
