#!/usr/bin/env python
# Copyright (c) 2017 Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
logging.basicConfig()

#import collections
import argparse
import sys
import os
import md5
from .common import DeepState

class DeepEVM(DeepState):
   @classmethod
   def parse_args(cls):
    """Parses command-line arguments needed by DeepState."""
    if cls._ARGS:
      return cls._ARGS

    parser = argparse.ArgumentParser(
        description="Symbolically execute unit tests with ManticoreEVM")

    parser.add_argument(
        "--initial_balance", default=1000, type=int,
        help="Initial balance for the contract to run.")

    parser.add_argument(
        "--output_test_dir", default="out", type=str, required=False,
        help="Directory where tests will be saved.")

    parser.add_argument(
        "contract", type=str, help="Path to the contract to run.")

    cls._ARGS = parser.parse_args()
    return cls._ARGS


try:
  import manticore.ethereum
except Exception as e:
  if "Z3NotFoundError" in repr(type(e)):  
    print "Manticore requires Z3 to be installed."
    sys.exit(255)
  else:
    raise
import traceback
from .common import DeepState

L = logging.getLogger("deepstate.evm")
L.setLevel(logging.INFO)

def move_tests(workspace, outdir):
  """Parse and sort testcases"""  
  tx_files = []
  for prefix, d, files in list(os.walk(workspace)):
    for f in files: 
      if "test" in f and ".tx" in f:
        tx_files.append(os.path.join(prefix,os.path.join('', *d), f))

  for filename in tx_files:
      txs = open(filename, "r+").read()
      test_name = md5.new(txs).hexdigest()
      if "THROW" in txs:
          test_name = test_name + ".fail"
      if "STOP" in txs:
          test_name = test_name + ".pass" 

      test_file = os.path.join(outdir, test_name)
      L.info("Saving input to {}".format(test_file))
      try:
        with open(test_file, "wb") as f:
          f.write(txs)
      except:
        L.critical("Error saving input to {}".format(test_file))

def compile_contract(contract, initial_balance):
  """Compile a contract"""
  m = manticore.ethereum.ManticoreEVM()
  source_code = open(contract, "r").read()
  owner_account = m.create_account(balance=initial_balance)
  contract_account = m.solidity_create_contract(source_code, owner=owner_account, contract_name="TEST")
  return m, owner_account, contract_account
 
def do_run_test(args, contract, test):
  """Run an individual test case."""
  test_name, test_args = test
  m, owner_account, contract_account = compile_contract(contract, args.initial_balance)
  m.verbosity(1)
  func = getattr(contract_account, test_name)
  func_args = [None]*len(test_args)
  func( *func_args )
  m.finalize()
  move_tests(m.workspace, get_test_dir_name(args, test))

def run_test(args, contract, test):
  try:
    do_run_test(args, contract, test)
  except:
    L.error("Uncaught exception: {}\n{}".format(
        sys.exc_info()[0], traceback.format_exc()))

def find_test_cases(contract):
  """Iterate over all the methods in the TEST contract and collect the "Test_" ones"""
  m, owner_account, contract_account = compile_contract(contract, 0) 
  signatures = m.get_metadata(contract_account.address).signatures
  test_cases = []
  for (h, n) in signatures.items():
    if "Test_" in n:
      test_name = n.split("(")[0]
      test_args = n.split("(")[1].split(")")[0].split(",")
      test_cases.append((test_name,test_args))

  return test_cases

def get_test_dir_name(args, test):
  """Returns the complete path to save the results"""
  test_name, _ = test
  test_name = test_name.replace("Test_", "") 
  test_dir = os.path.join(args.output_test_dir, os.path.basename(args.contract), test_name)
  return test_dir   

def try_make_test_dir(dirname):
  try:
    os.makedirs(dirname)
  except:
    pass

def run_tests(args):
  """Run all of the test cases."""
  results = []
  contract = args.contract
  tests = find_test_cases(contract)
  for test in tests:
    test_dir = get_test_dir_name(args, test)
    try_make_test_dir(test_dir)

  L.info("Running {} tests.".format(len(tests)))

  for test in tests:
    res = run_test(args, contract, test)
    results.append(res)

  exit(0)


def main():
  args = DeepEVM.parse_args()

  try:
    compile_contract(args.contract, 0) 
  except Exception as e:
    L.critical("Cannot create Manticore instance on contract {}: {}".format(
        args.contract, e))
    return 1

  # after this point, compile_contract cannot fail with any exception
  run_tests(args)
  return 0

if "__main__" == __name__:
  exit(main())
