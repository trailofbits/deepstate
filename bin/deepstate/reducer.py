#!/usr/bin/env python
# Copyright (c) 2018 Trail of Bits, Inc.
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

from __future__ import print_function
import argparse
import subprocess
import os
import time


def main():
  global candidateRuns

  parser = argparse.ArgumentParser(description="Intelligently reduce test case")

  parser.add_argument(
    "binary", type=str, help="Path to the test binary to run.")

  parser.add_argument(
    "input_test", type=str, help="Path to test to reduce.")

  parser.add_argument(
    "output_test", type=str, help="Path for reduced test.")

  parser.add_argument(
    "--which_test", type=str, help="Which test to run (equivalent to --input_which_test).", default=None)

  parser.add_argument(
    "--criteria", type=str, help="String to search for in valid reduction outputs.",
    default=None)

  parser.add_argument(
    "--search", action="store_true", help="Allow initial test to not satisfy criteria (search for test).",
    default=None)

  parser.add_argument(
    "--timeout", type=int, help="After this amount of time (in seconds), give up on reduction.",
    default=1200)

  parser.add_argument(
    "--fast", action='store_true',
    help="Faster, less complete, reduction (no range or byte pattern attempts).")

  parser.add_argument(
    "--verbose", action='store_true',
    help="Verbose reduction.")

  parser.add_argument(
    "--fork", action='store_true',
    help="Fork when running.")

  class TimeoutException(Exception):
    pass

  args = parser.parse_args()

  deepstate = args.binary
  test = args.input_test
  out = args.output_test
  checkString = args.criteria
  whichTest = args.which_test

  start = time.time()
  candidateRuns = 0

  def runCandidate(candidate):
    global candidateRuns
    candidateRuns += 1
    if (time.time() - start) > args.timeout:
      raise TimeoutException
    with open(".reducer." + str(os.getpid()) + ".out", 'w') as outf:
      cmd = [deepstate + " --input_test_file " +
           candidate + " --verbose_reads"]
      if whichTest is not None:
        cmd += ["--input_which_test", whichTest]
      if not args.fork:
        cmd += ["--no_fork"]
      subprocess.call(cmd, shell=True, stdout=outf, stderr=outf)
    result = []
    with open(".reducer." + str(os.getpid()) + ".out", 'r') as inf:
      for line in inf:
        result.append(line)
    return result

  def checks(result):
    for line in result:
      if checkString:
        if checkString in line:
          return True
      else:
        if "ERROR: Failed:" in line:
          return True
        if "ERROR: Crashed" in line:
          return True
    return False

  def writeAndRunCandidate(test):
    with open(".candidate." + str(os.getpid()) + ".test", 'wb') as outf:
      outf.write(test)
    r = runCandidate(".candidate." + str(os.getpid()) + ".test")
    return r

  def structure(result):
    OneOfs = []
    currentOneOf = []
    for line in result:
      if "STARTING OneOf CALL" in line:
        currentOneOf.append(-1)
      elif "Reading byte at" in line:
        lastRead = int(line.split()[-1])
        if len(currentOneOf) > 0:
          if currentOneOf[-1] == -1:
            currentOneOf[-1] = lastRead
      elif "FINISHED OneOf CALL" in line:
        OneOfs.append((currentOneOf[-1], lastRead))
        currentOneOf = currentOneOf[:-1]
    return (OneOfs, lastRead)

  def rangeConversions(result):
    conversions = []
    startedMulti = False
    multiFirst = None
    for line in result:
      if "Reading byte at" in line:
        lastRead = int(line.split()[-1])
      if "STARTING MULTI-BYTE READ" in line:
        startedMulti = True
      if startedMulti and (multiFirst is None) and ("Reading byte at" in line):
        multiFirst = lastRead
      if "FINISHED MULTI-BYTE READ" in line:
        currentMulti = (multiFirst, lastRead)
        startedMulti = False
        multiFirst = None
      if "Converting out-of-range value" in line:
        conversions.append((currentMulti, int(line.split()[-1])))
    return conversions

  def fixUp(test, conversions):
    numConversions = 0
    for (pos, value) in conversions:
      if pos[1] >= len(test):
        break
      if (value < 255) and (value < test[pos[1]]):
        numConversions += 1
        for b in range(pos[0], pos[1]):
          test[b] = 0
        test[pos[1]] = value
    if numConversions > 0:
      print("APPLIED", numConversions, "RANGE CONVERSIONS")

  initial = runCandidate(test)
  if (not args.search) and (not checks(initial)):
    print("STARTING TEST DOES NOT SATISFY REDUCTION CRITERIA")
    return 1

  with open(test, 'rb') as test:
    currentTest = bytearray(test.read())
  original = bytearray(currentTest)

  print("ORIGINAL TEST HAS", len(currentTest), "BYTES")

  fixUp(currentTest, rangeConversions(initial))
  r = writeAndRunCandidate(currentTest)
  assert(checks(r))

  s = structure(initial)
  if (s[1]+1) < len(currentTest):
    print("LAST BYTE READ IS", s[1])
    print("SHRINKING TO IGNORE UNREAD BYTES")
    currentTest = currentTest[:s[1]+1]

  if currentTest != original:
    print("WRITING REDUCED TEST WITH", len(currentTest), "BYTES TO", out)
    with open(out, 'wb') as outf:
      outf.write(currentTest)

  initialSize = float(len(currentTest))
  iteration = 0
  changed = True

  rangeRemovePos = 0
  byteReducePos = 0

  try:
    while changed:
      changed = False

      iteration += 1
      percent = 100.0 * ((initialSize - len(currentTest)) / initialSize)
      print("=" * 80)
      print("STARTING ITERATION #" + str(iteration), round(time.time()-start, 2), "SECONDS /",
              candidateRuns, "EXECUTIONS /", str(round(percent, 2)) + "% REDUCTION")
      if args.verbose:
        print("TRYING ONEOF REMOVALS...")
      cuts = s[0]
      for c in cuts:
        newTest = currentTest[:c[0]] + currentTest[c[1]+1:]
        if len(newTest) == len(currentTest):
          continue # Ignore non-shrinking reductions
        r = writeAndRunCandidate(newTest)
        if checks(r):
          print("ONEOF REMOVAL REDUCED TEST TO", len(newTest), "BYTES")
          changed = True
          rangeRemovePos = 0
          byteReducePos = 0
          break

      if (not args.fast) and (not changed):
        for b in range(rangeRemovePos, len(currentTest)):
          if args.verbose:
            print("TRYING BYTE RANGE REMOVAL FROM BYTE", str(b) + "...")
          for v in range(b+1, len(currentTest)):
            newTest = currentTest[:b] + currentTest[v:]
            r = writeAndRunCandidate(newTest)
            if checks(r):
              print("BYTE RANGE REMOVAL REDUCED TEST TO", len(newTest), "BYTES")
              rangeRemovePos = b
              byteReducePos = 0
              changed = True
              break
          if changed:
            break

      if (not args.fast) and (not changed):
        for b in range(0, rangeRemovePos):
          if args.verbose:
            print("TRYING BYTE RANGE REMOVAL FROM BYTE", str(b) + "...")
          for v in range(b+1, len(currentTest)):
            newTest = currentTest[:b] + currentTest[v:]
            r = writeAndRunCandidate(newTest)
            if checks(r):
              print("BYTE RANGE REMOVAL REDUCED TEST TO", len(newTest), "BYTES")
              rangeRemovePos = b
              byteReducePos = 0
              changed = True
              break
          if changed:
            break
        if not changed:
          rangeRemovePos = 0

      if not changed:
        if args.verbose:
          print("TRYING ONEOF SWAPPING...")
        cuts = s[0]
        for i in range(len(cuts)-1):
          cuti = cuts[i]
          bytesi = currentTest[cuti[0]:cuti[1] + 1]
          if args.verbose:
            print("TRYING ONEOF SWAPPING FROM BYTE", cuti[0], "[" + " ".join(map(str, bytesi)) + "]")
          for j in range(i + 1, len(cuts)):
            cutj = cuts[j]
            if cutj[0] > cuti[1]:
              bytesj = currentTest[cutj[0]:cutj[1] + 1]
              if bytesi > bytesj:
                newTest = currentTest[:cuti[0]] + bytesj + currentTest[cuti[1]+1:cutj[0]]
                newTest += bytesi
                newTest += currentTest[cutj[1]+1:]
                newTest = bytearray(newTest)
                r = writeAndRunCandidate(newTest)
                if checks(r):
                  print("ONEOF SWAP @ BYTE", cuti[0], "[" + " ".join(map(str, bytesi)) + "]", "WITH",
                          cutj[0], "[" + " ".join(map(str, bytesj)) + "]")
                  changed = True
                  byteReducePos = 0
                  break
          if changed:
            break

      if not changed:
        if args.verbose:
          print("TRYING BYTE REDUCTIONS...")
        for b in range(byteReducePos, len(currentTest)):
          for v in range(0, currentTest[b]):
            newTest = bytearray(currentTest)
            newTest[b] = v
            r = writeAndRunCandidate(newTest)
            if checks(r):
              print("BYTE REDUCTION: BYTE", b, "FROM", currentTest[b], "TO", v)
              changed = True
              byteReducePos = b+1
              break
          if changed:
            break

      if not changed:
        for b in range(0, byteReducePos):
          for v in range(0, currentTest[b]):
            newTest = bytearray(currentTest)
            newTest[b] = v
            r = writeAndRunCandidate(newTest)
            if checks(r):
              print("BYTE REDUCTION: BYTE", b, "FROM", currentTest[b], "TO", v)
              changed = True
              byteReducePos = b+1
              break
          if changed:
            break
        if not changed:
          byteReducePos = 0

      if not changed:
        if args.verbose:
          print("TRYING BYTE REDUCE AND DELETE...")
        for b in range(0, len(currentTest)-1):
          if currentTest[b] == 0:
            continue
          newTest = bytearray(currentTest)
          newTest[b] = currentTest[b]-1
          newTest = newTest[:b+1] + newTest[b+2:]
          r = writeAndRunCandidate(newTest)
          if checks(r):
            print("BYTE REDUCE AND DELETE AT BYTE", b)
            changed = True
            break

      if not changed:
        if args.verbose:
          print("TRYING BYTE REDUCE AND DELETE 4...")
        for b in range(0, len(currentTest)-5):
          if currentTest[b] == 0:
            continue
          newTest = bytearray(currentTest)
          newTest[b] = currentTest[b]-1
          newTest = newTest[:b+1] + newTest[b+5:]
          r = writeAndRunCandidate(newTest)
          if checks(r):
            print("BYTE REDUCE AND DELETE 4 AT BYTE", b)
            changed = True
            break

      if not changed:
        if args.verbose:
          print("TRYING BYTE REDUCE AND DELETE 8...")
        for b in range(0, len(currentTest)-9):
          if currentTest[b] == 0:
            continue
          newTest = bytearray(currentTest)
          newTest[b] = currentTest[b]-1
          newTest = newTest[:b+1] + newTest[b+9:]
          r = writeAndRunCandidate(newTest)
          if checks(r):
            print("BYTE REDUCE AND DELETE 8 AT BYTE", b)
            changed = True
            break

      if (not args.fast) and (not changed):
        for b1 in range(0, len(currentTest)-4):
          if args.verbose:
            print("TRYING BYTE PATTERN SEARCH FROM BYTE", str(b1) + "...")
          for b2 in range(b1+2, len(currentTest)-4):
            v1 = (currentTest[b1], currentTest[b1+1])
            v2 = (currentTest[b2], currentTest[b2+1])
            if (v1 == v2):
              ba = bytearray(v1)
              part1 = currentTest[:b1]
              part2 = currentTest[b1+2:b2]
              part3 = currentTest[b2+2:]
              banews = []
              banews.append(ba[0:1])
              banews.append(ba[1:2])
              if ba[0] > 0:
                for v in range(0, ba[0]):
                  banews.append(bytearray([v, ba[1]]))
                banews.append(bytearray([ba[0]-1]))
              if ba[1] > 0:
                for v in range(0, ba[1]):
                  banews.append(bytearray([ba[0], v]))
              for banew in banews:
                newTest = part1 + banew + part2 + banew + part3
                r = writeAndRunCandidate(newTest)
                if checks(r):
                  print("BYTE PATTERN", tuple(ba), "AT", b1, "AND", b2, "CHANGED TO", tuple(banew))
                  changed = True
                  break
              if changed:
                break
          if changed:
            break

      if changed:
        currentTest = newTest
        print("WRITING REDUCED TEST WITH", len(currentTest), "BYTES TO", out)
        with open(out, 'wb') as outf:
          outf.write(currentTest)
        s = structure(r)
        fixUp(currentTest, rangeConversions(r))
      else:
        print("*" * 80)
        print("NO (MORE) REDUCTIONS FOUND")
  except TimeoutException:
    print("*" * 80)
    print("REDUCTION TIMED OUT AFTER", args.timeout, "SECONDS")

  if (s[1] + 1) > len(currentTest):
    print("PADDING TEST WITH", (s[1] + 1) - len(currentTest), "ZEROS")
    padding = bytearray('\x00' * ((s[1] + 1) - len(currentTest)), 'utf-8')
    currentTest = currentTest + padding
  
  print("=" * 80)
  percent = 100.0 * ((initialSize - len(currentTest)) / initialSize)
  print("COMPLETED AFTER", iteration, "ITERATIONS:", round(time.time()-start, 2), "SECONDS /",
          candidateRuns, "EXECUTIONS /", str(round(percent, 2)) + "% REDUCTION")
  print("WRITING REDUCED TEST WITH", len(currentTest), "BYTES TO", out)
    
  with open(out, 'wb') as outf:
    outf.write(currentTest)

  return 0

if "__main__" == __name__:
  exit(main())
