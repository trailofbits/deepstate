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

import argparse
import subprocess

def main():
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

    args = parser.parse_args()

    deepstate = args.binary
    test = args.input_test
    out = args.output_test
    checkString = args.criteria
    whichTest = args.which_test

    def runCandidate(candidate):
        with open(".reducer.out", 'w') as outf:
            cmd = [deepstate + " --input_test_file " +
                   candidate + " --verbose_reads"]
            if whichTest is not None:
                cmd += ["--input_which_test", whichTest]
            subprocess.call(cmd, shell=True, stdout=outf, stderr=outf)
        result = []
        with open(".reducer.out", 'r') as inf:
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

    def structure(result):
        OneOfs = []
        currentOneOf = []
        for line in result:
            if "STARTING OneOf CALL" in line:
                currentOneOf.append(-1)
            elif "Reading byte at" in line:
                lastRead = int(line.split()[-1])
                if currentOneOf[-1] == -1:
                    currentOneOf[-1] = lastRead
            elif "FINISHED OneOf CALL" in line:
                OneOfs.append((currentOneOf[-1], lastRead))
                currentOneOf = currentOneOf[:-1]
        return (OneOfs, lastRead)

    initial = runCandidate(test)
    if not checks(initial):
        print "STARTING TEST DOES NOT SATISFY REDUCTION CRITERIA"
        return 1

    with open(test, 'rb') as test:
        currentTest = bytearray(test.read())

    print "ORIGINAL TEST HAS", len(currentTest), "BYTES"

    s = structure(initial)
    print "LAST BYTE READ IS", s[1]

    if s[1] < len(currentTest):
        print "SHRINKING TO IGNORE UNREAD BYTES"
        currentTest = currentTest[:s[1]+1]

    changed = True
    while changed:
        changed = False
        cuts = s[0]
        for c in cuts:
            newTest = currentTest[:c[0]] + currentTest[c[1]+1:]
            with open(".candidate.test", 'wb') as outf:
                outf.write(newTest)
            r = runCandidate(".candidate.test")
            if checks(r):
                print "ONEOF REMOVAL REDUCED TEST TO", len(newTest), "BYTES"
                s = structure(r)
                changed = True
                currentTest = newTest
                break
        if changed:
            continue
        for b in range(0, len(currentTest)):
            for v in range(b+1, len(currentTest)):
                newTest = currentTest[:b] + currentTest[v:]
                with open(".candidate.test", 'wb') as outf:
                    outf.write(newTest)
                r = runCandidate(".candidate.test")
                if checks(r):
                    print "BYTE RANGE REMOVAL REDUCED TEST TO", len(newTest), "BYTES"
                    s = structure(r)
                    changed = True
                    currentTest = newTest
                    break
        if changed:
            continue
        for b in range(0, len(currentTest)):
            for v in range(0, currentTest[b]):
                newTest = bytearray(currentTest)
                newTest[b] = v
                with open(".candidate.test", 'wb') as outf:
                    outf.write(newTest)
                r = runCandidate(".candidate.test")
                if checks(r):
                    print "BYTE REDUCTION: BYTE", b, "FROM", currentTest[b], "TO", v
                    s = structure(r)
                    changed = True
                    currentTest = newTest
                    break
        for b in range(0, len(currentTest)):
            newTest = bytearray(currentTest)
            newTest[b] = currentTest[b]-1
            newTest = newTest[:b+1] + newTest[b+2]
            with open(".candidate.test", 'wb') as outf:
                outf.write(newTest)
            r = runCandidate(".candidate.test")
            if checks(r):
                print "BYTE REDUCE AND DELETE AT BYTE", b
                s = structure(r)
                changed = True
                currentTest = newTest
                break

    print "NO REDUCTIONS FOUND"

    if (s[1] + 1) > len(currentTest):
        print "PADDING TEST WITH", (s[1] + 1) - len(currentTest), "ZEROS"
        padding = bytearray('\x00' * ((s[1] + 1) - len(currentTest)))
        currentTest = currentTest + padding
    
    print
    print "WRITING REDUCED TEST TO", out
        
    with open(out, 'wb') as outf:
        outf.write(currentTest)

    return 0

if "__main__" == __name__:
  exit(main())
