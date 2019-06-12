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


def main():
  global candidateRuns, currentTest, s, passStart

  parser = argparse.ArgumentParser(description="Intelligently reduce test case")

  parser.add_argument(
    "source", type=str, help="Path to input harness file.")
  parser.add_argument(
    "output_source", type=str, help="Path to output modified harness file.")
  parser.add_argument(
    "config", type=str, help="Path for configuration file listing functions to export to standalone.")

  args = parser.parse_args()

  functions = []

  def annotate(call, f):
    annotated = ""
    pos = 0
    spaces = ""
    for c in call:
      if c.isspace():
        spaces += c
        pos += 1
      else:
        break
    arguments = call.split(f + "(")[1]
    arguments = arguments.split(")")[0]
    theArgs = arguments.split(",")
    annotated += "LOG(TRACE) << "
    annotated += '"/* START STANDALONE CODE */' + spaces + call[pos:call.find("(") + 1] + '" << '
    if f != "assert":
      for arg in theArgs[:-1]:
        annotated += ("DeepState_Standalone_Wrap(" + arg + ') << "," << ')
      if len(theArgs) >= 1:
        annotated += ("DeepState_Standalone_Wrap(" + theArgs[-1] + ') << ')
    else:
      for i in range(1, len(call)):
        if call[-i] == ")":
          endPos = i
          break
      annotated += '"' + call[call.find("(")+1:-endPos] + '" << '
    annotated += '"); /* END STANDALONE CODE */";\n'
    return annotated
  
  with open(args.config, 'r') as cfile:
    for line in cfile:
      functions.append(line.split()[0])

  for f in functions:
    print("ADDING STANDALONE TEST GENERATION CODE FOR", f)

  functions.append("assert")
  
  oldSource = []
  with open(args.source, 'r') as sfile:
    for line in sfile:
      oldSource.append(line);

  newSource = []
  inTests = False
  for line in oldSource:
    if inTests:
      for f in functions:
        if f+"(" in line:
          print("ADDING TEST GENERATION CODE FOR:", line[:-1])
          a = annotate(line, f)
          print(a)
          newSource.append(a)
    elif "TEST(" in line:
      inTests = True
    newSource.append(line)

  with open(args.output_source, 'w') as nsfile:
    for line in newSource:
      nsfile.write(line)

if "__main__" == __name__:
  exit(main())
