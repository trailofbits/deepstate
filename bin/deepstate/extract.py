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

  parser = argparse.ArgumentParser(description="Extract standalone test information from a DeepState harness run")

  parser.add_argument(
    "run", type=str, help="Path to DeepState run output.")
  parser.add_argument(
    "template", type=str, help="Path to test template.")
  parser.add_argument(
    "output_file", type=str, help="Path to output standalone test.")

  args = parser.parse_args()

  run = []
  with open(args.run, 'r') as rfile:
    for line in rfile:
      run.append(line)

  newSource = []
  with open(args.template, 'r') as tfile:
    for line in tfile:
      if "<<INSERT TEST CODE HERE>>" not in line:
        newSource.append(line)
      else:
        for line in run:
          if "/* START STANDALONE CODE */" in line:
            newLine = line.split("/* START STANDALONE CODE */")[1]
            newLine = newLine.split("/* END STANDALONE CODE */")[0]
            newLine += "\n"
            print(newLine[:-1])
            newSource.append(newLine)

  with open(args.output_file, 'w') as ntfile:
    for line in newSource:
      ntfile.write(line)

if "__main__" == __name__:
  exit(main())
