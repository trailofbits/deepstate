from __future__ import print_function
import subprocess
import time
import sys
from tempfile import mkdtemp
from shutil import rmtree


def logrun(cmd, file, timeout, break_callback=None):
  sys.stderr.write("\n\n" + ("=" * 80) + "\n")
  sys.stderr.write("RUNNING: ")
  sys.stderr.write(" ".join(cmd) + "\n\n")
  sys.stderr.flush()

  tmp_out_dir = None
  with open(file, 'w') as outf:
    additional_args = []

    # auto-create output dir
    if set(cmd).isdisjoint({"-o", "--output_test_dir", "--out_test_name"}):
      tmp_out_dir = mkdtemp(prefix="deepstate_logrun_")
      additional_args.extend(["--output_test_dir", tmp_out_dir])  # create empty output dir

    # We need to set log_level so we see ALL messages, for testing
    if "--min_log_level" not in cmd:
      additional_args.extend(["--min_log_level", "0"])

    p = subprocess.Popen(cmd + additional_args, stdout=outf, stderr=outf)

  start = time.time()
  oldContents = ""
  lastOutput = time.time()
  while (p.poll() is None) and ((time.time() - start) < timeout):
    if (time.time() - lastOutput) > 300:
      sys.stderr.write(".")
      sys.stderr.flush()
      lastOutput = time.time()

    with open(file, 'r') as inf:
      contents = inf.read()

    if len(contents) > len(oldContents):
      sys.stderr.write(contents[len(oldContents):])
      sys.stderr.flush()
      oldContents = contents
      lastOutput = time.time()

    if break_callback and break_callback(contents):
      break

    time.sleep(0.05)

  totalTime = time.time() - start
  sys.stderr.write("\n")

  rv = (p.returncode, contents)
  if p.poll() is None:
    rv = ("TIMEOUT", contents)
  if "Traceback (most recent call last)" in contents:
    rv = ("EXCEPTION RAISED", contents)
  if "internal error" in contents:
    rv = ("INTERNAL ERROR", contents)

  sys.stderr.write("\nDONE\n\n")
  sys.stderr.write("TOTAL EXECUTION TIME: " + str(totalTime) + "\n")
  sys.stderr.write("RETURN VALUE: " + str(p.returncode) + "\n")
  sys.stderr.write("RETURNING AS RESULT: " + str(rv[0]) + "\n")
  sys.stderr.write("=" * 80 + "\n")

  if tmp_out_dir:
    rmtree(tmp_out_dir, ignore_errors=True)

  return rv
