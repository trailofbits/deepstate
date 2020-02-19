from __future__ import print_function
import subprocess
import time
import sys
from tempfile import mkdtemp
from shutil import rmtree
import psutil


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

    proc = subprocess.Popen(cmd + additional_args, stdout=outf, stderr=outf)

  callback_break = False
  oldContentLen = 0
  start = time.time()
  lastOutput = time.time()
  inf = open(file, 'r')
  while (proc.poll() is None) and ((time.time() - start) < timeout):
    inf.seek(0, 2)
    newContentLen = inf.tell()

    if newContentLen > oldContentLen:
      inf.seek(oldContentLen, 0)
      newContent = inf.read()
      sys.stderr.write(newContent)
      sys.stderr.flush()
      oldContentLen = newContentLen
      lastOutput = time.time()

      if break_callback and break_callback(newContent):
        callback_break = True
        break

    if (time.time() - lastOutput) > 300:
      sys.stderr.write(".")
      sys.stderr.flush()
      lastOutput = time.time()

    time.sleep(0.5)

  totalTime = time.time() - start
  sys.stderr.write("\n")

  inf.seek(oldContentLen, 0)
  newContent = inf.read()
  sys.stderr.write(newContent)
  sys.stderr.flush()
  inf.seek(0, 0)
  contents = inf.read()
  inf.close()

  rv = [proc.returncode, contents]
  if callback_break:
    rv[0] = "CALLBACK_BREAK"
  elif proc.poll() is None:
    rv[0] = "TIMEOUT"
  elif "Traceback (most recent call last)" in contents:
    rv[0] = "EXCEPTION RAISED"
  elif "internal error" in contents:
    rv[0] = "INTERNAL ERROR"

  try:
    for some_proc in psutil.Process(proc.pid).children(recursive=True) + [proc]:
        some_proc.terminate()
  except psutil.NoSuchProcess:
    pass

  sys.stderr.write("\nDONE\n\n")
  sys.stderr.write("TOTAL EXECUTION TIME: " + str(totalTime) + "\n")
  sys.stderr.write("RETURN VALUE: " + str(proc.returncode) + "\n")
  sys.stderr.write("RETURNING AS RESULT: " + str(rv[0]) + "\n")
  sys.stderr.write("=" * 80 + "\n")

  if tmp_out_dir:
    rmtree(tmp_out_dir, ignore_errors=True)

  return rv
