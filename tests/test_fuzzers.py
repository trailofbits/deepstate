from __future__ import print_function
import deepstate_base
import logrun
from tempfile import mkdtemp, TemporaryDirectory, mkstemp
from pathlib import Path
from os import path
from glob import glob
import re
import sys


class CrashFuzzerTest(deepstate_base.DeepStateFuzzerTestCase):
  def run_deepstate(self, deepstate):
    def do_compile(tempdir, test_source_file):
      """
      Compile test_source_file using frontend API
      temdir is a workspace 
      """
      # prepare args
      output_test_name = path.join(tempdir, Path(test_source_file).stem)
      _, output_log_file = mkstemp(dir=tempdir)
      arguments = [
        "--compile_test", test_source_file,
        "--out_test_name", output_test_name
      ]

      # run command
      (r, output) = logrun.logrun([deepstate] + arguments, output_log_file, 360)
      compiled_files = glob(output_test_name + '*')

      # check output
      self.assertEqual(r, 0)
      for compiled_file in compiled_files:
        self.assertTrue(path.isfile(compiled_file))

      # return compiled file(s)
      # if Angora fuzzer, file.taint should be before file.fast 
      if any([compiled_file.endswith('.taint') for compiled_file in compiled_files]):
        compiled_files = sorted(compiled_files, reverse=True) 
      return compiled_files


    def crash_found(output):
      """
      Check if some crash were found assuming that
        fuzzer output is the deepstate one (--fuzzer_out == False)
      """
      for crashes_stat in re.finditer(r"^FUZZ_STATS:.*:unique_crashes:(\d+)$",
                                        output, re.MULTILINE):
        if int(crashes_stat.group(1)) > 0:
          return True
      return False


    def do_fuzz(tempdir, compiled_files):
      """
      Fuzz compiled_files (single compiled test/harness or two files if Angora)
      until first crash
      """
      # prepare args
      _, output_log_file = mkstemp(dir=tempdir)
      output_test_dir = mkdtemp(dir=tempdir)
      
      arguments = [
        "--output_test_dir", output_test_dir
      ] + compiled_files

      # run command
      (r, output) = logrun.logrun([deepstate] + arguments, output_log_file, 
                                    180, break_callback=crash_found)

      # check output
      self.assertTrue(crash_found(output))


    test_source_file = "examples/SimpleCrash.cpp"
    with TemporaryDirectory(prefix="deepstate_test_fuzzers_") as tempdir:
      compiled_files = do_compile(tempdir, test_source_file)
      do_fuzz(tempdir, compiled_files)
