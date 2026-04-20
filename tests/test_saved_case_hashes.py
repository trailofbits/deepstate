from __future__ import print_function
import hashlib
from pathlib import Path
from shutil import rmtree
from tempfile import mkdtemp
from unittest import TestCase

import logrun


class SavedCaseHashesTest(TestCase):
  def test_saved_case_filenames_match_input_md5(self):
    output_dir = mkdtemp(prefix="deepstate_saved_case_hashes_")

    try:
      (r, output) = logrun.logrun([
        "build/examples/OneOf",
        "--fuzz",
        "--timeout", "2",
        "--no_fork",
        "--output_test_dir", output_dir,
      ], "deepstate.out", 1800,
        filters=["Assumption", "Abandoned", "CRITICAL", "ERROR"])

      self.assertEqual(r, 0)
      self.assertTrue("Saved test case in file" in output)

      saved_cases = [path for path in Path(output_dir).rglob("*") if path.is_file()]
      self.assertTrue(saved_cases)

      for saved_case in saved_cases:
        self.assertEqual(
          saved_case.stem,
          hashlib.md5(saved_case.read_bytes()).hexdigest())
    finally:
      rmtree(output_dir, ignore_errors=True)