import os
import shutil
import logging
from unittest import TestCase
from deepstate.executors.fuzz.afl import AFL


from typing import Text


L = logging.getLogger(__name__)


expected_contents = set(["0", "1", "2", "3",
                        "4", "5", "6", "7",
                        "8", "README.txt"])


def create_crash_dirs(path: Text) -> None:
  dir_i, crash_i = 0, 0
  while dir_i < 3:
    i, crash_dir = 0, os.path.join(path, "crashes")
    if dir_i:
      crash_dir += ".dir_" + str(dir_i)
    os.mkdir(crash_dir, 0o777)
    crash_file = os.path.join(crash_dir, "README.txt")
    with open(crash_file, "w") as f:
      f.write(crash_file)
    while i < 3:
      crash_file = os.path.join(crash_dir, str(crash_i))
      with open(crash_file, "w") as f:
        f.write(crash_file)
      i, crash_i = i + 1, crash_i + 1
    dir_i += 1


class AFLCombineCrashDirsTest(TestCase):
  def test_combine_crash_directories(self):
    afl = AFL("deepstate-afl")
    afl.output_test_dir = os.path.join(os.getcwd(), "tests")
    crash_out_dir = os.path.join(afl.output_test_dir, "the_fuzzer")
    os.mkdir(crash_out_dir, 0o777)
    create_crash_dirs(crash_out_dir)
    afl.consolidate_crash_dirs()
    contents = set()
    for directory in os.listdir(crash_out_dir):
        crash_dir = os.path.join(crash_out_dir, directory)
        for f in os.listdir(crash_dir):
          contents.add(f)
    shutil.rmtree(crash_out_dir)
    self.assertEqual(len(expected_contents - contents), 0)
