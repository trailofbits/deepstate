from __future__ import print_function

import os
import re
import subprocess
import sys
import time

from base64 import b64decode
from glob import glob
from os import path
from pathlib import Path
from shutil import rmtree
from tempfile import mkdtemp
from tempfile import mkstemp
from time import sleep
from unittest import TestCase

import psutil


class CrashFuzzerTest(TestCase):
  def test_fuzzers_synchronization(self):
    def do_compile(fuzzer, tempdir, test_source_file):
      """
      Compile test_source_file using frontend API
      temdir is a workspace 
      """
      print(f"Compiling testcase for fuzzer {fuzzer}")

      # prepare args
      output_test_name = path.join(tempdir, Path(test_source_file).stem)
      _, output_log_file = mkstemp(dir=tempdir)
      arguments = [
        "--compile_test", test_source_file,
        "--out_test_name", output_test_name
      ]

      # run command
      proc = subprocess.Popen([f"deepstate-{fuzzer}"] + arguments)
      proc.communicate()
      compiled_files = glob(output_test_name + f"*.{fuzzer}")

      # check output
      self.assertEqual(proc.returncode, 0)
      for compiled_file in compiled_files:
        self.assertTrue(path.isfile(compiled_file))

      # return compiled file(s)
      # if Angora fuzzer, file.taint should be before file.fast 
      if any([compiled_file.endswith('.taint.angora') for compiled_file in compiled_files]):
        compiled_files = sorted(compiled_files, reverse=True) 
      return compiled_files


    def do_fuzz(fuzzer, workspace_dir, sync_dir, compiled_files, output_from_fuzzer=None):
      """
      Fuzz compiled_files (single compiled test/harness or two files if Angora)
      until first crash
      """
      # prepare args
      output_dir = mkdtemp(prefix=f"deepstate_{fuzzer}_", dir=workspace_dir)

      arguments = [
        "--output_test_dir", output_dir,
        "--sync_dir", sync_dir,
        "--sync_cycle", "5",
        "--min_log_level", "0"
      ] + compiled_files

      # run command
      exe = f"deepstate-{fuzzer}"
      cmd = ' '.join([exe] + arguments)
      print(f"Running: `{cmd}`.")
      if output_from_fuzzer and output_from_fuzzer == fuzzer:
        proc = subprocess.Popen([exe] + arguments)
      else:
        proc = subprocess.Popen([exe] + arguments,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
      return output_dir, proc


    def crashes_found(fuzzer, output):
      """
      Check if some crash were found assuming that
        fuzzer output is the deepstate one (--fuzzer_out == False)
      """
      no_crashes = 0
      for crashes_stat in re.finditer(r"^unique_crashes:(\d+)$",
                                        output, re.MULTILINE):
        no_crashes = int(crashes_stat.group(1))
      print(f"Crashes found by fuzzer {fuzzer} - {no_crashes}.")
      return 0


    def wait_for_crashes(fuzzers, timeout):
      for fuzzer in fuzzers:
        fuzzers[fuzzer]["no_crashes"] = 0

      start_time = int(time.time())

      while any([v["no_crashes"] < 1 for _, v in fuzzers.items()]):
        if timeout:
          self.assertLess(time.time() - start_time, timeout, msg="TIMEOUT")

        for fuzzer, values in fuzzers.items():
          try:
            stats = dict()
            with open(values["stats_file"], "r") as f:
              for line in f:
                line = line.strip()
                if ":" not in line:
                  continue
                k, v = line.split(":", 1)
                stats[k] = v

            print("{:10s}:".format(fuzzer), end="\t")
            if values["proc"].poll() is None:
              for stat in ["unique_crashes", "sync_dir_size", "execs_done", "paths_total"]:
                if stat in stats:
                  print("{}: {:10s}".format(stat, stats[stat]), end=" |\t")
              print("")
              fuzzers[fuzzer]["no_crashes"] = int(stats["unique_crashes"])
            else:
              if "unique_crashes" in stats:
                print("unique_crashes: {:10s}".format(stats["unique_crashes"]), end=" |\t")
              print("DEAD " + "OoOoo"*5 + "x...")

          except FileNotFoundError:
            print(f" - stats not found (`{values['stats_file']}`).")

        for _ in range(3):
          print("~*~"*5, end=" - ")
          sys.stderr.flush()
          sys.stdout.flush()  
          sleep(1)
        print("")

      print("CRASHING - done")
      print("-"*50)


    def do_sync_test(output_from_fuzzer=None):
      # start all fuzzers
      for fuzzer in fuzzers.keys():
        output_dir, proc = do_fuzz(fuzzer, workspace_dir, sync_dir,
                                    fuzzers[fuzzer]["compiled_files"],
                                    output_from_fuzzer)
        fuzzers[fuzzer]["output_dir"] = output_dir
        fuzzers[fuzzer]["proc"] = proc
        fuzzers[fuzzer]["stats_file"] = os.path.join(output_dir, "deepstate-stats.txt")

      # import Frontend classes so we can use PUSH/PULL/CRASH dirs
      deepstate_python = os.path.join(os.path.dirname(__file__), "bin", "deepstate")
      print(f"Adding deepstate python path: {deepstate_python}.")
      sys.path.append(deepstate_python)

      if "afl" in fuzzers:
        from deepstate.executors.fuzz.afl import AFL
        fuzzers["afl"]["class"] = AFL
      if "angora" in fuzzers:
        from deepstate.executors.fuzz.angora import Angora
        fuzzers["angora"]["class"] = Angora
      if "honggfuzz" in fuzzers:
        from deepstate.executors.fuzz.honggfuzz import Honggfuzz
        fuzzers["honggfuzz"]["class"] = Honggfuzz
      if "eclipser" in fuzzers:
        from deepstate.executors.fuzz.eclipser import Eclipser
        fuzzers["eclipser"]["class"] = Eclipser
      if "libfuzzer" in fuzzers:
        from deepstate.executors.fuzz.libfuzzer import LibFuzzer
        fuzzers["libfuzzer"]["class"] = LibFuzzer

      # run them for a bit
      wait_for_start = 2
      print(f"Fuzzers started, waiting {wait_for_start} seconds.")
      for _ in range(wait_for_start):
        sleep(1)
        print('.', end="")
        sys.stderr.flush()
        sys.stdout.flush()
      print("")

      # assert that all fuzzers started
      print("Checking if fuzzers are up and running")
      for fuzzer, values in fuzzers.items():
        try:
          self.assertTrue(values["proc"].poll() is None)
        except Exception as e:
          print(f"Error for fuzzer {fuzzer}:")
          if values["proc"] and values["proc"].stderr:
            print(values["proc"].stderr.read().decode('utf8'))
          raise e
        push_dir = os.path.join(values["output_dir"], values["class"].PUSH_DIR)
        self.assertTrue(os.path.isdir(push_dir))

      # manually push crashing seeds to fuzzers local dirs
      seeds = [b64decode("R3JvcyBwemRyIGZyb20gUEwu")]
      fuzzer_id = 0
      for seed_no, seed in enumerate(seeds):
        fuzzer_id %= len(fuzzers)
        fuzzer = sorted(fuzzers.keys())[fuzzer_id]
        values = fuzzers[fuzzer]
        push_dir = os.path.join(values["output_dir"], values["class"].PUSH_DIR)
        print(f"Pushing seed {seed_no} to {fuzzer}: `{push_dir}`")
        with open(os.path.join(push_dir, "id:000201,the_crash"), "wb") as f:
          f.write(seed)
        fuzzer_id += 1

      # check if all fuzzers find at least two crashes
      # that is: the one pushed to its local dir and at least one other
      wait_for_crashes(fuzzers, timeout)


    # config
    fuzzers_list = ["afl", "libfuzzer", "angora", "eclipser", "honggfuzz"]
    output_from_fuzzer = None  # or "afl" etc
    timeout = None

    # init
    fuzzers = dict()
    test_source_file = "examples/EnsembledCrash.cpp"
    sync_dir = mkdtemp(prefix="syncing_")
    workspace_dir = mkdtemp(prefix="workspace_")
    compiled_files_dir = mkdtemp(prefix="compiled_", dir=workspace_dir)

    # compile for all fuzzers
    for fuzzer in fuzzers_list:
      compiled_files = do_compile(fuzzer, compiled_files_dir, test_source_file)
      fuzzers[fuzzer] = {"compiled_files": compiled_files}

    # do testing
    try:
      print("Starting synchronization run")
      do_sync_test(output_from_fuzzer)
    except Exception as e:
      # cleanup
      # hard kill processes
      print('Killing spawned processes.')
      for _, value in fuzzers.items():
        try:
          proc = value["proc"]
          for some_proc in psutil.Process(proc.pid).children(recursive=True) + [proc]:
            some_proc.kill()
        except:
          pass

      # filesystem
      print("Clearing tmp files.")
      try:
        sleep(1)
        rmtree(workspace_dir, ignore_errors=True)
        rmtree(sync_dir, ignore_errors=True)
      except Exception as e2:
        print(f"Error clearing: {e2}")

      # now can raise
      raise e
