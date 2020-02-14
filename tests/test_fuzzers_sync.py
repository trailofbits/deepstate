from __future__ import print_function

import base64
import deepstate_base
import logrun
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
from tempfile import TemporaryDirectory
from tempfile import mkdtemp
from tempfile import mkstemp
from time import sleep
from unittest import TestCase


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
        proc = subprocess.Popen([exe] + arguments + ["--fuzzer_out"])
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


    def wait_for_crashes(fuzzers, timeout, crashes_required):
      fuzzers_done = set()
      start_time = int(time.time())

      while len(fuzzers_done) < len(fuzzers):
        self.assertLess(time.time() - start_time, timeout)
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
            for stat in ["unique_crashes", "sync_dir_size", "execs_done", "paths_total"]:
              if stat in stats:
                print(f"{stat}: {stats[stat]}", end="\t|\t")
            print("")

            if int(stats["unique_crashes"]) >= crashes_required:
              fuzzers_done.add(fuzzer)
          except FileNotFoundError:
            print(f"Stats for {fuzzer} (`{values['stats_file']}`) - not found")
          sleep(1)

      print(f"CRASH {crashes_required} - done")
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

      from deepstate.executors.fuzz.afl import AFL
      fuzzers["afl"]["class"] = AFL
      # from deepstate.executors.fuzz.angora import Angora
      # fuzzers["angora"]["class"] = Angora
      # from deepstate.executors.fuzz.honggfuzz import Honggfuzz
      # from deepstate.executors.fuzz.eclipser import Eclipser
      from deepstate.executors.fuzz.libfuzzer import LibFuzzer
      fuzzers["libfuzzer"]["class"] = LibFuzzer

      # run them for a bit
      print("Fuzzers started, waiting 5 seconds.")
      sleep(2)

      # assert that all fuzzers started
      print("Checking if fuzzers are up and running")
      for fuzzer, values in fuzzers.items():
        try:
          self.assertTrue(values["proc"].poll() is None)
        except Exception as e:
          print(f"Error for fuzzer {fuzzer}:")
          print(values["proc"].stderr.read().decode('utf8'))
          raise e
        push_dir = os.path.join(values["output_dir"], values["class"].PUSH_DIR)
        self.assertTrue(os.path.isdir(push_dir))

      # manually push first crashing seed to AFL local dir
      push_dir = os.path.join(fuzzers["afl"]["output_dir"], fuzzers["afl"]["class"].PUSH_DIR)
      print(f"Pushing seed 1 to AFL: `{push_dir}`")
      with open(os.path.join(push_dir, "id:000101,first_crash"), "wb") as f:
        f.write(b64decode("R3JvcyBwemRyQUFBQUFBQUFB"))

      # check if all fuzzers find first crash using afl's seed
      wait_for_crashes(fuzzers, one_crash_sync_timeout, 1)

      # # manually push second crashing seed to Angora local dir
      # push_dir = os.path.join(fuzzers["angora"]["output_dir"], ANGORA_PUSH_DIR)
      # print(f"Pushing seed 2 to Angora: `{push_dir}`")
      # with open(os.path.join(push_dir, "id:000202,second_crash"), "wb") as f:
      #   f.write(b64decode("R3JvcyBwemRyIGZyb20gUEwu"))

      # # check if all fuzzers find first crash using afl's seed
      # wait_for_crashes(fuzzers, one_crash_sync_timeout, 2)


    # config
    fuzzers_list = ["afl", "libfuzzer"]
    output_from_fuzzer = None

    # init
    fuzzers = dict()
    one_crash_sync_timeout = 4*60
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
      for _, value in fuzzers.items():
        try:
          proc = value["proc"]
          for some_proc in psutil.Process(proc.pid).children(recursive=True) + [proc]:
            some_proc.kill()
        except:
          pass

      # filesystem
      try:
        rmtree(workspace_dir, ignore_errors=True)
        rmtree(sync_dir, ignore_errors=True)
      except:
        pass

      # now can raise
      raise e
