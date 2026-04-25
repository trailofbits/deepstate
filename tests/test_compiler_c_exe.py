#!/usr/bin/env python3
"""
Tests for the COMPILER_C / compiler_c_exe changes described in issue #337.

Place this file at:  deepstate/tests/test_compiler_c_exe.py

Run from the repo root:
    cd deepstate
    PYTHONPATH=bin python3 -m unittest tests.test_compiler_c_exe -v
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

# ---------------------------------------------------------------------------
# Make sure the real deepstate package is importable.
# All tests in this repo are run with PYTHONPATH=bin, which puts
# bin/deepstate on the path — mirroring how the other tests work.
# ---------------------------------------------------------------------------
from deepstate.core.base import AnalysisBackend, AnalysisBackendError
from deepstate.core.fuzz import FuzzerFrontend, FuzzFrontendError
from deepstate.executors.fuzz.afl import AFL


# ---------------------------------------------------------------------------
# Helper: build a concrete FuzzerFrontend subclass on the fly
# ---------------------------------------------------------------------------

def make_frontend(executables: dict, compile_test: str = "harness.cpp"):
    """
    Returns an instantiated FuzzerFrontend subclass configured with the
    given EXECUTABLES dict and compile_test path.
    Each call gets its own fresh copy of the dict so tests don't bleed
    into each other.
    """

    class TestFrontend(FuzzerFrontend):
        NAME = "TestFuzzer"
        EXECUTABLES = dict(executables)
        ENVVAR = "PATH"

    frontend = TestFrontend()
    frontend.compile_test = compile_test
    return frontend


# ---------------------------------------------------------------------------
# 1. base.py — compiler_c_exe is initialised from EXECUTABLES
# ---------------------------------------------------------------------------

class TestCompilerCExeInit(unittest.TestCase):

    def test_compiler_c_exe_set_when_provided(self):
        fe = make_frontend({
            "FUZZER":     "afl-fuzz",
            "COMPILER":   "afl-clang++",
            "COMPILER_C": "afl-clang",
        })
        self.assertEqual(fe.compiler_c_exe, "afl-clang")

    def test_compiler_c_exe_none_when_not_provided(self):
        fe = make_frontend({
            "FUZZER":   "afl-fuzz",
            "COMPILER": "afl-clang++",
        })
        self.assertIsNone(fe.compiler_c_exe)

    def test_compiler_c_exe_popped_from_executables(self):
        """COMPILER_C must be removed from EXECUTABLES after init."""
        fe = make_frontend({
            "FUZZER":     "afl-fuzz",
            "COMPILER":   "afl-clang++",
            "COMPILER_C": "afl-clang",
        })
        self.assertNotIn("COMPILER_C", fe.EXECUTABLES)


# ---------------------------------------------------------------------------
# 2. fuzz.py _set_executables() — compiler_c_exe is resolved
# ---------------------------------------------------------------------------

class TestSetExecutables(unittest.TestCase):

    def test_compiler_c_exe_resolved(self):
        fe = make_frontend({
            "FUZZER":     "afl-fuzz",
            "COMPILER":   "afl-clang++",
            "COMPILER_C": "afl-clang",
        })
        # patch _search_for_executable to avoid needing real binaries installed
        with patch.object(fe, "_search_for_executable", side_effect=lambda x: x):
            fe._set_executables()
        self.assertEqual(fe.compiler_c_exe, "afl-clang")

    def test_compiler_c_exe_skipped_when_none(self):
        fe = make_frontend({
            "FUZZER":   "afl-fuzz",
            "COMPILER": "afl-clang++",
        })
        with patch.object(fe, "_search_for_executable", side_effect=lambda x: x):
            fe._set_executables()
        self.assertIsNone(fe.compiler_c_exe)


# ---------------------------------------------------------------------------
# 3. fuzz.py compile() — CC / CXX env vars
# ---------------------------------------------------------------------------

class TestCompileEnvVars(unittest.TestCase):

    def _run_compile(self, frontend):
        """Run compile() with subprocess and filesystem mocked out."""
        captured_env = {}

        def fake_popen(cmd, env=None):
            captured_env.update(env or {})
            m = MagicMock()
            m.communicate.return_value = (b"", b"")
            return m

        with patch("subprocess.Popen", side_effect=fake_popen), \
             patch("os.path.isfile", return_value=True), \
             patch("os.path.exists", return_value=False):
            frontend.compile(lib_path="/fake/lib.a", flags=[], _out_bin="out")

        return captured_env

    def test_cc_uses_compiler_c_exe_when_set(self):
        fe = make_frontend({
            "FUZZER":     "afl-fuzz",
            "COMPILER":   "afl-clang++",
            "COMPILER_C": "afl-clang",
        })
        env = self._run_compile(fe)
        self.assertEqual(env["CC"],  "afl-clang")
        self.assertEqual(env["CXX"], "afl-clang++")

    def test_cc_falls_back_to_stripping_plusplus(self):
        """Without COMPILER_C, CC should be derived by stripping '++'."""
        fe = make_frontend({
            "FUZZER":   "afl-fuzz",
            "COMPILER": "afl-clang++",
        })
        env = self._run_compile(fe)
        self.assertEqual(env["CC"],  "afl-clang")
        self.assertEqual(env["CXX"], "afl-clang++")


# ---------------------------------------------------------------------------
# 4. fuzz.py compile() — correct compiler binary and -std flag
# ---------------------------------------------------------------------------

class TestCompileCommandSelection(unittest.TestCase):

    def _captured_cmd(self, compile_test, executables):
        captured = {}

        def fake_popen(cmd, env=None):
            captured["cmd"] = cmd
            m = MagicMock()
            m.communicate.return_value = (b"", b"")
            return m

        fe = make_frontend(executables, compile_test=compile_test)

        with patch("subprocess.Popen", side_effect=fake_popen), \
             patch("os.path.isfile", return_value=True), \
             patch("os.path.exists", return_value=False):
            fe.compile(lib_path="/fake/lib.a", flags=[], _out_bin="out")

        return captured["cmd"]

    def test_c_file_uses_c_compiler_and_c11(self):
        cmd = self._captured_cmd(
            compile_test="harness.c",
            executables={
                "FUZZER":     "afl-fuzz",
                "COMPILER":   "afl-clang++",
                "COMPILER_C": "afl-clang",
            },
        )
        self.assertEqual(cmd[0], "afl-clang",
                         "C file should use the C compiler, not the C++ one")
        self.assertIn("-std=c11", cmd)
        self.assertNotIn("-std=c++11", cmd)

    def test_cpp_file_uses_cxx_compiler_and_cpp11(self):
        cmd = self._captured_cmd(
            compile_test="harness.cpp",
            executables={
                "FUZZER":     "afl-fuzz",
                "COMPILER":   "afl-clang++",
                "COMPILER_C": "afl-clang",
            },
        )
        self.assertEqual(cmd[0], "afl-clang++",
                         "C++ file should use the C++ compiler")
        self.assertIn("-std=c++11", cmd)
        self.assertNotIn("-std=c11", cmd)

    def test_c_file_fallback_does_not_use_cxx_binary(self):
        """Even without COMPILER_C, a .c file must not use afl-clang++."""
        cmd = self._captured_cmd(
            compile_test="harness.c",
            executables={
                "FUZZER":   "afl-fuzz",
                "COMPILER": "afl-clang++",
            },
        )
        self.assertNotEqual(cmd[0], "afl-clang++")
        self.assertEqual(cmd[0], "afl-clang")


# ---------------------------------------------------------------------------
# 5. afl.py — EXECUTABLES has COMPILER_C with the correct value
# ---------------------------------------------------------------------------

class TestAFLExecutables(unittest.TestCase):

    def test_afl_has_compiler_c_key(self):
        self.assertIn("COMPILER_C", AFL.EXECUTABLES)

    def test_afl_compiler_c_is_afl_clang(self):
        self.assertEqual(AFL.EXECUTABLES["COMPILER_C"], "afl-clang")

    def test_afl_compiler_c_differs_from_compiler(self):
        self.assertNotEqual(
            AFL.EXECUTABLES["COMPILER_C"],
            AFL.EXECUTABLES["COMPILER"],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
