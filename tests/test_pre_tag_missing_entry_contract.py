"""Nachtrag 32, point 4 (card OA-efb0df3845): a sys.path entry that is MISSING is judged by its spelling, not
its existence. A missing entry that spells its way INTO the checkout is barred at both the path cleaning and the
startup search-path check; a missing entry OUTSIDE the checkout stays a control (it is kept / not reported).

This locks the contract the docstring of `_judged_location` now states ("spelling first, then identity;
'contains nothing' is an identity-test statement"). It is a contract lock, green at f65e9ec1 and after; the
docstring precision is the change, the behaviour was already correct and must not regress.
"""
from __future__ import annotations

import importlib.util
import os
import pathlib
import shutil
import tempfile
import types
import unittest
from unittest import mock

REPO = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = REPO / "scripts"


def _load(rel: str, name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class AMissingEntryIsJudgedBySpellingNotExistence(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not (SCRIPTS / "verify_pre_tag_receipt.py").is_file():
            raise unittest.SkipTest("scripts/verify_pre_tag_receipt.py is not in this tree")
        cls.vp = _load("verify_pre_tag_receipt.py", "_missing_entry_verifier")

    def setUp(self):
        base = tempfile.mkdtemp(prefix="pre-tag-missing-")
        self.addCleanup(shutil.rmtree, base, ignore_errors=True)
        self.root = os.path.realpath(os.path.join(base, "clone"))
        os.makedirs(self.root)
        self.outside = os.path.realpath(tempfile.mkdtemp(prefix="pre-tag-outside-"))
        self.addCleanup(shutil.rmtree, self.outside, ignore_errors=True)
        # neither of these exists on disk
        self.in_clone_missing = os.path.join(self.root, "absent-pkg")
        self.outside_missing = os.path.join(self.outside, "absent-pkg")

    def test_judged_location_bars_a_missing_in_clone_entry_and_passes_a_missing_outside_one(self):
        jl = self.vp._judged_location
        self.assertTrue(jl(os.path.realpath(self.in_clone_missing), self.root),
                        "a missing directory of the checkout is contained by its spelling (barred)")
        self.assertFalse(jl(os.path.realpath(self.outside_missing), self.root),
                         "a missing directory outside the checkout is not contained (a control)")

    def test_cleaning_drops_the_missing_in_clone_entry_and_keeps_the_missing_outside_one(self):
        with mock.patch.object(self.vp, "_checkout_root", lambda: self.root), \
             mock.patch.object(self.vp.sys, "path", [self.in_clone_missing, self.outside_missing,
                                                     "/usr/lib/python3.11"]):
            self.vp._remove_the_judged_tree_from_sys_path()
            kept = list(self.vp.sys.path)
        self.assertNotIn(self.in_clone_missing, kept, "a missing in-clone entry must be removed before import")
        self.assertIn(self.outside_missing, kept, "a missing outside entry stays a control")

    def test_startup_check_reports_the_missing_in_clone_entry_only(self):
        flags = types.SimpleNamespace(isolated=1)
        with mock.patch.object(self.vp, "_checkout_root", lambda: self.root), \
             mock.patch.object(self.vp.sys, "flags", flags), \
             mock.patch.object(self.vp.sys, "path", [self.in_clone_missing, self.outside_missing,
                                                     "/usr/lib/python3.11"]):
            reported = self.vp._startup_search_paths_into_the_checkout()
        self.assertIn(self.in_clone_missing, reported, "a missing in-clone entry is barred at the startup check")
        self.assertNotIn(self.outside_missing, reported, "a missing outside entry stays a control")


if __name__ == "__main__":
    unittest.main()
