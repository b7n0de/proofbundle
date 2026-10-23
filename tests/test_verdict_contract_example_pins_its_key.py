"""K4 (Codex defect search on the 6.3.0 candidate 98b168b9, CODEX-630-K4): the example checker takes the key it
trusts from outside the package it checks.

`check_example.py DIR` read `DIR/publickey.hex` and used it as the pin for `DIR/receipt.json`, and the producer
writes both files. A package issued by key B, its own `publickey.hex` included, therefore passed in place of the
package of the expected key A: measured at 98b168b9 and at f6ea5cc3, exit 0 for both. The checker now pins the
example key itself, or takes the expected key from its caller (`--public-key`); `DIR/publickey.hex` decides
nothing. Test keys only, generated per case by `make_example.py`.
"""
from __future__ import annotations

import importlib.util
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
EXAMPLE = REPO / "examples" / "verdict_contract"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(f"_k4_{name}", EXAMPLE / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(EXAMPLE))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(EXAMPLE))
    return module


class TheExampleCheckerPinsItsKey(unittest.TestCase):

    def setUp(self):
        for needed in ("check_example.py", "make_example.py", "reply.txt", "out/receipt.json"):
            if not (EXAMPLE / needed).is_file():
                self.skipTest(f"examples/verdict_contract/{needed} is not in this tree")
        if shutil.which("git") is None:
            self.skipTest("the example rebuilds its toy repository with git")
        d = tempfile.mkdtemp(prefix="k4-")
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        self.base = pathlib.Path(d)

    def _package(self, name: str) -> tuple[pathlib.Path, str]:
        """A package made by make_example.py with a fresh test key of its own; (folder, public key hex)."""
        key, out = self.base / f"{name}.key", self.base / name
        r = subprocess.run([sys.executable, "-B", str(EXAMPLE / "make_example.py"), "--reply",
                            str(EXAMPLE / "reply.txt"), "--key", str(key), "--out", str(out),
                            "--declared-at", "2026-10-11T08:30:00Z"],
                           capture_output=True, text=True, timeout=300, cwd=str(self.base))
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])
        public = _load("make_example").load_key(key).public_key().public_bytes_raw().hex()
        return out, public

    def _check(self, folder: pathlib.Path, *extra: str) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, "-B", str(EXAMPLE / "check_example.py"), str(folder), *extra],
                              capture_output=True, text=True, timeout=300, cwd=str(self.base))

    def test_RED_a_package_of_another_key_does_not_pass_for_the_expected_one(self):
        """T4: with A expected, the package of B, its own publickey.hex included, is refused."""
        a, key_a = self._package("a")
        b, key_b = self._package("b")
        self.assertEqual((b / "publickey.hex").read_text().strip(), key_b, "precondition: B ships its own key")
        self.assertEqual(self._check(a, "--public-key", key_a).returncode, 0, "A with A expected")
        refused = self._check(b, "--public-key", key_a)
        self.assertEqual(refused.returncode, 1, refused.stdout)
        self.assertIn("crypto=False", refused.stdout)

    def test_RED_without_a_given_key_the_checker_uses_its_own_pin(self):
        """Neither A nor B is the example key the checker pins, so without --public-key both are refused,
        whatever their publickey.hex says."""
        for name in ("a", "b"):
            folder, _key = self._package(name)
            self.assertEqual(self._check(folder).returncode, 1, name)

    def test_CONTROL_the_shipped_package_passes_with_the_pin_and_B_with_B_given(self):
        shipped = self.base / "out"
        shutil.copytree(EXAMPLE / "out", shipped, ignore=shutil.ignore_patterns("toyrepo"))
        self.assertEqual(self._check(shipped).returncode, 0)
        b, key_b = self._package("b")
        self.assertEqual(self._check(b, "--public-key", key_b).returncode, 0)


if __name__ == "__main__":
    unittest.main()
