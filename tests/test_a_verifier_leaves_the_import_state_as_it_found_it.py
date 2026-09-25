"""A verifier judges a tree; it does not install it into the process that asked.

THE CLASS (measured 2026-09-25 on main 166aec47). Both pre-tag verifiers put the JUDGED tree's `src/`
in front of `sys.path` so that `verify_receipt` can import `proofbundle.signature`, and both set
`sys.pycache_prefix` / `sys.dont_write_bytecode` so that no bytecode next to the judged sources is
read. Neither undid it. In the same process a later plain `import pre_tag_receipt_lib` then resolved
to whatever the judged tree carried under that name: in tests/test_pretag_gate_state_typed_l5_g6_01.py
the forged library one case plants, which failed eight other cases with `cannot import name
'canonical_bytes'` under PYTHONHASHSEED 5 and 7, the orders in which they happened to run.

The gate itself was safe, it loads its library by path. Everyone who ran after it in the same process
was not. That is the by-path fix of 2026-09-17 left open one step further out.

THE PROPERTY, per verifier: after a call over a tree that carries its own `src/pre_tag_receipt_lib.py`,
`sys.path`, `sys.pycache_prefix` and `sys.dont_write_bytecode` are what they were, and a fresh import
by name finds the real library. `scripts/pre_tag_receipt.py` (the producer) is a neighbour on purpose
NOT held to this: it sets the bytecode switches for its whole process so that the audit program it
starts inherits them, and restoring them would break that.
"""
from __future__ import annotations

import importlib
import importlib.util
import pathlib
import subprocess
import sys
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
_SCRIPTS = str(REPO / "scripts")
if _SCRIPTS not in sys.path:
    sys.path.insert(0, _SCRIPTS)


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, REPO / rel)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


def _tree_with_a_forged_library() -> pathlib.Path:
    """A committed git tree whose own `src/` carries a module named like the receipt library."""
    d = pathlib.Path(tempfile.mkdtemp(prefix="importzustand_"))
    (d / "pyproject.toml").write_text('[project]\nversion = "6.0.0"\n', encoding="utf-8")
    (d / "src").mkdir()
    (d / "src" / "pre_tag_receipt_lib.py").write_text("RECEIPT_SCHEMA = 'forged'\n", encoding="utf-8")
    for args in (["init", "-q"], ["add", "-A"],
                 ["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "basis"]):
        subprocess.run(["git", "-C", str(d), *args], check=True, capture_output=True, timeout=60)
    return d


def _zustand():
    return list(sys.path), sys.pycache_prefix, sys.dont_write_bytecode


class TheImportStateIsRestored(unittest.TestCase):

    def _the_real_library_is_found_by_name(self, d: pathlib.Path) -> None:
        alt = sys.modules.pop("pre_tag_receipt_lib", None)
        try:
            lib = importlib.import_module("pre_tag_receipt_lib")
            self.assertTrue(hasattr(lib, "canonical_bytes"), lib.__file__)
            self.assertNotIn(str(d), str(lib.__file__))
        finally:
            sys.modules.pop("pre_tag_receipt_lib", None)
            if alt is not None:
                sys.modules["pre_tag_receipt_lib"] = alt

    def test_the_release_gate(self):
        gate = _load("_importzustand_gate", "scripts/pre_tag_audit_gate.py")
        d = _tree_with_a_forged_library()
        vorher = _zustand()
        r = gate.evaluate(d, "6.0.0")
        self.assertFalse(r["ok"], r)
        self.assertEqual(_zustand(), vorher)
        self._the_real_library_is_found_by_name(d)

    def test_the_readers_verifier(self):
        ver = _load("_importzustand_verify", "scripts/verify_pre_tag_receipt.py")
        d = _tree_with_a_forged_library()
        kopf = subprocess.run(["git", "-C", str(d), "rev-parse", "HEAD"], capture_output=True,
                              text=True, check=True, timeout=30).stdout.strip()
        vorher = _zustand()
        r = ver.measure(d, kopf, "6.0.0")
        # PRECONDITION: the measurement got past the checkout checks, to the point where the judged
        # src is put on the path. Refused earlier, it would never have touched the import state, and
        # the assertion below would hold for a reason that has nothing to do with the restore.
        self.assertEqual(r["verdict"], "NOT_VERIFIED", r)
        self.assertEqual(_zustand(), vorher)
        self._the_real_library_is_found_by_name(d)

    def test_a_second_call_runs_with_the_bytecode_protection_too(self):
        """Restored after each call, the protection must also be SET on each call; set once per
        process, a second call would run without it. Measured inside the call, at a function each
        verifier reaches only after its setup."""
        for rel, name, einstieg in (("scripts/pre_tag_audit_gate.py", "_iz_gate2", "_gate_tree_digest"),
                                    ("scripts/verify_pre_tag_receipt.py", "_iz_ver2", "_version_token")):
            mod = _load(name, rel)
            gesehen = []
            echt = getattr(mod, einstieg)

            def spion(*a, _echt=echt, **kw):
                gesehen.append((sys.pycache_prefix, sys.dont_write_bytecode))
                return _echt(*a, **kw)

            setattr(mod, einstieg, spion)
            d = _tree_with_a_forged_library()
            kopf = subprocess.run(["git", "-C", str(d), "rev-parse", "HEAD"], capture_output=True,
                                  text=True, check=True, timeout=30).stdout.strip()
            for _ in range(2):
                if rel.endswith("pre_tag_audit_gate.py"):
                    mod.evaluate(d, "6.0.0")
                else:
                    mod.measure(d, kopf, "6.0.0")
            with self.subTest(verifier=rel):
                self.assertEqual(len(gesehen), 2, gesehen)
                for praefix, kein_schreiben in gesehen:
                    self.assertIsNotNone(praefix)
                    self.assertEqual(praefix, mod._CACHE_DIR)
                    self.assertTrue(kein_schreiben)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
