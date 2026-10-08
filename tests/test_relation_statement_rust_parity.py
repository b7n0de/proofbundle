"""3.5.0 WP-B: the Python<->Rust relation differential is GREEN and the parity registry honestly
marks the relation surface COVERED (the AST-checked honesty gate, not a hand-maintained claim).

The crosscheck differential needs the cargo-built binary; when it is absent the differential subtest
is skipped (honest DATA_BLOCKED, never a false pass), but the registry-integrity assertion always
runs (it does not need the binary)."""
from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import unittest

try:
    import _pb_verify_rs  # tests/_pb_verify_rs.py, the one way to the binary
except ModuleNotFoundError:  # `python -m unittest tests.<module>` puts the root on sys.path
    from tests import _pb_verify_rs

ROOT = pathlib.Path(__file__).resolve().parents[1]
CROSSCHECK = ROOT / "tools" / "pb_verify_rs" / "crosscheck.py"


class TestRelationDifferential(unittest.TestCase):
    def test_crosscheck_relation_differential_green(self):
        # Decided at run time through tests/_pb_verify_rs.py, no longer at import: a binary built by an
        # earlier test is found, and where CI requires the binary its absence fails this test.
        # The seam's binary is what crosscheck measures: passed as its pin, so the validation and the run are
        # one file (Codex thread 4217981884).
        binary = _pb_verify_rs.binary_or_skip()
        proc = subprocess.run([sys.executable, str(CROSSCHECK)], capture_output=True, text=True,
                              cwd=str(ROOT), timeout=300,
                              env={**os.environ, _pb_verify_rs.PINNED_ENV: str(binary)})
        self.assertEqual(proc.returncode, 0, f"crosscheck failed:\n{proc.stdout}\n{proc.stderr}")
        # The relation vectors were driven differentially and Python==Rust on every one.
        self.assertIn("relation vector(s) differentially", proc.stdout)
        self.assertIn("Python==Rust", proc.stdout)
        self.assertIn(f"BINARY UNDER TEST: {binary} ", proc.stdout)


class TestRegistryHonesty(unittest.TestCase):
    def test_relation_surface_is_covered_and_integrity_ok(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import rust_parity_gate as gate  # noqa: PLC0415
        result = gate.evaluate()
        self.assertTrue(result["registry_integrity_ok"],
                        f"registry integrity problems: untracked={result['untracked']} "
                        f"orphaned={result['orphaned']} stale={result['stale']}")
        by_ref = {i["python_ref"]: i for i in result["items"]}
        self.assertIn("proofbundle.relation.verify_relationship_edges", by_ref)
        self.assertEqual(by_ref["proofbundle.relation.verify_relationship_edges"]["status"], "COVERED")
        # The new standalone verify_* function is auto-discovered and must be tracked (not UNTRACKED).
        self.assertIn("proofbundle.relation_statement.verify_relation_statement", by_ref)
        self.assertIn(by_ref["proofbundle.relation_statement.verify_relation_statement"]["status"],
                      ("COVERED", "PARTIAL"))


if __name__ == "__main__":
    unittest.main()
