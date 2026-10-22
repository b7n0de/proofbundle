"""K7 (Codex defect search on the 6.3.0 candidate 98b168b9, CODEX-630-K7): a binary that is there and answers
`coverage-report` with something that is not evidence does not switch the binary comparison off.

`rust_coverage_report` accepted any parseable JSON, and `evaluate` read `{}` as no report (`if coverage`), so a
present binary printing `{}` gave `binary_available=true`, `registry_integrity_ok=true` and exit 0 under
`--strict` on the real tree and registry (measured at 98b168b9 and f6ea5cc3), while an explicitly empty
subcommand list failed with exit 1. The same function turned a present binary that exits non-zero or prints no
JSON into no binary at all. Absent evidence stays DATA_BLOCKED; present invalid evidence is now a registry
integrity problem. The fake binaries are local scripts after `_fake_binary` in tests/test_rust_parity_gate.py.
"""
from __future__ import annotations

import importlib.util
import io
import json
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
_GATE = REPO / "scripts" / "rust_parity_gate.py"


def _gate():
    spec = importlib.util.spec_from_file_location("_k7_rust_parity_gate", _GATE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _binary(dir_: Path, stdout: str, code: int = 0) -> Path:
    """An executable that answers `coverage-report` with `stdout` and exit `code`."""
    path = dir_ / "fake_pb_verify_rs.py"
    path.write_text(
        f"#!{sys.executable}\n"
        "import sys\n"
        "if len(sys.argv) > 1 and sys.argv[1] == 'coverage-report':\n"
        f"    sys.stdout.write({stdout!r} + '\\n')\n"
        f"    sys.exit({code})\n"
        "sys.exit(2)\n",
        encoding="utf-8",
    )
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return path


class TheGateRefusesInvalidCoverageEvidence(unittest.TestCase):

    def setUp(self):
        if not _GATE.is_file():
            self.skipTest("scripts/rust_parity_gate.py is not in this tree")
        self.rpg = _gate()
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.dir = Path(d.name)
        self.arms = sorted(self.rpg.rust_match_arms())

    def _strict(self, binary: Path) -> tuple[int, dict]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = self.rpg.main(["--strict", "--rust-bin", str(binary), "--json"])
        return rc, json.loads(buf.getvalue())

    def test_CONTROL_the_full_subcommand_list_passes(self):
        rc, out = self._strict(_binary(self.dir, json.dumps({"verify_subcommands": self.arms})))
        self.assertEqual((rc, out["binary_available"], out["registry_integrity_ok"]), (0, True, True), out["stale"])

    def test_CONTROL_an_explicitly_empty_list_fails(self):
        rc, out = self._strict(_binary(self.dir, json.dumps({"verify_subcommands": []})))
        self.assertEqual(rc, 1)
        self.assertGreater(len(out["stale"]), 0)

    def test_CONTROL_a_missing_binary_stays_data_blocked(self):
        rc, out = self._strict(self.dir / "not-built")
        self.assertEqual((rc, out["binary_available"]), (0, False))

    def test_RED_an_empty_object_is_not_evidence(self):
        """T7: the binary prints {} and exits 0."""
        rc, out = self._strict(_binary(self.dir, "{}"))
        self.assertEqual(rc, 1, out)
        self.assertTrue(out["binary_available"])
        self.assertFalse(out["registry_integrity_ok"])
        self.assertGreater(len(out["stale"]), 0)

    def test_RED_a_subcommand_map_in_place_of_a_list_is_not_evidence(self):
        rc, out = self._strict(_binary(self.dir, json.dumps({"verify_subcommands": {a: 1 for a in self.arms}})))
        self.assertEqual(rc, 1, out)
        self.assertFalse(out["registry_integrity_ok"])

    def test_RED_a_present_binary_that_prints_no_json_is_not_absent(self):
        rc, out = self._strict(_binary(self.dir, "coverage: all"))
        self.assertEqual((rc, out["binary_available"], out["registry_integrity_ok"]), (1, True, False), out)

    def test_RED_invalid_evidence_fails_the_registry_even_when_no_claim_names_a_subcommand(self):
        """A registry whose one COVERED claim is backed by a crosscheck reference alone: nothing is stale, and
        the present invalid report is still a registry integrity problem of its own, not a skipped layer."""
        root = self.dir / "tree"
        (root / "src" / "proofbundle").mkdir(parents=True)
        (root / "src" / "proofbundle" / "thing.py").write_text("def verify_widget(x):\n    return True\n",
                                                                encoding="utf-8")
        (root / "main.rs").write_text('fn main() {\n    match "x" {\n        other => {}\n    }\n}\n', encoding="utf-8")
        (root / "crosscheck.py").write_text("# CALL_THING_CHECK\n", encoding="utf-8")
        (root / "registry.json").write_text(json.dumps({"schema": "test.registry.v1", "entries": {
            "proofbundle.thing.verify_widget": {"status": "COVERED", "rust_subcommands": [],
                                                "crosscheck_refs": ["CALL_THING_CHECK"], "notes": ""}}}),
            encoding="utf-8")

        def evaluate(binary: Path) -> dict:
            return self.rpg.evaluate(src_dir=root / "src" / "proofbundle", registry_path=root / "registry.json",
                                     rust_main=root / "main.rs", crosscheck_py=root / "crosscheck.py",
                                     rust_bin=binary)
        control = evaluate(_binary(self.dir, json.dumps({"verify_subcommands": []})))
        self.assertEqual((control["covered"], control["stale"], control["registry_integrity_ok"]), (1, [], True))
        out = evaluate(_binary(self.dir, "{}"))
        self.assertEqual(out["stale"], [])
        self.assertFalse(out["registry_integrity_ok"], out)

    def test_RED_a_present_binary_that_exits_non_zero_is_not_absent(self):
        rc, out = self._strict(_binary(self.dir, json.dumps({"verify_subcommands": self.arms}), code=3))
        self.assertEqual((rc, out["binary_available"], out["registry_integrity_ok"]), (1, True, False), out)


if __name__ == "__main__":
    unittest.main()
