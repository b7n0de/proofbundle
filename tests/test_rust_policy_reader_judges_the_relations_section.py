"""The Rust verifier refuses every `relations` section the Python policy loader refuses.

WHERE THIS COMES FROM. Measured 2026-09-26 on main 1f7a62d2, corpus case
`relation-signer-cross-issuer-unauthorized`, with one field of its policy changed:

| policy change | Python `decision verify --policy` | Rust `verify-relation --policy` |
|---|---|---|
| relation_signer mode "bogus" | exit 2, mode must be one of ['same-key', 'pinned'] | exit 0, reasons [] |
| pinned key = the identity point | exit 2, low-order Ed25519 point | exit 3, RELATION_SIGNER_UNAUTHORIZED |

The first row is a fail-open in the second verifier: same bytes, refuse against accept. The Rust
reader checked the policy's hull (unknown fields, schema, policy_id) and read the section it
evaluates without judging it, although its own comment said both must get Python's verdict.

WHAT IS PINNED. Each way `policy.load_policy` refuses a `relations` section, run through both
verifiers on the same receipt: both exit 2, and the Rust reason carries Python's wording. The
original policy is the positive control: both exit 3 with RELATION_SIGNER_UNAUTHORIZED, so a refusal
below cannot come from a case that fails for any other reason.

WHAT IS NOT PINNED, and why it is named here. A policy malformed OUTSIDE `relations` (for example a
`merkle.trusted_roots` entry that is not base64) is refused by Python and still evaluated by Rust:
measured on the same case, Python exit 2, Rust exit 3. The Rust reader does not evaluate those
sections, and porting all of `load_policy` is its own change. `test_a_section_rust_does_not_read_
is_still_a_named_gap` measures that the gap is still there, so the day it closes this file says so.
"""
from __future__ import annotations

import base64
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CASE = REPO / "conformance" / "relation" / "relation-signer-cross-issuer-unauthorized"
RUST_DIR = REPO / "tools" / "pb_verify_rs"
RUST_BIN = RUST_DIR / "target" / "release" / "pb_verify_rs"
IDENTITY_B64 = base64.b64encode(b"\x01" + b"\x00" * 31).decode("ascii")


def _rust_binary():
    """Same lookup as tests/test_lauf11_l1_l4_rust_strukturbudget_und_kreuzvergleich.py."""
    if RUST_BIN.exists():
        return RUST_BIN
    if not RUST_DIR.is_dir() or shutil.which("cargo") is None:
        return None
    b = subprocess.run(["cargo", "build", "--release"], cwd=RUST_DIR,  # noqa: S603,S607
                       capture_output=True, text=True, timeout=1800)
    return RUST_BIN if b.returncode == 0 and RUST_BIN.exists() else None


def _mutate(change):
    policy = json.loads((CASE / "policy.json").read_text(encoding="utf-8"))
    change(policy)
    return policy


def _set_rule(rule):
    def change(p):
        p["relations"]["relation_signer"]["supersedes"] = rule
    return change


def _set(key, value):
    def change(p):
        p["relations"][key] = value
    return change


# (label, change, fragment both reasons must carry)
REFUSED = [
    ("unknown mode", _set_rule({"mode": "bogus"}), "mode must be one of ['same-key', 'pinned']"),
    ("mode missing", _set_rule({"keys": [IDENTITY_B64]}), "mode must be one of"),
    ("same-key with keys", _set_rule({"mode": "same-key", "keys": []}), "takes no 'keys'"),
    ("pinned without keys", _set_rule({"mode": "pinned"}), "needs a non-empty 'keys' list"),
    ("pinned with an empty list", _set_rule({"mode": "pinned", "keys": []}), "needs a non-empty"),
    ("a key that is not base64", _set_rule({"mode": "pinned", "keys": ["!!"]}), "is not valid base64"),
    ("a short key", _set_rule({"mode": "pinned", "keys": [base64.b64encode(b"\x01" * 16).decode()]}),
     "must decode to 32 bytes, got 16"),
    ("a low-order key", _set_rule({"mode": "pinned", "keys": [IDENTITY_B64]}), "low-order Ed25519 point"),
    ("a non-canonical key",
     _set_rule({"mode": "pinned", "keys": [base64.b64encode(((1 << 255) - 18).to_bytes(32, "little")).decode()]}),
     "non-canonical Ed25519 encoding"),
    ("an extra field in a rule", _set_rule({"mode": "same-key", "extra": 1}), "unknown field(s) in"),
    ("a rule that is no object", _set_rule("pinned"), "must be a JSON object"),
    ("an unknown relation name",
     lambda p: p["relations"]["relation_signer"].update({"replaces": {"mode": "same-key"}}),
     "is not a relation name out of"),
    ("reject_superseded as text", _set("reject_superseded", "false"), "must be a boolean"),
    ("reject_retracted as a number", _set("reject_retracted", 1), "must be a boolean"),
    ("resolution list empty", _set("require_relation_resolution", []), "must be a non-empty list"),
    ("resolution names an unknown relation", _set("require_relation_resolution", ["replaces"]),
     "must be a non-empty list"),
    ("target not hex", _set("require_relation_target", {"supersedes": "xyz"}), "64-char lowercase hex"),
    ("target list empty", _set("require_relation_target", {"supersedes": []}), "must not be an empty list"),
    ("target for an unknown relation", _set("require_relation_target", {"replaces": "a" * 64}),
     "is not a relation name out of"),
]


class RustPolicyReaderJudgesTheRelationsSection(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.rust = _rust_binary()
        if cls.rust is None:
            raise unittest.SkipTest("NOT MEASURABLE: tools/pb_verify_rs is missing or cargo is absent — "
                                    "the parity cases did NOT run (env_blocked, never green)")
        cls.pub = (CASE / "pub.b64").read_text(encoding="utf-8").strip()
        cls.case = json.loads((CASE / "case.json").read_text(encoding="utf-8"))

    def _both(self, policy: dict):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "policy.json"
            path.write_text(json.dumps(policy), encoding="utf-8")
            related = []
            for rel, rpub in zip(self.case["related"], self.case["relatedPubs"]):
                related += ["--with-related", str(CASE / rel), "--related-pub", rpub]
            py = subprocess.run(
                [sys.executable, "-c",
                 "import sys; sys.path.insert(0, %r); from proofbundle.cli import main; "
                 "sys.exit(main(sys.argv[1:]))" % str(REPO / "src"),
                 "decision", "verify", str(CASE / "receipt.json"), "--pub", self.pub, *related,
                 "--policy", str(path)],
                capture_output=True, text=True, timeout=120)
            rs = subprocess.run([str(self.rust), "verify-relation", str(CASE / "receipt.json"), self.pub,
                                 *related, "--policy", str(path)],
                                capture_output=True, text=True, timeout=120)
        return py, rs

    def test_positive_control_the_corpus_policy_is_unmet_in_both(self):
        py, rs = self._both(_mutate(lambda p: None))
        self.assertEqual(py.returncode, 3, py.stdout + py.stderr)
        self.assertEqual(rs.returncode, 3, rs.stdout + rs.stderr)
        self.assertIn("RELATION_SIGNER_UNAUTHORIZED", rs.stdout)

    def test_every_malformed_relations_section_is_refused_by_both_for_the_same_reason(self):
        for label, change, fragment in REFUSED:
            with self.subTest(case=label):
                py, rs = self._both(_mutate(change))
                self.assertEqual(py.returncode, 2, py.stdout + py.stderr)
                self.assertIn(fragment, py.stdout + py.stderr)
                self.assertEqual(rs.returncode, 2, rs.stdout + rs.stderr)
                self.assertIn(fragment, rs.stderr)

    def test_a_section_rust_does_not_read_is_still_a_named_gap(self):
        """Counter-direction, measured rather than assumed: the gap named in the module docstring."""
        py, rs = self._both(_mutate(lambda p: p.update({"merkle": {"trusted_roots": ["not base64!"]}})))
        self.assertEqual(py.returncode, 2, py.stdout + py.stderr)
        self.assertEqual(rs.returncode, 3, "the Rust reader now judges the merkle section; update the "
                                           "docstring and the parity registry: " + rs.stdout + rs.stderr)


if __name__ == "__main__":
    unittest.main()
