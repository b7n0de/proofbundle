"""The human-readable report of `decision verify` and `outcome verify` names the lineage state.

SPEC.md §7j: the verifier reports a relationship as its own `lineage` state rather than leaving
replacement invisible, and a DECLARED_UNRESOLVED edge never reads as a pass. `relation-statement
verify` prints a `LINEAGE:` line; `decision verify` and `outcome verify` printed none, so the text
report of a receipt whose `supersedes` target is held (VERIFIED) and the text report of the same
receipt whose target is not held (DECLARED_UNRESOLVED) were byte-identical, and only `--json` told
them apart. Measured at 65bd4b7a and at 121cd089 with the vectors K1 and K3 of the audit decision
receipts draft: both exit 0, same stdout.

The exit codes do not change: DECLARED_UNRESOLVED stays exit 0 without a policy, and the existing
`relations.require_relation_resolution` rule of the trust policy turns it into exit 3.
"""
from __future__ import annotations

import base64
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from proofbundle import anchors, cli, dsse
from proofbundle.decision import _rfc8785_bytes, emit_decision_receipt
from proofbundle.emit import generate_signer
from proofbundle.outcome import build_outcome_statement

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
H_B = "b" * 64


def _edge(target_hex: str, relation: str = "supersedes") -> dict:
    return {"relation": relation,
            "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": target_hex}}


def _run(argv: list[str]) -> tuple[int, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = cli.main(argv)
    return rc, out.getvalue()


def _lineage_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.startswith("LINEAGE:")]


class TestDecisionVerifyTextNamesLineage(unittest.TestCase):

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.tmp = Path(self._td.name)
        self.pred = json.loads((EXAMPLES / "decision_receipt_deny.json").read_text(encoding="utf-8"))
        self.signer = generate_signer()
        self.pub = base64.b64encode(self.signer.public_key().public_bytes_raw()).decode()
        # The predecessor P and an unrelated receipt U, both by the same signer.
        p_env = emit_decision_receipt(dict(self.pred, decisionId="d-pred"), self.signer, strict=True)
        u_env = emit_decision_receipt(dict(self.pred, decisionId="d-other"), self.signer, strict=True)
        (self.tmp / "p.json").write_text(json.dumps(p_env), encoding="utf-8")
        (self.tmp / "u.json").write_text(json.dumps(u_env), encoding="utf-8")
        p_root = anchors.statement_content_root(dsse.load_payload(p_env)).hex()
        s_env = emit_decision_receipt(dict(self.pred, decisionId="d-succ", relationships=[_edge(p_root)]),
                                      self.signer, strict=True)
        (self.tmp / "s.json").write_text(json.dumps(s_env), encoding="utf-8")
        plain = emit_decision_receipt(dict(self.pred, decisionId="d-plain"), self.signer, strict=True)
        (self.tmp / "plain.json").write_text(json.dumps(plain), encoding="utf-8")

    def tearDown(self):
        self._td.cleanup()

    def _verify(self, receipt: str, *extra: str) -> tuple[int, str]:
        return _run(["decision", "verify", str(self.tmp / receipt), "--pub", self.pub, *extra])

    def test_predecessor_held_reads_verified(self):
        rc, out = self._verify("s.json", "--with-related", str(self.tmp / "p.json"))
        self.assertEqual(rc, 0)
        self.assertEqual(_lineage_lines(out), ["LINEAGE: VERIFIED"])

    def test_predecessor_not_held_reads_declared_unresolved(self):
        # The shape of K3: receipts are held, none of them is the predecessor.
        rc, out = self._verify("s.json", "--with-related", str(self.tmp / "u.json"))
        self.assertEqual(rc, 0)
        self.assertEqual(_lineage_lines(out), ["LINEAGE: DECLARED_UNRESOLVED"])

    def test_nothing_held_reads_declared_unresolved(self):
        rc, out = self._verify("s.json")
        self.assertEqual(rc, 0)
        self.assertEqual(_lineage_lines(out), ["LINEAGE: DECLARED_UNRESOLVED"])

    def test_held_and_not_held_reports_differ(self):
        _, held = self._verify("s.json", "--with-related", str(self.tmp / "p.json"))
        _, not_held = self._verify("s.json", "--with-related", str(self.tmp / "u.json"))
        self.assertNotEqual(held, not_held)

    def test_require_relation_resolution_makes_not_held_exit_3(self):
        # The existing switch: unchanged behaviour, pinned here next to the text line.
        pol = self.tmp / "pol.json"
        pol.write_text(json.dumps({"schema": "proofbundle/trust-policy/v0.2", "policy_id": "t",
                                   "policyPurpose": "decision",
                                   "relations": {"require_relation_resolution": ["supersedes"]}}),
                       encoding="utf-8")
        rc, out = self._verify("s.json", "--with-related", str(self.tmp / "u.json"), "--policy", str(pol))
        self.assertEqual(rc, 3)
        self.assertEqual(_lineage_lines(out), ["LINEAGE: DECLARED_UNRESOLVED"])
        rc, out = self._verify("s.json", "--with-related", str(self.tmp / "p.json"), "--policy", str(pol))
        self.assertEqual(rc, 0)
        self.assertEqual(_lineage_lines(out), ["LINEAGE: VERIFIED"])

    def test_no_edges_nothing_held_prints_no_lineage_line(self):
        rc, out = self._verify("plain.json")
        self.assertEqual(rc, 0)
        self.assertEqual(_lineage_lines(out), [])


class TestOutcomeVerifyTextNamesLineage(unittest.TestCase):

    def test_outcome_declared_unresolved_is_named(self):
        signer = generate_signer()
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            stmt = build_outcome_statement({
                "schemaVersion": "0.1.0", "outcomeId": "o-unresolved",
                "decisionRef": {"sha256": "c" * 64}, "executor": {"id": "ex-1"},
                "requestedActionDigest": {"sha256": "d" * 64},
                "status": "executed", "performedAt": "2026-07-16T00:00:00Z",
                "relationships": [_edge(H_B)],
            })
            env = dsse.sign_envelope(_rfc8785_bytes(stmt), signer,
                                     payload_type="application/vnd.in-toto+json")
            (tmp / "o.json").write_text(json.dumps(env), encoding="utf-8")
            pub = base64.b64encode(signer.public_key().public_bytes_raw()).decode()
            rc, out = _run(["outcome", "verify", str(tmp / "o.json"), "--pub", pub])
        self.assertEqual(rc, 0)
        self.assertEqual(_lineage_lines(out), ["LINEAGE: DECLARED_UNRESOLVED"])


if __name__ == "__main__":
    unittest.main()
