"""Addendum 46g (`KRAXO-CLOUD-N46G-TOKEN-NICHT-IN-DER-AUSGABE-01`, Z309 / 6.2.0).

The per-process origin token (``errors._origin_token`` / ``_compute_origin_token``) is placed by
``decision.py`` and ``relation._stamp_lineage_origin`` as a plain ``verified_origin`` key in the returned
result / ``lineage`` dict, so that a downstream check IN THE SAME PROCESS can recompute and compare it.
``errors.py`` docstrings promised it was "process-internal, never serialised", but the CLI emitted the
``lineage`` sub-dict verbatim in the ``--json`` report of ``decision verify``, ``outcome verify`` and
``relation-statement verify`` — so the token travelled in CLI output and survived a JSON round-trip.

46g strips ``verified_origin`` from ALL CLI output (also nested in ``lineage``) via the shared
``cli._without_origin_token``, applied at every verify report site. It is OUTPUT-ONLY: the live result dict
is untouched, so no verdict changes (an in-process recompute still works). The docstrings now say exactly
what holds: the KEY is never serialised; the token sits in the result; an unchanged copy stays authentic in
THIS process; outside the process it is meaningless.

RED at the 46f head 1590ca9aaff7fbca28ea61d321ca0423fb3dbbeb (the token appeared in the --json output);
GREEN at the 46g head (it does not, the other fields unchanged).
"""
from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import tempfile
import unittest

from proofbundle import generate_signer
from proofbundle.cli import main
from proofbundle.relation_statement import emit_relation_statement

_RELATIONS_POLICY = {"schema": "proofbundle/trust-policy/v0.2", "policy_id": "n46g",
                     "relations": {"reject_superseded": True}}


def _raw_pub(signer) -> bytes:
    return signer.public_key().public_bytes_raw()


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = main(argv)
    return rc, out.getvalue(), err.getvalue()


def _signed_statement_and_pub():
    signer = generate_signer()
    predicate = {"schemaVersion": "0.1.0", "statementId": "urn:uuid:n46g-1",
                 "relationships": [{"relation": "retracts",
                                    "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1",
                                                            "digest": "a" * 64}}]}
    env = emit_relation_statement(predicate, signer)
    return env, base64.b64encode(_raw_pub(signer)).decode("ascii")


class RelationStatementVerifyJsonHasNoOriginToken(unittest.TestCase):
    """VERTRAG 2/3: `relation-statement verify --json` under a relations policy (which stamps the lineage)
    must not emit verified_origin, nested in lineage included. RED at 1590ca9a (present), GREEN at head."""

    def _verify_json(self):
        env, pub = _signed_statement_and_pub()
        with tempfile.TemporaryDirectory() as d:
            sp = os.path.join(d, "stmt.json")
            pp = os.path.join(d, "policy.json")
            with open(sp, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(env))
            with open(pp, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(_RELATIONS_POLICY))
            rc, out, err = _run(["relation-statement", "verify", sp, "--pub", pub, "--json", "--policy", pp])
        return rc, out, err

    def test_no_verified_origin_in_output(self):
        rc, out, err = self._verify_json()
        self.assertEqual(rc, 0, f"the statement verifies (exit 0); got {rc}\n{out}\n{err}")
        self.assertNotIn("verified_origin", out,
                         "the per-process origin token must not appear in CLI --json output (46g)")
        report = json.loads(out)
        self.assertIsInstance(report.get("lineage"), dict, "this case stamps a lineage")
        self.assertNotIn("verified_origin", report["lineage"],
                         "verified_origin must not survive nested in the lineage sub-dict")

    def test_the_other_report_fields_are_unchanged(self):
        # Control: stripping the token leaves every other field intact — the lineage still carries its
        # edges and verdict, and the top-level crypto/structure verdict is unchanged.
        rc, out, err = self._verify_json()
        report = json.loads(out)
        self.assertIs(report["crypto_ok"], True)
        self.assertIs(report["structure_ok"], True)
        self.assertIn("edges", report["lineage"])
        self.assertIn("lineage", report["lineage"])          # the lineage verdict key is still present
        self.assertIn("verified_successor_key_b64", report["lineage"])  # the public key stays (not the token)


class TheSharedStripHelper(unittest.TestCase):
    """VERTRAG 2: `cli._without_origin_token` is the single mechanism every verify report site uses
    (decision verify, outcome verify, relation-statement verify). It removes verified_origin at the top
    level AND at any nesting, and leaves everything else byte-identical."""

    def test_strips_top_level_and_nested_and_preserves_the_rest(self):
        from proofbundle.cli import _without_origin_token
        report = {
            "ok": True, "crypto_ok": True, "verified_origin": "TOP",
            "lineage": {"lineage": "VERIFIED", "edges": [{"relation": "retracts"}],
                        "verified_origin": "NESTED", "verified_successor_key_b64": "k"},
            "warnings": [], "errors": [],
        }
        stripped = _without_origin_token(report)
        self.assertNotIn("verified_origin", stripped)
        self.assertNotIn("verified_origin", stripped["lineage"])
        # everything else identical (including the public successor key, which is not the token)
        self.assertEqual(stripped["lineage"]["verified_successor_key_b64"], "k")
        self.assertEqual(stripped["lineage"]["edges"], [{"relation": "retracts"}])
        self.assertEqual({k: report[k] for k in ("ok", "crypto_ok", "warnings", "errors")},
                         {k: stripped[k] for k in ("ok", "crypto_ok", "warnings", "errors")})

    def test_the_input_is_not_mutated(self):
        from proofbundle.cli import _without_origin_token
        report = {"verified_origin": "TOP", "lineage": {"verified_origin": "N"}}
        _without_origin_token(report)
        self.assertIn("verified_origin", report, "the helper returns a copy; the live dict is untouched")
        self.assertIn("verified_origin", report["lineage"])


class TheLiveResultStillCarriesTheTokenInProcess(unittest.TestCase):
    """VERTRAG 1/5: the narrowing is OUTPUT-ONLY. The library result dict still carries verified_origin so
    an in-process judge (evaluate_decision_policy) keeps working; no verdict changes. This documents the
    accepted, precisely-stated behaviour (an unchanged copy stays authentic in the same process)."""

    def test_verify_decision_receipt_result_keeps_verified_origin(self):
        from proofbundle.decision import emit_decision_receipt, verify_decision_receipt
        from pathlib import Path
        predicate = json.loads(
            (Path(__file__).resolve().parent.parent / "examples" / "decision_receipt_deny.json")
            .read_text(encoding="utf-8"))
        signer = generate_signer()
        env = emit_decision_receipt(predicate, signer, strict=True)
        result = verify_decision_receipt(env, _raw_pub(signer), strict=True)
        self.assertIs(result["crypto_ok"], True)
        self.assertIsInstance(result.get("verified_origin"), str,
                              "the live in-process result still carries the token (output-only narrowing)")


if __name__ == "__main__":
    unittest.main()
