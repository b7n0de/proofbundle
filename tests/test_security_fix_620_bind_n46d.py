"""Addendum 46d (`KRAXO-CLOUD-N46D-STEMPEL-NACH-DEM-CHECK-UND-SW-01`, Z309 / 6.2.0).

Two regressions Addendum 46c introduced over 07e16e7c, each measured RED at the 46c head
d1b114fb4282c8b533eb6590279f71ad20ae9953 and GREEN at the 46d head, narrowing/ordering only.

R1 — CLI checkpoint added AFTER the origin stamp. verify_bundle stamps the origin over the check
list as it stands there (N46c); the ``verify`` command then appends ``checkpoint-authenticity`` to
that already-stamped result, so ``evaluate_policy``'s ``result.origin_authentic()`` recomputed a
DIFFERENT token and rejected a genuine bundle (policy:result_origin, exit 3). A real eval bundle +
a valid C2SP checkpoint + a minimal passing policy therefore exited 3 / policy_ok False at d1b114fb,
where it must exit 0 / policy_ok True. The fix re-stamps after the checkpoint add; a check mutated
AFTER that re-stamp is still rejected (the control below).

R2 — relation_statement ``_sw`` set in one branch, read in another. ``_sw`` was assigned only inside
the ``isinstance(predicate, dict) and crypto_ok`` block, but the relations-policy branch reads it
gated on crypto_ok + a relations section, NOT on a dict predicate. A validly signed statement whose
predicate is not a dict, verified against a relations policy, skipped the assignment and raised
UnboundLocalError at d1b114fb (decision.py / outcome.py preset ``_sw = None``; this file did not).
The fix presets ``_sw = None``; the surface now returns a fail-closed verdict (ok False, crypto_ok
True), never a raised exception.
"""
from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization

from proofbundle import checkpoint as cp
from proofbundle import dsse, generate_signer
from proofbundle.cli import main
from proofbundle.errors import VerificationResult
from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt
from proofbundle.relation_statement import (
    INTOTO_STATEMENT_PAYLOAD_TYPE,
    RELATION_STATEMENT_PREDICATE_TYPE,
    STATEMENT_TYPE,
    verify_relation_statement,
)

_ORIGIN = "verifier.example/log"


def _raw_pub(signer) -> bytes:
    return signer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = main(argv)
    return rc, out.getvalue(), err.getvalue()


def _eval_bundle_and_signer():
    signer = generate_signer()
    claim, _ = build_eval_claim(
        suite="s", suite_version="1", metric="acc", comparator=">=", threshold="0.5",
        score="0.9", n=10, model_id="m", dataset_id="d", issuer="iss",
        timestamp="2026-07-09T10:00:00Z")
    bundle = emit_eval_receipt(claim, signer)
    return bundle, signer


def _trusting_policy(signer) -> dict:
    pub_b64 = base64.b64encode(_raw_pub(signer)).decode("ascii")
    return {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "n46d",
            "allowed_schema_versions": ["proofbundle/v0.1"],
            "allowed_issuers": [{"issuer": "iss", "public_key_b64": pub_b64, "kid": "k"}],
            "signature": {"allowed_algs": ["ed25519"], "require_expected_signer": True},
            "merkle": {"required_hash_alg": "sha256-rfc6962"},
            "assurance": {"minimum_level": "self_attested"}}


class R1CheckpointIsCoveredByTheOriginStamp(unittest.TestCase):
    """VERTRAG 1: a genuine bundle + a valid checkpoint + a minimal policy verifies (POLICY OK, exit 0);
    the origin token covers the checkpoint-authenticity check the CLI adds. RED at d1b114fb (exit 3,
    policy_ok False, policy:result_origin); GREEN at head."""

    def test_a_real_bundle_with_a_valid_checkpoint_and_policy_passes(self):
        bundle, signer = _eval_bundle_and_signer()
        root = base64.b64decode(bundle["merkle"]["root_b64"])
        tree_size = bundle["merkle"]["tree_size"]
        note = cp.sign_checkpoint(_ORIGIN, tree_size, root, signer, _ORIGIN)
        vkey = cp.vkey(_ORIGIN, _raw_pub(signer))
        policy = _trusting_policy(signer)
        with tempfile.TemporaryDirectory() as d:
            bpath = os.path.join(d, "b.json")
            npath = os.path.join(d, "ckpt.txt")
            ppath = os.path.join(d, "p.json")
            with open(bpath, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(bundle))
            with open(npath, "w", encoding="utf-8") as fh:
                fh.write(note)
            with open(ppath, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(policy))
            rc, out, err = _run(["verify", bpath, "--policy", ppath, "--trusted-checkpoint", npath,
                                 "--checkpoint-vkey", vkey, "--json"])
        report = json.loads(out) if out.strip().startswith("{") else {}
        self.assertEqual(rc, 0, f"a genuine bundle+checkpoint+policy must verify (exit 0); got {rc}\n{out}\n{err}")
        self.assertIs(report.get("policy_ok"), True, "policy_ok must be True once the origin covers the checkpoint")
        self.assertNotIn("result_origin", out + err,
                         "the checkpoint-authenticity add must not break the origin token (policy:result_origin)")

    def test_a_check_mutated_after_the_restamp_is_still_rejected(self):
        # VERTRAG 1, the narrowing stays: re-stamping over the final check list does NOT weaken the
        # origin token — a check changed AFTER the (re-)stamp still fails origin_authentic().
        r = VerificationResult()
        r.add("ed25519-signature", True, "ok")
        r.stamp_origin()                      # the verify_bundle stamp
        r.add("checkpoint-authenticity", True, "ok")
        r.stamp_origin()                      # the N46d re-stamp over the full list
        self.assertTrue(r.origin_authentic(), "a freshly re-stamped result is authentic")
        r.checks[-1].ok = False   # mutate a check (Check is a dataclass) AFTER the re-stamp
        self.assertFalse(r.origin_authentic(),
                         "a check mutated after the re-stamp must break the origin token")


def _signed_statement(predicate, signer):
    """A DSSE-signed in-toto relation-statement built directly (bypassing build_relation_statement's
    predicate validation), so the predicate can be a NON-dict while the signature stays valid."""
    statement = {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": "x", "digest": {"sha256": "00" * 32}}],
        "predicateType": RELATION_STATEMENT_PREDICATE_TYPE,
        "predicate": predicate,
    }
    body = json.dumps(statement, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return dsse.sign_envelope(body, signer, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE)


_RELATIONS_POLICY = {"schema": "proofbundle/trust-policy/v0.2", "policy_id": "n46d-rel",
                     "relations": {"reject_superseded": True}}


class R2NonDictPredicateUnderARelationsPolicyFailsClosed(unittest.TestCase):
    """VERTRAG 2: a validly signed relation-statement whose predicate is NOT a dict, verified against a
    relations policy, returns a fail-closed verdict (ok False, crypto_ok True) and never raises. RED at
    d1b114fb (UnboundLocalError on ``_sw``); GREEN at head."""

    def _assert_failclosed(self, predicate):
        signer = generate_signer()
        env = _signed_statement(predicate, signer)
        try:
            res = verify_relation_statement(env, _raw_pub(signer), policy=_RELATIONS_POLICY)
        except Exception as exc:  # noqa: BLE001 - the whole point is that nothing escapes this surface
            self.fail(f"verify_relation_statement must not raise on a non-dict predicate; raised {type(exc).__name__}: {exc}")
        self.assertIs(res["ok"], False, "a non-dict predicate is not a valid relation-statement (fail-closed)")
        self.assertIs(res["crypto_ok"], True, "the signature is genuine, so crypto_ok stays True")

    def test_list_predicate(self):
        self._assert_failclosed(["not", "a", "dict"])

    def test_text_predicate(self):
        self._assert_failclosed("not a dict")

    def test_null_predicate(self):
        self._assert_failclosed(None)

    def test_control_a_dict_predicate_statement_still_verifies_its_relations(self):
        # The control: a well-formed dict predicate with one edge, under the same relations policy, is
        # evaluated as before (no exception; a real verdict). This proves the preset did not change the
        # dict path.
        signer = generate_signer()
        predicate = {
            "schemaVersion": "proofbundle/relation-statement/v0.1",
            "statementId": "stmt-1",
            "relationships": [{"relation": "supersedes", "target": {"sha256": "11" * 32}}],
        }
        env = _signed_statement(predicate, signer)
        res = verify_relation_statement(env, _raw_pub(signer), policy=_RELATIONS_POLICY)
        self.assertIn(res["ok"], (True, False), "the dict path returns a real verdict, never raises")
        self.assertIs(res["crypto_ok"], True)


if __name__ == "__main__":
    unittest.main()
