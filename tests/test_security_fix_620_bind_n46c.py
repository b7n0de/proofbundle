"""Addendum 46c (`KRAXO-CLOUD-N46C-HERKUNFT-DECKT-DIE-CHECKS-01`, Z309 / 6.2.0).

FINDING (measured at 07e16e7c): the origin token (errors._compute_origin_token for a VerificationResult;
errors._origin_token for the dict paths) covered the verified-state identity (signer, payload digest, Merkle
root / successor key, edges digest) but NOT the result's checks. A genuine, stamped result whose checks were
changed after stamping stayed origin-authentic, so intoto.svr_properties still read each changed check's ok,
and the relation relation_signer verdict stayed bound when an attached supersession was cleared.

CONTRACT N46c: every origin token additionally covers every adopted check (name, ok as an EXACT truth value,
detail) in a fixed, type-marked, length-prefixed, counted encoding. Any post-stamp change — a check changed,
removed or added, an ok flipped (a truthy non-bool included), a detail changed — makes the token no longer
match, and no derived verdict is positive.

PER PATH (measured):
- VerificationResult / svr_properties: the checks are result.checks; svr_properties reads each check's ok for
  PROOFBUNDLE_SIGNATURE_VALID / PROOFBUNDLE_RECEIPT_UNCHANGED. Covered here (stable API: stamp_origin /
  origin_authentic / svr_properties).
- evaluate_policy: adopts no check off the result, only result.origin_authentic(); the token covering the
  checks strengthens that gate. Exercised by the full suite's policy tests; not re-probed per check here.
- relation: the per-edge fields (resolution, verified_under, targetDigest) were already bound by the N48 edges
  digest; the one adopted-positive field left unbound was the top-level supersededByAttached. Covered here via
  the public verify + _abschnitt_urteil re-judge with a relation_signer rule (the token-gated verdict).
- decision: evaluate_decision_policy adopts only crypto_ok (a direct `is True` gate) and the identity fields
  the N48 token already covers, re-deriving every verdict from the statement; it holds no check the token does
  not already cover, so there is nothing to bind and no N46c counter-probe (verified closed, see the report).

Red at 07e16e7c374aa582d156d6002571b21b9c6dbddb, green afterwards. Only fail-closed checked; the inputs are
built here with test keys.
"""
from __future__ import annotations

import base64
import json
import pathlib
import unittest

from proofbundle import anchors, dsse, intoto
from proofbundle.decision import emit_decision_receipt
from proofbundle.emit import generate_signer
from proofbundle.errors import Check
from proofbundle.evalclaim import build_eval_claim, issuer_fingerprint
from proofbundle.relation import CODE_RELATION_SIGNER_UNAUTHORIZED, _abschnitt_urteil
from proofbundle.relation_statement import emit_relation_statement, verify_relation_statement

from _svr_binding import bound_svr_result  # type: ignore

_PROPS = ("PROOFBUNDLE_SIGNATURE_VALID", "PROOFBUNDLE_RECEIPT_UNCHANGED")
EXAMPLES = pathlib.Path(__file__).resolve().parents[1] / "examples"
BASE = json.loads((EXAMPLES / "decision_receipt_deny.json").read_text(encoding="utf-8"))


def _edge(hexd: str, relation: str) -> dict:
    return {"relation": relation,
            "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": hexd}}


class TestSvrOriginCoversTheChecks(unittest.TestCase):
    """A VerificationResult's origin token covers its checks: any post-stamp change to the checks makes
    origin_authentic() False, so svr_properties derives no property (the claim-binding gate returns [])."""

    def setUp(self):
        self.signer = generate_signer()
        claim, _ = build_eval_claim(
            suite="safety-refusal", suite_version="v1", metric="refusal_rate",
            comparator=">=", threshold="0.80", score="0.92", n=500,
            model_id="acme/model-x", dataset_id="acme/dataset-y",
            issuer=issuer_fingerprint(self.signer), timestamp="2026-09-19T12:00:00Z",
            model_salt=b"0" * 16, dataset_salt=b"1" * 16)
        self.basis = dict(claim)

    def _bound(self):
        # A REAL verify_bundle result + decoded claim from one eval receipt (as export_svr_dsse derives them);
        # the result is stamped over its checks (Nachtrag 46c), and svr_properties earns both check properties.
        return bound_svr_result(self.basis, self.signer)

    def test_unchanged_result_is_positive(self):
        # CONTROL: the stamped, unmutated result is authentic and earns both check properties.
        r, claim = self._bound()
        self.assertTrue(r.origin_authentic())
        self.assertEqual(sorted(p for p in intoto.svr_properties(r, claim) if p in _PROPS), sorted(_PROPS))

    def test_a_flipped_ok_breaks_the_origin(self):
        r, claim = self._bound()
        r.checks[0].ok = (r.checks[0].ok is not True)   # an ok flipped after stamping
        self.assertFalse(r.origin_authentic())
        self.assertEqual(intoto.svr_properties(r, claim), [])

    def test_a_truthy_non_bool_ok_breaks_the_origin(self):
        r, claim = self._bound()
        r.checks[0].ok = 1   # a truthy non-bool is a third, distinct marker (not the exact True)
        self.assertFalse(r.origin_authentic())
        self.assertEqual(intoto.svr_properties(r, claim), [])

    def test_a_changed_detail_breaks_the_origin(self):
        r, claim = self._bound()
        r.checks[0].detail = (r.checks[0].detail or "") + " changed"
        self.assertFalse(r.origin_authentic())
        self.assertEqual(intoto.svr_properties(r, claim), [])

    def test_a_removed_check_breaks_the_origin(self):
        r, claim = self._bound()
        r.checks.pop()   # a check removed after stamping
        self.assertFalse(r.origin_authentic())
        self.assertEqual(intoto.svr_properties(r, claim), [])

    def test_an_added_check_breaks_the_origin(self):
        r, claim = self._bound()
        r.checks.append(Check("merkle-inclusion", True))   # a check added after stamping
        self.assertFalse(r.origin_authentic())
        self.assertEqual(intoto.svr_properties(r, claim), [])

    def test_restamping_over_the_changed_checks_binds_again(self):
        # CONTROL (the legitimate re-stamp path): re-stamping over the changed checks binds again, and
        # svr_properties then reads the new checks — a flipped ed25519-signature ok earns no SIGNATURE_VALID.
        r, claim = self._bound()
        for c in r.checks:
            if c.name == "ed25519-signature":
                c.ok = False
        r.stamp_origin()
        self.assertTrue(r.origin_authentic())
        self.assertNotIn("PROOFBUNDLE_SIGNATURE_VALID", intoto.svr_properties(r, claim))


class TestRelationOriginCoversSupersededByAttached(unittest.TestCase):
    """The relation lineage origin token covers supersededByAttached: clearing an attached supersession after
    stamping breaks the token, so the token-gated relation_signer verdict is no longer bound (unauthorized)."""

    def _verified_with_supersession(self):
        sk = generate_signer()
        pub = sk.public_key().public_bytes_raw()
        pub_b64 = base64.b64encode(pub).decode()
        tgt = emit_decision_receipt({**BASE, "decisionId": "d-target"}, sk, strict=True)
        root = anchors.statement_content_root(dsse.load_payload(tgt)).hex()
        env = emit_relation_statement(
            {"schemaVersion": "0.1.0", "statementId": "urn:uuid:n46c-1",
             "relationships": [_edge(root, "retracts")]}, sk)
        stmt_hex = anchors.statement_content_root(dsse.load_payload(env)).hex()
        # An attached, verified neighbour declares a SUPERSESSION over this statement -> supersededByAttached set.
        related = {root: {"verified": True, "relationships": [_edge(stmt_hex, "supersedes")],
                          "verified_under": pub_b64, "subject_digest": None}}
        # A relation_signer PINNED rule on the own `retracts` edge — the token-gated verdict. No reject_superseded,
        # so the supersession is only a warning and relation_signer can be positive while it is present.
        section = {"relation_signer": {"retracts": {"mode": "pinned", "keys": [pub_b64]}}}
        r = verify_relation_statement(env, pub, related=related, policy={"relations": section})
        return r, section, pub_b64

    def test_clearing_supersededByAttached_after_stamping_unbinds_relation_signer(self):
        r, section, pub_b64 = self._verified_with_supersession()
        self.assertIsNotNone(r["lineage"]["supersededByAttached"])   # precondition: a supersession was stamped
        # CONTROL: unmutated, the relation_signer rule is satisfied (bound + pinned), no unauthorized code.
        viol0 = _abschnitt_urteil(section, r["lineage"], successor_key_b64=pub_b64)
        self.assertFalse(any(v.get("code") == CODE_RELATION_SIGNER_UNAUTHORIZED for v in viol0))
        # N46c: clear the attached supersession after stamping, then re-judge the same lineage.
        r["lineage"]["supersededByAttached"] = None
        viol1 = _abschnitt_urteil(section, r["lineage"], successor_key_b64=pub_b64)
        self.assertTrue(any(v.get("code") == CODE_RELATION_SIGNER_UNAUTHORIZED for v in viol1))

    def test_unmutated_lineage_stays_authorized(self):
        # CONTROL: judging the unmutated lineage twice stays authorized (the binding is stable).
        r, section, pub_b64 = self._verified_with_supersession()
        for _ in range(2):
            viol = _abschnitt_urteil(section, r["lineage"], successor_key_b64=pub_b64)
            self.assertFalse(any(v.get("code") == CODE_RELATION_SIGNER_UNAUTHORIZED for v in viol))


if __name__ == "__main__":
    unittest.main()
