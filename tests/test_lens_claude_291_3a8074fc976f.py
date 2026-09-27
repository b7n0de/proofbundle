"""Lens run (Claude family) on fix/a-resolver-promotes-only-on-exact-true at 3a8074fc (PR 291, round 2).

Every case below was RED at 3a8074fc976ff027cdc5197930d31ef5a631af61 when it was written (python -m
pytest on this file, Python 3.11.15) and is the reproduction of one row of
REVIEW_lens_claude_291_3a8074fc976f.md. No production code changes. Oracle for N1 to N4: the house rule
this branch states for what a caller supplies (a flag counts only as the exact bool, R-B4, CWE-1287);
for N5: the documented return type of a registered anchor verifier (a dict).
"""
from __future__ import annotations

import base64
import collections
import hashlib
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle import agent_review as AR
from proofbundle import anchors, assurance, intoto
from proofbundle import evalclaim as ec
from proofbundle.adapters._provenance import bind_reported_version
from proofbundle.errors import Check, ProofBundleError, VerificationResult

_NICHT_BOOL_FALSCH = (None, 0, "", [])
_NICHT_BOOL_WAHR = ("false", "no", 1, [0])


class N1ApplicableIsABool(unittest.TestCase):
    """PROPERTY (this branch, 67bb104e: what a caller supplies to assurance counts only as an exact
    bool): `applicable` of classify_digest_evidence is read by its truth. None, 0, "" or [] make a
    weak field not applicable, evidence_ladder_summary then ignores it, and the summary of a CLAIMED
    and a CONTENT_RESOLVED field rises to CONTENT_RESOLVED. "false" keeps the field applicable. P1."""

    def test_n1_a_falsy_non_bool_drops_the_weakest_link(self) -> None:
        strong = assurance.classify_digest_evidence({"sha256": "a" * 64}, applicable=True,
                                                    evidence_resolver=lambda _d: True)
        weak = assurance.classify_digest_evidence({"sha256": "not-hex"}, applicable=True)
        self.assertEqual(assurance.evidence_ladder_summary(weak, strong)["level_name"], "CLAIMED")
        for wert in _NICHT_BOOL_FALSCH:
            with self.subTest(applicable=wert):
                try:
                    feld = assurance.classify_digest_evidence({"sha256": "not-hex"}, applicable=wert)
                except ProofBundleError:
                    continue
                self.assertEqual(assurance.evidence_ladder_summary(feld, strong)["level_name"], "CLAIMED")


class N2BoundIsABool(unittest.TestCase):
    """PROPERTY (the same rule at an emitter): `bound` of bind_reported_version is read by its truth,
    so bound="false", "no", 1 or [0] write the version with status `reported`, where False writes
    `not_bound` with its reason. The provenance block is signed into the receipt. P1."""

    def test_n2_bound_false_as_a_string(self) -> None:
        for wert in _NICHT_BOOL_WAHR:
            with self.subTest(bound=wert):
                block: dict = {}
                try:
                    bind_reported_version(block, "harness_version", "0.3.1", reason="r", bound=wert)
                except (ValueError, ProofBundleError):
                    continue
                self.assertNotEqual(block.get("harness_version_status"), "reported")


class N3LegacyIsABool(unittest.TestCase):
    """PROPERTY (the same rule at a rule-set switch): `legacy_v01` is read by its truth
    (`_fassung_fuer_renderer`: `return not legacy_v01`), so "false" or "no" judges a v0.1 predicate
    under the legacy v0.1 rules that False and 0 refuse under the v0.2 rules (the default since
    6.0.0): emit_agent_review emits it, require_valid_agent_review_predicate_any accepts it and
    render_disclosure_block renders it. P1."""

    def test_n3_legacy_false_as_a_string(self) -> None:
        body = "# T\n\nText.\n"
        findings = [{"id": "F1", "severity": "low", "title": "t", "disposition": "dismissed", "reason": "r"}]
        predicate = {
            "schemaVersion": "0.1.0", "reviewId": "r",
            "subjectContext": {"kind": "githubPullRequest", "forge": "github.com", "repositoryId": "R",
                               "pullRequestNodeId": "PR", "headSha": "a" * 40, "baseSha": "b" * 40,
                               "reviewedDiffDigest": "c" * 64, "bodyCoreDigest": AR.body_core_digest(body)},
            "declaration": {"authoring": [{"assurance": "selfDeclared", "assertedBy": "x"}], "reviewRuns": [],
                            "findings": findings, "findingsTotal": 1,
                            "findingsRoot": AR.findings_root(findings), "nonClaims": ["n"]},
            "coverage": {"status": "UNKNOWN"}, "times": {"declaredAt": "2026-08-31T17:00:00Z"},
            "limitations": ["l"],
        }
        sk = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        stellen = (
            ("emit_agent_review", lambda v: AR.emit_agent_review(predicate, sk, legacy_v01=v)),
            ("require_valid_agent_review_predicate_any",
             lambda v: AR.require_valid_agent_review_predicate_any(predicate, legacy_v01=v)),
            ("render_disclosure_block", lambda v: AR.render_disclosure_block(predicate, legacy_v01=v)),
        )
        for name, ruf in stellen:
            with self.assertRaises(ProofBundleError):
                ruf(False)
            for wert in ("false", "no"):
                with self.subTest(site=name, legacy_v01=wert):
                    with self.assertRaises(ProofBundleError):
                        ruf(wert)


class N4TheSignedSvrReadsNoTruth(unittest.TestCase):
    """PROPERTY (this branch's round 2, "the verdicts a caller builds"): a caller-built check and a
    caller-attested flag earn a signed SVR property only as the exact True. At this head
    svr_properties reads `ok` and `anchor_verified` by their truth: Check("ed25519-signature",
    "false") earns PROOFBUNDLE_SIGNATURE_VALID and anchor_verified="false" earns
    PROOFBUNDLE_ANCHOR_VALID. Not touched here; closed on the D4 branch at fa555f13 (rounds 9 and 10).
    P0 while this branch is on main without D4."""

    def setUp(self) -> None:
        self.claim, _ = ec.build_eval_claim(
            suite="s", suite_version="1", metric="acc", comparator=">=", threshold="0.10", score="0.5",
            n=10, model_id="m", dataset_id="d", issuer="x", timestamp="2026-07-09T10:00:00Z",
            model_salt=b"0" * 16, dataset_salt=b"1" * 16)

    def test_n4_check_ok_false_as_a_string(self) -> None:
        for wert in _NICHT_BOOL_WAHR:
            with self.subTest(ok=wert):
                result = VerificationResult([Check("ed25519-signature", wert), Check("merkle-inclusion", wert)])
                self.assertNotIn("PROOFBUNDLE_SIGNATURE_VALID", intoto.svr_properties(result, self.claim))

    def test_n4_anchor_verified_false_as_a_string(self) -> None:
        result = VerificationResult([Check("ed25519-signature", True)])
        try:
            props = intoto.svr_properties(result, self.claim, anchor_verified="false")
        except ProofBundleError:
            return
        self.assertNotIn("PROOFBUNDLE_ANCHOR_VALID", props)


class N5ADictResultIsADict(unittest.TestCase):
    """PROPERTY: a registered anchor verifier returns a dict (`register_anchor_type`). At this head a
    `collections.OrderedDict` or `defaultdict` result with ok True and no method of its own is a failed
    anchor whose detail says the verifier "returned no result object"; on main 31816e08 both PASS. The
    branch refuses a dict subclass on purpose (its own `get` could answer anything); this case holds
    the weaker property, that the refusal names what was returned. P2: fail-closed, wrong message."""

    _TYPE = "lens-ordereddict/v1"

    def tearDown(self) -> None:
        anchors._VERIFIERS.pop(self._TYPE, None)

    def test_n5_the_detail_names_the_returned_type(self) -> None:
        wurzel = hashlib.sha256(b"statement").digest()
        anker = {"type": self._TYPE, "target": "statement", "canonicalRoot": base64.b64encode(wurzel).decode(),
                 "proof": base64.b64encode(b"proof").decode()}
        for name, antwort in (("OrderedDict", collections.OrderedDict(ok=True, status="PASS", detail="x")),
                              ("defaultdict", collections.defaultdict(str, ok=True, status="PASS", detail="x"))):
            with self.subTest(result=name):
                anchors.register_anchor_type(self._TYPE, lambda proof, root, *, frozen, now, a=antwort: a)
                r = anchors.verify_anchor(anker, target_roots={"statement": wurzel})
                if r.get("ok") is True:
                    continue
                self.assertNotIn("no result object", str(r.get("detail")))
                self.assertIn(name, str(r.get("detail")))


if __name__ == "__main__":
    unittest.main()
