"""Every site of the independent cross-check refuses a policy field of the wrong type, at the public verifier.

SOURCE. After the deep gate at 7409b123 confirmed the P1 of tests/test_the_evaluators_judge_a_policy_by_the_loaders_rule.py,
a second session checked the class on main 52231c95, read only and with its own reproducers (2026-09-29): 44 sites
where a public evaluator or verifier reads a list- or dict-valued policy field, 26 of them P1 candidates. At each
of these a wrong type let a check pass whose correctly typed control fails.

This file measures each candidate at the surface a relying party calls, by its VERDICT, not by a message: a
policy without the restriction passes (base), the restriction with the right type fails (control), and every
wrong value delta probed fails as well (a list field: 5, "abc", {}, None, True; an object field: 5, "abc",
["x"], None, True). At 52231c95 every wrong value of every site below passed, except at
``require_relation_target[relation]``, where only None passed and the other values already failed; at the head that
adds this file every one fails. Two sites were still open at 2a2d59b2 and close here: a relations section the policy holds as
JSON null at the outcome and relation statement verifiers, and ``RenewalPolicy.from_dict`` with a
``deprecated_algs`` of another type, a Python set included. The verify lens on that step (bc3d275f) found two more:
an entry of ``deprecated_algs`` that is no text, and a whole policy the loader refuses (a top-level typo such as
``"relationz"``) at the outcome and relation statement verifiers, which judged only its relations section.

Not in this file: ``agent_review`` reads ``blocking`` and ``require_coverage_status`` of null as no rule in its own
loader too, so loader and evaluator agree there; whether null should mean absent is an owner decision (card
OA-94cca14255), not this class.
"""
from __future__ import annotations

import base64
import copy
import json
import pathlib
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle import anchors, dsse
from proofbundle import renewal as rn
from proofbundle.bundle import verify_bundle
from proofbundle.decision import emit_decision_receipt, verify_decision_receipt
from proofbundle.evalclaim import ASSURANCE_LEVELS, build_eval_claim, emit_eval_receipt, issuer_fingerprint
from proofbundle.outcome import emit_outcome_receipt, verify_outcome_receipt
from proofbundle.policy import evaluate_policy
from proofbundle.relation_statement import emit_relation_statement, verify_relation_statement

_WURZEL = pathlib.Path(__file__).resolve().parents[1]

# Literal seeds: tests/test_sdist_ohne_signierwerkzeug.py allows `from_private_bytes` in a shipped test only over
# a seed written out in the source.
_A = Ed25519PrivateKey.from_private_bytes(b"\x51" * 32)   # signs every receipt here
_F = Ed25519PrivateKey.from_private_bytes(b"\x52" * 32)   # a key no receipt here is signed by

_LISTE = (("5", 5), ('"abc"', "abc"), ("{}", {}), ("None", None), ("True", True))
_OBJEKT = (("5", 5), ('"abc"', "abc"), ('["x"]', ["x"]), ("None", None), ("True", True))


def _roh(k) -> bytes:
    return k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _b64(k) -> str:
    return base64.b64encode(_roh(k)).decode("ascii")


def _kante(hexd: str, relation: str = "supersedes") -> dict:
    return {"relation": relation, "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": hexd}}


def _wurzel(umschlag) -> str:
    return anchors.statement_content_root(dsse.load_payload(umschlag)).hex()


_DECISION = json.loads((_WURZEL / "examples" / "decision_receipt_deny.json").read_text(encoding="utf-8"))
_OUTCOME = {"schemaVersion": "0.1.0", "outcomeId": "o-cross-check", "decisionRef": {"sha256": "d" * 64},
            "executor": {"id": "ex"}, "requestedActionDigest": {"sha256": "e" * 64}, "status": "executed",
            "performedAt": "2026-09-28T00:00:00Z"}


class _Stellen(unittest.TestCase):
    """One site: the base passes, the control fails, and every wrong value fails."""

    def _stelle(self, name: str, pruefe, base, control, falsch, werte) -> None:
        with self.subTest(site=name, case="base"):
            self.assertIs(pruefe(copy.deepcopy(base)), True, "the base must pass, or the site measures nothing")
        with self.subTest(site=name, case="control"):
            self.assertIsNot(pruefe(copy.deepcopy(control)), True, "the control must fail")
        for label, wert in werte:
            with self.subTest(site=name, wrong=label):
                self.assertIsNot(pruefe(falsch(copy.deepcopy(wert))), True,
                                 f"{name} = {label} was read as no restriction")


class TheDecisionPolicySection(_Stellen):
    """policy.py:713, 744, 750, 771, 775, 779 at 52231c95, through verify_decision_receipt."""

    def test_every_site(self) -> None:
        umschlag = emit_decision_receipt(copy.deepcopy(_DECISION), _A, strict=True)
        eigen, fremd = [{"public_key_b64": _b64(_A)}], [{"public_key_b64": _b64(_F)}]

        def ok(politik) -> bool:
            return verify_decision_receipt(umschlag, _roh(_A), policy=politik)["ok"]

        self._stelle("decision_receipt", ok, {}, {"decision_receipt": {"trusted_decision_makers": fremd}},
                     lambda w: {"decision_receipt": w}, _OBJEKT)
        self._stelle("decision_receipt.trusted_decision_makers", ok, {"decision_receipt": {}},
                     {"decision_receipt": {"trusted_decision_makers": fremd}},
                     lambda w: {"decision_receipt": {"trusted_decision_makers": w}}, _LISTE)
        for feld, kontrolle in (("accepted_predicate_types", ["https://example.invalid/other"]),
                                ("allowed_decision_types", ["zzz"]), ("allowed_verdicts", ["zzz"]),
                                ("required_evidence_relations", ["zzz"])):
            self._stelle(f"decision_receipt.{feld}", ok, {"decision_receipt": {"trusted_decision_makers": eigen}},
                         {"decision_receipt": {"trusted_decision_makers": eigen, feld: kontrolle}},
                         lambda w, feld=feld: {"decision_receipt": {"trusted_decision_makers": eigen, feld: w}},
                         _LISTE)


class TheRelationsSectionAtAllThreeVerifiers(_Stellen):
    """relation.py:880, 913, 922, 953, 960 at 52231c95 and the section itself, each at the decision, outcome and
    relation statement verifier (decision.py:973, outcome.py:1037, relation_statement.py:370)."""

    def test_the_section(self) -> None:
        d = emit_decision_receipt({**_DECISION, "decisionId": "d-cross-section"}, _A, strict=True)
        o = emit_outcome_receipt(copy.deepcopy(_OUTCOME), _A, strict=True)
        ziel = emit_decision_receipt({**_DECISION, "decisionId": "d-cross-target"}, _A, strict=True)
        s = emit_relation_statement({"schemaVersion": "0.1.0", "statementId": "urn:uuid:cross-section",
                                     "relationships": [_kante(_wurzel(ziel), "retracts")]}, _A)

        def rueckzug(umschlag) -> dict:
            return {"b" * 64: {"verified": True, "relationships": [_kante(_wurzel(umschlag), "retracts")]}}

        angehaengt = {_wurzel(ziel): {"verified": True, "relationships": None, "verified_under": _b64(_A),
                                      "subject_digest": None}}
        for name, pruefe, regel in (
                ("decision", lambda p: verify_decision_receipt(d, _roh(_A), related=rueckzug(d), policy=p)["ok"],
                 {"reject_superseded": True}),
                ("outcome", lambda p: verify_outcome_receipt(o, _roh(_A), related=rueckzug(o), policy=p)["ok"],
                 {"reject_superseded": True}),
                ("relation statement",
                 lambda p: verify_relation_statement(s, _roh(_A), related=angehaengt, policy=p)["ok"],
                 {"reject_retracted": True})):
            self._stelle(f"relations @ {name}", pruefe, {"relations": {}}, {"relations": regel},
                         lambda w: {"relations": w}, _OBJEKT)
            with self.subTest(site=f"relations @ {name}", case="absent"):
                self.assertIs(pruefe({}), True, "a policy without a relations key is no relations rule")
            # The verify lens on bc3d275f: a typo in the top-level key read as no relations section at the outcome
            # and relation statement verifiers, which judge only that section; the loader refuses the policy, and
            # so does every verifier, as does a whole policy with any other field the loader refuses.
            for label, politik in (("a typo in the key", {"relationz": regel}),
                                   ("a wrong field beside a readable section",
                                    {"relations": {}, "allowed_issuers": 5}),
                                   ("an unknown top-level key beside no rule", {"relations": {}, "x": 1})):
                with self.subTest(site=f"whole policy @ {name}", case=label):
                    self.assertIsNot(pruefe(politik), True, f"{label} was read as a policy the loader accepts")

    def test_every_rule_of_the_section(self) -> None:
        ziel = "c" * 64
        d = emit_decision_receipt({**_DECISION, "decisionId": "d-cross-edge", "relationships": [_kante(ziel)]}, _A,
                                  strict=True)
        o = emit_outcome_receipt({**_OUTCOME, "outcomeId": "o-cross-edge", "relationships": [_kante(ziel)]}, _A,
                                 strict=True)
        s = emit_relation_statement({"schemaVersion": "0.1.0", "statementId": "urn:uuid:cross-edge",
                                     "relationships": [_kante(ziel)]}, _A)
        fremd = {"mode": "pinned", "keys": [_b64(_F)]}
        for name, pruefe in (("decision", lambda p: verify_decision_receipt(d, _roh(_A), policy=p)["ok"]),
                             ("outcome", lambda p: verify_outcome_receipt(o, _roh(_A), policy=p)["ok"]),
                             ("relation statement", lambda p: verify_relation_statement(s, _roh(_A), policy=p)["ok"])):
            leer = {"relations": {}}
            self._stelle(f"require_relation_resolution @ {name}", pruefe, leer,
                         {"relations": {"require_relation_resolution": ["supersedes"]}},
                         lambda w: {"relations": {"require_relation_resolution": w}}, _LISTE)
            self._stelle(f"relation_signer @ {name}", pruefe, leer,
                         {"relations": {"relation_signer": {"supersedes": fremd}}},
                         lambda w: {"relations": {"relation_signer": w}}, _OBJEKT)
            self._stelle(f"relation_signer[supersedes] @ {name}", pruefe, leer,
                         {"relations": {"relation_signer": {"supersedes": fremd}}},
                         lambda w: {"relations": {"relation_signer": {"supersedes": w}}}, _OBJEKT)
            self._stelle(f"require_relation_target @ {name}", pruefe, leer,
                         {"relations": {"require_relation_target": {"supersedes": "f" * 64}}},
                         lambda w: {"relations": {"require_relation_target": w}}, _OBJEKT)
            self._stelle(f"require_relation_target[supersedes] @ {name}", pruefe, leer,
                         {"relations": {"require_relation_target": {"supersedes": "f" * 64}}},
                         lambda w: {"relations": {"require_relation_target": {"supersedes": w}}},
                         _LISTE + (('["x"]', ["x"]),))


class TheBundleTrustPolicy(_Stellen):
    """policy.py:970, 978 (twice), 986, 1004, 1024, 1077, 1111, 1188, 1189, 1200 at 52231c95, through
    evaluate_policy over a verified eval receipt."""

    def test_every_site(self) -> None:
        claim, _ = build_eval_claim(
            suite="s", suite_version="1.0.0", metric="m", comparator=">=", threshold="0.5", score="0.9", n=10,
            model_id="a/m", dataset_id="a/d", issuer=issuer_fingerprint(_A), timestamp="2026-07-05T12:00:00Z",
            model_salt=bytes(16), dataset_salt=bytes(16))
        buendel = emit_eval_receipt(claim, _A)
        echt = verify_bundle(buendel)
        self.assertIs(echt.ok, True)

        def ok(politik) -> bool:
            return evaluate_policy(buendel, echt, politik)["policy_ok"]

        null_wurzel = base64.b64encode(bytes(32)).decode("ascii")
        for feld, art, kontrolle, falsch in (
                ("allowed_schema_versions", _LISTE, {"allowed_schema_versions": ["x"]},
                 lambda w: {"allowed_schema_versions": w}),
                ("signature", _OBJEKT, {"signature": {"allowed_algs": ["rsa"]}}, lambda w: {"signature": w}),
                ("signature.allowed_algs", _LISTE, {"signature": {"allowed_algs": ["rsa"]}},
                 lambda w: {"signature": {"allowed_algs": w}}),
                ("allowed_issuers", _LISTE, {"allowed_issuers": [{"public_key_b64": _b64(_F)}]},
                 lambda w: {"allowed_issuers": w}),
                ("merkle", _OBJEKT, {"merkle": {"require_authenticated_root": True}}, lambda w: {"merkle": w}),
                ("merkle.trusted_checkpoints", _LISTE, {"merkle": {"trusted_checkpoints": [{}]}},
                 lambda w: {"merkle": {"trusted_checkpoints": w}}),
                ("merkle.trusted_roots", _LISTE, {"merkle": {"trusted_roots": [null_wurzel]}},
                 lambda w: {"merkle": {"trusted_roots": w}}),
                ("sd_jwt", _OBJEKT, {"sd_jwt": {"require_nonce": True}}, lambda w: {"sd_jwt": w}),
                ("status", _OBJEKT, {"status": {"reject_self_issued": True}}, lambda w: {"status": w}),
                ("status.allowed_status_authorities", _LISTE, {"status": {"allowed_status_authorities": ["x"]}},
                 lambda w: {"status": {"allowed_status_authorities": w}}),
                ("assurance", _OBJEKT, {"assurance": {"minimum_level": ASSURANCE_LEVELS[-1]}},
                 lambda w: {"assurance": w})):
            self._stelle(feld, ok, {}, kontrolle, falsch, art)


class TheRenewalPolicyLoader(_Stellen):
    """renewal.py:1325 at 52231c95: RenewalPolicy.from_dict is the only loader of this policy, and no CLI path takes
    it, so nothing else stops a deprecated_algs of another type."""

    def test_deprecated_algs(self) -> None:
        folge = rn.build_initial_sequence(["ab" * 32], hash_alg="sha256", time=1000)

        def ok(obj) -> bool:
            try:
                politik = rn.RenewalPolicy.from_dict(obj)
            except rn.RenewalError:
                return False
            return all(c.ok for c in rn.evaluate_renewal_policy(folge, policy=politik, now=1001).checks)

        self._stelle("deprecated_algs", ok, {"strictness": "fail"}, {"strictness": "fail", "deprecated_algs": ["sha256"]},
                     lambda w: {"strictness": "fail", "deprecated_algs": w}, _LISTE)
        for label, behaelter in (("tuple", ("sha256",)), ("set", {"sha256"}), ("frozenset", frozenset({"sha256"}))):
            with self.subTest(container=label):
                self.assertIs(ok({"strictness": "fail", "deprecated_algs": behaelter}), False,
                              f"a {label} of deprecated algorithms was read as none")
        for wert in (5, "sha256", {"sha256": 1}, None, True):
            with self.subTest(refused=repr(wert)):
                with self.assertRaises(rn.RenewalError) as ctx:
                    rn.RenewalPolicy.from_dict({"deprecated_algs": wert})
                self.assertIn("deprecated_algs must be a list of hash algorithm names", str(ctx.exception))
        # An entry that is no text was dropped, so it deprecated nothing (the verify lens on bc3d275f); it is refused
        # by the loader and by the evaluator for a policy built directly.
        for label, eintrag in (("nested list", ["sha256"]), ("bytes", b"sha256"), ("int", 5), ("object", {})):
            with self.subTest(entry=label):
                self.assertIs(ok({"strictness": "fail", "deprecated_algs": [eintrag]}), False)
                with self.assertRaises(rn.RenewalError):
                    rn.RenewalPolicy.from_dict({"deprecated_algs": ["sha1", eintrag]})
                r = rn.evaluate_renewal_policy(folge, policy=rn.RenewalPolicy(deprecated_algs=[eintrag]), now=1001)
                self.assertEqual([(c.name, c.ok) for c in r.checks], [("renewal:policy_malformed", False)])
        # control: an absent key is no deprecated algorithm, and the shipped example loads as before
        self.assertEqual(rn.RenewalPolicy.from_dict({}).deprecated_algs, frozenset())
        beispiel = json.loads((_WURZEL / "docs" / "adr" / "renewal_policy.example.json").read_text(encoding="utf-8"))
        self.assertEqual(rn.RenewalPolicy.from_dict(beispiel).deprecated_algs, frozenset({"sha1", "md5"}))


if __name__ == "__main__":
    unittest.main()
