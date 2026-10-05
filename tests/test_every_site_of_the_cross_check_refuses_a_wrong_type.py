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


class TheSitesTheVerifyLensesFound(unittest.TestCase):
    """The same class beyond the policy dict, found by two verify lenses on bc3d275f with a reproduction each: a
    restriction the caller hands in (a relying-party pin, a trust pack field, an automation requirement, an expected
    id or route) of another type or shape was read as no restriction. Each case has its control beside it."""

    def test_a_tsa_policy_oid_pin_of_another_shape_is_refused(self) -> None:
        try:
            import rfc3161_client as tsp  # noqa: PLC0415
        except ImportError:
            self.skipTest("needs proofbundle[anchors] (rfc3161-client)")
        from proofbundle.anchors_rfc3161 import verify_rfc3161  # noqa: PLC0415
        anker = json.loads((_WURZEL / "tests" / "fixtures" / "anchors" / "freetsa_receipt_anchor.json").read_text())
        wurzel, beweis = base64.b64decode(anker["canonicalRoot"]), base64.b64decode(anker["proof"])
        echt = tsp.decode_timestamp_response(beweis).tst_info.policy.dotted_string
        eingefroren = {k: v for k, v in anker["frozen"].items() if k != "policyOid"}

        def lauf(oids) -> dict:
            return verify_rfc3161(beweis, wurzel, frozen=eingefroren, rp_trust={
                "trusted_tsa_roots": list(anker["frozen"]["rootCertsDerB64"]), "trusted_tsa_policy_oids": oids})

        self.assertIs(lauf([echt])["ok"], True)             # control: the token's own policy
        self.assertIs(lauf([])["ok"], True)                 # control: an empty list is no pin
        self.assertIs(lauf([echt + ".999"])["ok"], False)   # control: another policy fails
        for wert in (0, False, "", {}, None, 5, True, echt, [""], [None], [0], [[]], ["", echt + ".999"]):
            with self.subTest(trusted_tsa_policy_oids=repr(wert)):
                r = lauf(wert)
                self.assertIs(r["ok"], False, "a pin of another shape was read as no pin")
                self.assertEqual(r["status"], "rp_trust_malformed")

    @staticmethod
    def _outcome_umschlag(**extra):
        praedikat = {**_OUTCOME, "outcomeId": "o-lens", "executor": {"id": "executor:x", "keyId": "kid-exec"},
                     "effectDigest": {"sha256": "c" * 64}, **extra}
        return emit_outcome_receipt(praedikat, _A, strict=True), praedikat

    def test_a_revoked_list_of_another_type_revokes_every_key(self) -> None:
        from proofbundle.outcome import executor_trusted_by_role, receiver_trusted_by_role  # noqa: PLC0415
        umschlag, praedikat = self._outcome_umschlag()

        def pack(**revoked) -> dict:
            return {"roles": {"outcomeExecutors": {"keyIds": ["kid-exec"]}, "outcomeReceivers": {"keyIds": ["kid-exec"]}},
                    "keys": {"kid-exec": {"publicKey": _b64(_A)}}, **revoked}

        def vertraut(p) -> tuple:
            # N43: the executor role verdict is positive only under a relying-party anchor; pin the pack
            # (forwarded verdict) so this test still measures the REVOCATION behaviour, not the missing anchor.
            r = verify_outcome_receipt(umschlag, _roh(_A), trust_pack=p, trust_pack_pinned=True)
            return r["executor_role_trusted"], r["ok"], r["automation"]["safeForAutomation"]

        self.assertEqual(vertraut(pack())[:2], (True, True))                 # base: not revoked
        self.assertEqual(vertraut(pack(revoked=[])), vertraut(pack()))       # base: an empty list revokes nobody
        self.assertEqual(vertraut(pack(revoked=["kid-exec"])), (False, False, False))   # control
        for wert in ("kid-exec", {"kid-exec": True}, 5, True, None, [5], [["kid-exec"]]):
            with self.subTest(revoked=repr(wert)):
                self.assertEqual(vertraut(pack(revoked=wert)), (False, False, False))
                self.assertIs(executor_trusted_by_role(praedikat["executor"], pack(revoked=wert), public_key=_roh(_A)),
                              False)
                self.assertIs(receiver_trusted_by_role("kid-exec", pack(revoked=wert)), False)

    def test_a_malformed_pack_key_for_a_receiver_promotes_nothing(self) -> None:
        from proofbundle.assurance import EvidenceLevel  # noqa: PLC0415
        empfaenger = _roh(_F)
        umschlag, _ = self._outcome_umschlag(receiverRefs=[{"relation": "acknowledges", "digest": {"sha256": "d" * 64},
                                                   "receiverKeyId": "kid-recv"}])

        def stufe(eintrag) -> str:
            p = {"roles": {"outcomeReceivers": {"keyIds": ["kid-recv"]}}, "keys": {"kid-recv": eintrag}}
            r = verify_outcome_receipt(umschlag, _roh(_A), trust_pack=p, evidence_resolver=lambda d: True,
                                       receiver_attestation_resolver=lambda d: True)
            return EvidenceLevel(r["evidence_levels"]["receiverRefs"]["level"]).name

        kontrolle = stufe({"publicKey": base64.b64encode(empfaenger).decode()})
        self.assertEqual(kontrolle, "CONTENT_RESOLVED")   # control: a bare True binds no key to the label
        for label, eintrag in (("publicKey 5", {"publicKey": 5}), ("publicKey null", {"publicKey": None}),
                               ("31 bytes", {"publicKey": base64.b64encode(empfaenger[:31]).decode()}),
                               ("no base64", {"publicKey": "*"}), ("a text", "x"), ("a list", [])):
            with self.subTest(entry=label):
                self.assertEqual(stufe(eintrag), kontrolle, "a malformed pack key read as the pack naming no key")
        # A well-formed ML-DSA key for the label names a key too, and it cannot be the 32-byte signer key a
        # resolver can return, so a bare True binds nothing there either (named in the change, the house rule of
        # `pack_key_binds_signer`: an mldsa65 key never binds an Ed25519 DSSE signer).
        self.assertEqual(stufe({"publicKey": base64.b64encode(bytes(1952)).decode(), "alg": "mldsa65"}), kontrolle)

    def test_references_of_another_shape_are_unresolved(self) -> None:
        from proofbundle.automation_verdict import automation_summary  # noqa: PLC0415
        ergebnis = {"crypto_ok": True, "structure_ok": True, "policy_ok": True, "evidence_bound": False}

        def sicher(refs) -> bool:
            return automation_summary(ergebnis, required_checks={"crypto": "crypto_ok", "structure": "structure_ok",
                                                                 "policy": "policy_ok", "references": refs}
                                      )["safeForAutomation"]

        self.assertIs(sicher(["evidence_bound"]), False)   # control
        # A str subclass names the field by its characters (regression lens): it blocks here as the text does,
        # and a resolved reference named by one passes.
        _name = type("_Name", (str,), {})
        self.assertIs(sicher([_name("evidence_bound")]), False)
        self.assertIs(automation_summary({**ergebnis, "evidence_bound": True}, required_checks={
            "crypto": "crypto_ok", "structure": "structure_ok", "policy": "policy_ok",
            "references": [_name("evidence_bound")]})["safeForAutomation"], True)
        self.assertIs(sicher(None), True)                  # control: no references named
        self.assertIs(sicher([]), True)                    # control: an empty list names none
        for wert in ("evidence_bound", {"evidence_bound"}, frozenset({"evidence_bound"}), {"evidence_bound": True},
                     5, True, [b"evidence_bound"], [["evidence_bound"]]):
            with self.subTest(references=repr(wert)):
                self.assertIs(sicher(wert), False)

    def test_a_decision_maker_id_that_is_no_text_shows_no_separation(self) -> None:
        umschlag, _ = self._outcome_umschlag(executor={"id": "12345", "keyId": "kid-exec"})

        def getrennt(dm) -> bool:
            return verify_outcome_receipt(umschlag, _roh(_A), decision_maker_id=dm)["role_separation_ok"]

        self.assertIs(getrennt("other"), True)    # control: another id
        self.assertIs(getrennt("12345"), False)   # control: the same id
        for wert in (12345, True, 1.5, b"12345", ["12345"]):
            with self.subTest(decision_maker_id=repr(wert)):
                self.assertIs(getrennt(wert), False)

    def test_an_empty_anchor_requirement_stays_what_the_loader_accepts(self) -> None:
        """Not a site: `load_policy` accepts `anchors.require_anchor: ""` (a string or null), and the CLI passes it
        on; beside a target it means any type. A regression lens measured that refusing it changed the CLI exit
        code of such a policy from 0 to 3, so it is read as before."""
        self.assertEqual(anchors.verify_anchors(None, target_roots={}, require="x")["status"], "FAIL")   # control
        self.assertEqual(anchors.verify_anchors(None, target_roots={}, require="")["status"], "SKIP")
        r = anchors.verify_anchors(None, target_roots={}, require="", require_target="receipt")
        self.assertEqual((r["status"], r["require_met"]), ("FAIL", False))   # a target is a requirement of any type

    def test_a_planned_route_that_is_no_text_is_not_measurable(self) -> None:
        import hashlib  # noqa: PLC0415
        import warnings  # noqa: PLC0415
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from proofbundle.experimental import attested_inference as ai  # noqa: PLC0415
        anfrage, antwort, nonce = b"req", b"res", "n" * 16
        beleg = {"signed": {"nonce": nonce, "request_hash": hashlib.sha256(anfrage).hexdigest(),
                            "response_hash": hashlib.sha256(antwort).hexdigest()}, "route": "us-east-1"}

        def ausgang(route) -> str:
            return ai.check_on_receipt(beleg, provider="p", nonce=nonce, request_bytes=anfrage, response_bytes=antwort,
                                       planned_route=route)["outcome"]

        self.assertEqual(ausgang("us-east-1"), ai.OUTCOME_ACCEPTED)             # control
        self.assertEqual(ausgang("eu-west-1"), ai.OUTCOME_ATTESTATION_FAILURE)  # control
        # A str subclass or a str Enum is read by its characters, as a text is everywhere else (regression lens).
        import enum  # noqa: PLC0415

        class _Route(str, enum.Enum):
            EINS = "us-east-1"
            ZWEI = "eu-west-1"

        self.assertEqual(ausgang(type("_Text", (str,), {})("us-east-1")), ai.OUTCOME_ACCEPTED)
        self.assertEqual(ausgang(_Route.EINS), ai.OUTCOME_ACCEPTED)
        self.assertEqual(ausgang(_Route.ZWEI), ai.OUTCOME_ATTESTATION_FAILURE)
        for wert in (None, "", 0, False, [], {}, (), 5, True, ["us-east-1"]):
            with self.subTest(planned_route=repr(wert)):
                self.assertEqual(ausgang(wert), ai.OUTCOME_NOT_MEASURABLE)

    def test_the_policy_projections_refuse_what_the_loader_refuses(self) -> None:
        from proofbundle.policy import PolicyError, lint_policy, policy_anchor_trust, policy_expected_aud  # noqa: PLC0415
        self.assertEqual(policy_expected_aud({"sd_jwt": {"expected_aud": "a"}}), "a")   # control
        self.assertEqual(policy_anchor_trust({"anchors": {"trusted_tsa_policy_oids": ["1.2.3"]}}),
                         {"trusted_tsa_policy_oids": ["1.2.3"]})                         # control
        for politik in ({"sd_jwt": 5}, {"anchors": {"trusted_tsa_policy_oids": 0}}, {"anchors": {"bitcoin_block_headers": 5}},
                        {"anchors": "x"}, {"relationz": {}}):
            with self.subTest(policy=repr(politik)):
                with self.assertRaises(PolicyError):
                    policy_expected_aud(copy.deepcopy(politik))
                with self.assertRaises(PolicyError):
                    policy_anchor_trust(copy.deepcopy(politik))
        # A huge freshness bound passes the loader; explaining it raised a raw ValueError (int->str cap).
        r = lint_policy({"schema": "proofbundle/trust-policy/v0.2", "policy_id": "p",
                         "sd_jwt": {"max_iat_age_seconds": 10 ** 5000}})
        self.assertIsInstance(r, dict)


if __name__ == "__main__":
    unittest.main()
