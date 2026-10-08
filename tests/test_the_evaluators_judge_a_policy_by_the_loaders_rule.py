"""A policy the loader refuses is refused by every evaluator, with the loader's message.

The deep gate of the 6.2.0 release preparation at 7409b123 confirmed a P1 (three of three blind jurors): a
decision policy whose ``decision_receipt.trusted_decision_makers`` is not a list made
``verify_decision_receipt`` report ``ok`` and ``policy_ok`` True for a receipt signed by a key the policy does not
trust. ``evaluate_decision_policy`` read the value with ``_as_list``, a value of another type became ``[]``, and an
empty list pins nobody. ``load_policy`` refuses that policy, so the CLI exits 2 on it; the library path did not.

That is the third instance of one class. The evaluators take a policy dict that may never have passed
``load_policy`` (``evaluate_policy``, ``evaluate_decision_policy``, ``relation.evaluate_relations_policy``), and each
applied only part of the loader's rule: the hull (round 14, lens L4, F1: an unknown key) and the boolean fields (pull
request 291). "Required fields and types stay load_policy's business" left every other field to be read as empty
when it had another type, and empty means no constraint: an ``allowed_issuers`` that is an object, an
``allowed_algs`` that is a string, a ``trusted_roots`` that is a string, a ``signature`` section that is a list, a
``require_relation_resolution`` that is a string, a ``relation_signer`` that is a list, each gave ``policy_ok`` True
with no check at all, and ``load_policy`` refuses each.

The fix is one rule: the loader's field rule (everything it checks on a field that is present) is one function, and
``load_policy`` and the three evaluators call it. The evaluators keep accepting a partial policy without ``schema`` or
``policy_id``; what they no longer accept is a present field the loader would refuse.

The cases below ask ``load_policy`` itself which values it refuses, for every key of every section it knows and for
every section as a whole, so a field added to the loader is covered here without a list to keep in step.
"""
from __future__ import annotations

import base64
import copy
import json
import unittest
from pathlib import Path

from proofbundle import dsse, relation
from proofbundle import policy as policy_module
from proofbundle.bundle import verify_bundle
from proofbundle.decision import emit_decision_receipt, verify_decision_receipt
from proofbundle.emit import generate_signer
from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt, issuer_fingerprint
from proofbundle.policy import (
    PolicyError,
    evaluate_decision_policy,
    evaluate_policy,
    lint_policy,
    load_policy,
    policy_warnings,
)

# Nachtrag 48/48b: a decision result stand-in bound to its statement + signer (evaluate_decision_policy now
# refuses an unbound result); used only where a positive policy verdict is expected in isolation.
from _decision_result_binding import bound_decision_result  # type: ignore  # noqa: E402

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
_V02 = "proofbundle/trust-policy/v0.2"

#: The values each field is probed with. Each is a JSON value, so a refusal is the loader's field rule and never
#: its "not a JSON object" copy rule.
_PROBES = (("int 5", 5), ("str 'x'", "x"), ("object {}", {}), ("object {'a': 1}", {"a": 1}), ("list []", []),
           ("list [5]", [5]), ("list [{}]", [{}]), ("null", None), ("true", True), ("false", False))

#: The sections the loader knows, with their closed key sets, read from the module.
_SECTIONS = (("signature", policy_module._SIG_KEYS), ("merkle", policy_module._MERKLE_KEYS),
             ("sd_jwt", policy_module._SDJWT_KEYS), ("status", policy_module._STATUS_KEYS),
             ("assurance", policy_module._ASSURANCE_KEYS), ("anchors", policy_module._ANCHORS_KEYS),
             ("relations", policy_module._RELATIONS_KEYS), ("decision_receipt", policy_module._DECISION_KEYS))
_SECTION_NAMES = {name for name, _keys in _SECTIONS}


def _eval_bundle():
    sk = generate_signer()
    claim, _ = build_eval_claim(
        suite="s", suite_version="1.0.0", metric="m", comparator=">=", threshold="0.5", score="0.9", n=10,
        model_id="a/m", dataset_id="a/d", issuer=issuer_fingerprint(sk), timestamp="2026-07-05T12:00:00Z",
        model_salt=bytes(16), dataset_salt=bytes(16))
    return emit_eval_receipt(claim, sk)


def _set(pol: dict, section, key, value) -> dict:
    if section is None:
        pol[key] = value
    elif key is None:
        pol[section] = value
    else:
        sect = pol.get(section)
        pol[section] = {**(sect if isinstance(sect, dict) else {}), key: value}
    return pol


def _loader_refusals():
    """Every (section, key, probe, message) the loader refuses, found by asking it.

    ``key`` None is the section itself set to the probe. The top level is probed on every key but ``schema`` and
    ``policy_id``, which the evaluators do not require."""
    places = [(None, k) for k in sorted(policy_module._TOP_KEYS - {"schema", "policy_id"} - _SECTION_NAMES)]
    places += [(s, None) for s, _k in _SECTIONS] + [(None, "allowed_issuers")]
    places += [(s, k) for s, keys in _SECTIONS for k in sorted(keys)]
    found = []
    for section, key in places:
        for label, value in _PROBES:
            pol = _set({"schema": _V02, "policy_id": "probe"}, section, key, copy.deepcopy(value))
            try:
                load_policy(pol)
            except PolicyError as exc:
                found.append((section, key, label, value, str(exc)))
    return found


def _name(section, key) -> str:
    return "trust policy" if section is None and key is None else ".".join(x for x in (section, key) if x)


class TheEvaluatorsJudgeAPolicyByTheLoadersRule(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signer = generate_signer()
        cls.pub = cls.signer.public_key().public_bytes_raw()
        cls.pub_b64 = base64.b64encode(cls.pub).decode("ascii")
        cls.tdm = [{"public_key_b64": cls.pub_b64}]
        deny = json.loads((EXAMPLES / "decision_receipt_deny.json").read_text(encoding="utf-8"))
        cls.env = emit_decision_receipt(copy.deepcopy(deny), cls.signer, strict=True)
        cls.statement = json.loads(dsse.load_payload(cls.env))
        cls.bundle = _eval_bundle()
        cls.real = verify_bundle(cls.bundle)
        cls.refusals = _loader_refusals()
        other = generate_signer().public_key().public_bytes_raw()
        cls.other_b64 = base64.b64encode(other).decode("ascii")

    def test_the_oracle_reaches_every_list_and_object_field_it_has_to(self):
        # The per-field cases below must have something to pass over, or they would pass over nothing.
        seen = {_name(s, k) for s, k, _l, _v, _m in self.refusals}
        for must in ("decision_receipt.trusted_decision_makers", "decision_receipt.allowed_decision_types",
                     "decision_receipt.allowed_verdicts", "decision_receipt.required_evidence_relations",
                     "decision_receipt.accepted_predicate_types", "allowed_issuers", "allowed_schema_versions",
                     "signature.allowed_algs", "merkle.trusted_roots", "merkle.trusted_checkpoints",
                     "status.allowed_status_authorities", "anchors.trusted_tsa_roots",
                     "anchors.bitcoin_block_headers", "relations.require_relation_resolution",
                     "relations.relation_signer", "relations.require_relation_target", "signature", "merkle",
                     "sd_jwt", "status", "assurance", "anchors", "relations", "decision_receipt"):
            self.assertIn(must, seen)

    def test_the_measured_p1_the_signer_pin_holds_for_every_value_of_another_type(self):
        for label, value in (("int 5", 5), ("str 'x'", "x"), ("object {}", {}), ("null", None), ("true", True),
                             ("a key string", self.other_b64),
                             ("one entry without a list", {"id": "o", "public_key_b64": self.other_b64})):
            with self.subTest(trusted_decision_makers=label):
                pol = {"decision_receipt": {"trusted_decision_makers": copy.deepcopy(value)}}
                r = verify_decision_receipt(self.env, self.pub, policy=pol)
                self.assertIs(r["ok"], False, r)
                self.assertIs(r["policy_ok"], False, r)
                self.assertTrue(any("decision_receipt.trusted_decision_makers must be a list" in e
                                    for e in r["errors"]), r["errors"])

    def test_every_loader_refusal_is_a_refusal_of_evaluate_decision_policy(self):
        for section, key, label, value, message in self.refusals:
            base = {"decision_receipt": {"trusted_decision_makers": copy.deepcopy(self.tdm)}}
            pol = _set(base, section, key, copy.deepcopy(value))
            with self.subTest(field=_name(section, key), value=label):
                r = evaluate_decision_policy(self.statement, {}, pol, signer_public_key_b64=self.pub_b64)
                self.assertIs(r["policy_ok"], False, r)
                self.assertTrue(any(message in e for e in r["errors"]), (message, r["errors"]))

    def test_every_loader_refusal_is_a_refusal_of_evaluate_policy(self):
        for section, key, label, value, message in self.refusals:
            pol = _set({}, section, key, copy.deepcopy(value))
            with self.subTest(field=_name(section, key), value=label):
                r = evaluate_policy(self.bundle, self.real, pol)
                self.assertIs(r["policy_ok"], False, r)
                self.assertIn(message, r["reason"])

    def test_every_loader_refusal_in_the_relations_section_is_a_violation_of_evaluate_relations_policy(self):
        lineage = {"edges": [], "supersededByAttached": None}
        cases = [(s, k, lab, v, m) for s, k, lab, v, m in self.refusals if s == "relations" and k is not None]
        self.assertTrue(cases)
        for section, key, label, value, message in cases:
            with self.subTest(field=_name(section, key), value=label):
                out = relation.evaluate_relations_policy({key: copy.deepcopy(value)}, lineage,
                                                         successor_key_b64=self.pub_b64)
                self.assertTrue(any(message in v["message"] for v in out), (message, out))

    def test_every_loader_refusal_is_a_lint_error(self):
        for section, key, label, value, message in self.refusals:
            pol = _set({"schema": _V02, "policy_id": "p"}, section, key, copy.deepcopy(value))
            with self.subTest(field=_name(section, key), value=label):
                res = lint_policy(pol)
                self.assertIs(res["ok"], False, res)
                self.assertIn(message, res["errors"])

    def test_a_signer_list_of_another_type_does_not_silence_the_attributes_to_nobody_warning(self):
        for field, value in (("allowed_issuers", 5), ("allowed_issuers", {"public_key_b64": "x"}),
                             ("decision_receipt", {"trusted_decision_makers": 5}),
                             ("decision_receipt", {"trusted_decision_makers": "x"})):
            with self.subTest(field=field, value=repr(value)):
                warned = policy_warnings({"schema": _V02, "policy_id": "p", field: copy.deepcopy(value)})
                self.assertEqual(len(warned), 1, warned)
                self.assertIn("attributes to nobody", warned[0])

    def test_a_value_too_large_to_render_is_refused_with_a_bounded_message(self):
        big = 10 ** 5000
        for pol in ({"policyPurpose": big}, {"relations": {"relation_signer": {"supersedes": {"mode": big}}}}):
            with self.subTest(policy=sorted(pol)):
                with self.assertRaises(PolicyError):
                    load_policy({"schema": _V02, "policy_id": "p", **copy.deepcopy(pol)})
                r = evaluate_decision_policy(self.statement, {}, {
                    **copy.deepcopy(pol), "decision_receipt": {"trusted_decision_makers": self.tdm}},
                    signer_public_key_b64=self.pub_b64)
                self.assertIs(r["policy_ok"], False, r)
                self.assertTrue(any("bits>" in e for e in r["errors"]), r["errors"])
                r = evaluate_policy(self.bundle, self.real, copy.deepcopy(pol))
                self.assertIs(r["policy_ok"], False, r)
                r = verify_decision_receipt(self.env, self.pub, policy={
                    **copy.deepcopy(pol), "decision_receipt": {"trusted_decision_makers": self.tdm}})
                self.assertIs(r["ok"], False, r)

    def test_control_a_policy_the_loader_accepts_is_judged_as_before(self):
        base = {"schema": _V02, "policy_id": "p"}
        mine = load_policy({**base, "decision_receipt": {"trusted_decision_makers": copy.deepcopy(self.tdm)}})
        r = verify_decision_receipt(self.env, self.pub, policy=mine)
        self.assertIs(r["policy_ok"], True, r)
        self.assertIs(r["ok"], True, r)
        other = load_policy({**base, "decision_receipt": {"trusted_decision_makers": [
            {"public_key_b64": self.other_b64}]}})
        r = verify_decision_receipt(self.env, self.pub, policy=other)
        self.assertIs(r["policy_ok"], False, r)
        self.assertIn("signer key is not in trusted_decision_makers", r["errors"])
        # A partial policy without schema or policy_id stays acceptable to the evaluators.
        r = evaluate_decision_policy(self.statement, bound_decision_result(self.statement, self.pub_b64),
                                     {"decision_receipt": {"trusted_decision_makers": self.tdm}},
                                     signer_public_key_b64=self.pub_b64)
        self.assertIs(r["policy_ok"], True, r)
        self.assertIs(evaluate_policy(self.bundle, self.real, {"signature": {"allowed_algs": ["ed25519"]}})[
            "policy_ok"], True)
        r = evaluate_policy(self.bundle, self.real, {"signature": {"allowed_algs": ["rsa"]}})
        self.assertIs(r["policy_ok"], False, r)
        self.assertEqual(relation.evaluate_relations_policy(
            {"require_relation_resolution": ["supersedes"]}, {"edges": []}, successor_key_b64=self.pub_b64), [])


if __name__ == "__main__":
    unittest.main()
