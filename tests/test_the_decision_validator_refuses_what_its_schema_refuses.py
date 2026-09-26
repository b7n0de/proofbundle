"""The enforced decision validator refuses what the published decision schema refuses — null included.

WHERE THIS COMES FROM. Deep gate Z195 against main 5b53ab3e, two findings of one class:

* L3-Z195-03 (P2, jury 3 of 3): JSON null satisfied the required fields schemaVersion and decidedAt, and in
  strict mode privacy, notChecked and decisionChangeConditions; `decision verify --strict` under a
  signer-pinning policy reported safeForAutomation=true for such a receipt. The required-field loop checks
  presence, and every value check skipped None.
* L3-Z195-05 (P3, 3 of 3): 311 type-confused predicates that schemas/decision-receipt-v0.1.schema.json
  refuses passed `validate_decision_predicate(strict=True)`; tests/test_schema_parity.py pinned 11 points.

Both measured again on main 10f3466b before this change: 311 with the gate's generator (the allow
example, eleven values, strict mode), and the five nulls reaching safeForAutomation=true. The generator
below, over a fully populated predicate in both modes, measures 472 strict and 522 lenient there. The
first version of this text gave only the 311 next to this generator (gate on 3562dc71, lens B,
228bcB-01: two numbers from two generators, and the text did not say which).

WHAT IS PINNED. (1) Every schema path with a declared type is in `decision._NESTED_TYPES` or checked by
its own code (DEDICATED, with the reason), so a field added to the schema without a check turns this file
red. (2) A generator: every leaf of a predicate that fills every optional field, replaced by each of
eleven type-confused values; whatever the schema refuses, the validator refuses, strict or not. (3) Null
at every required field is refused, and end to end a signed receipt with a null schemaVersion is no longer
safe for automation. (4) The walker stays inside its budget on a hostile structure.

NO DIVERGENCE LEFT. The first version named one: a bare string entry in notChecked, refused by the
schema and accepted by the validator, which never read entry types, while the vendored third-party
receipt in conformance/decision/crossimpl/ writes strings. The owner decided it (owner decision,
2026-09-26): the string stays allowed as a deprecated legacy form, the schema now says so, and the
object form {field, reason, impact} is preferred.

NAMED LIMITS. The generator only replaces values; it adds no keys (key closure is
`nested_closure_violations`, pinned elsewhere). The relationships subtree is validated by the relation
module and pinned by the relationships class of tests/test_schema_parity.py. The wider generator of
tests/test_every_validator_refuses_what_its_schema_refuses.py covers what this one does not (a string of
the right type and the wrong shape, an added key at every object, the relationships subtree), over this
schema and four others; lens B of the gate on 3562dc71 (228bcB-03) found that this one tried no string
of the wrong shape. Both read `pattern` through tests/_schema_oracle.py, as ECMA-262. The reverse direction
(the validator refusing what the schema accepts) is deliberate where strict mode asks for more than the
schema, and is measured, not pinned, here.
"""
from __future__ import annotations

import base64
import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path

try:
    import jsonschema
except ImportError:  # pragma: no cover - dev-only dependency
    jsonschema = None
else:
    from _schema_oracle import schema_accepts

from proofbundle import decision
from proofbundle.decision import _NESTED_TYPES, validate_decision_predicate

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schemas" / "decision-receipt-v0.1.schema.json").read_text(encoding="utf-8"))
DENY = json.loads((ROOT / "examples" / "decision_receipt_deny.json").read_text(encoding="utf-8"))

# Paths whose value has its own check in validate_decision_predicate, with where that check is.
DEDICATED = {
    "schemaVersion": "0.1.x string check", "decisionId": "non-empty string check",
    "decisionType": "enum check", "decidedAt": "RFC3339-Z time paths", "recordedAt": "RFC3339-Z time paths",
    "decisionMaker": "identity object check", "decisionMaker.id": "identity id check",
    "agent": "identity object check", "agent.id": "identity id check",
    "principal": "identity object check", "principal.id": "identity id check",
    "proposedAction": "proposedAction object check", "proposedAction.actionType": "actionType check",
    "proposedAction.parametersRef": "non-empty object check",
    "inputSnapshot": "list check", "inputSnapshot[]": "item digest check", "inputSnapshot[].digest": "item digest check",
    "policyBoundary": "object check", "policyBoundary.policyEngine": "non-empty string check",
    "policyBoundary.policyId": "non-empty string check", "policyBoundary.decisionPath": "non-empty string check",
    "evidenceRefs": "list check", "evidenceRefs[]": "item check", "evidenceRefs[].relation": "item check",
    "evidenceRefs[].digest": "content-root digest check", "evidenceRefs[].artifactDigest": "digest check",
    "evidenceRefs[].typedDigest": "_typed_digest_error",
    "evidenceRefs[].typedDigest.type": "_typed_digest_error", "evidenceRefs[].typedDigest.purpose": "_typed_digest_error",
    "evidenceRefs[].typedDigest.digestAlgorithm": "_typed_digest_error",
    "evidenceRefs[].typedDigest.digest": "_typed_digest_error",
    "decision.reasonCodes[]": "non-empty list of strings check",
    "decision": "object check", "decision.verdict": "enum check", "decision.reasonCodes": "non-empty list check",
    "actionOutcome": "object check", "actionOutcome.status": "enum check",
    "privacy": "object check", "validity": "object check",
}
# Deliberately untyped or validated elsewhere.
UNTYPED = {
    "decisionMaker.version": "the versioned extensions container, unconstrained in the schema too",
    "relationships": "relation.validate_relationships, pinned by tests/test_schema_parity.py",
}

MAL = {"null": None, "true": True, "zero": 0, "minus one": -1, "a float": 1.5, "empty string": "",
       "empty list": [], "list of null": [None], "empty object": {}, "object with empty key": {"": None},
       "a string": "x"}


def _resolve(node: dict) -> dict:
    ref = node.get("$ref")
    if isinstance(ref, str) and ref.startswith("#/$defs/"):
        return SCHEMA["$defs"][ref.rsplit("/", 1)[1]]
    return node


def _typed_schema_paths() -> set:
    """Every dotted path the schema gives a type, enum, const or $ref to, below the root."""
    out: set = set()
    stack = [("", SCHEMA)]
    while stack:
        path, node = stack.pop()
        node = _resolve(node)
        for alt in node.get("anyOf", []):
            stack.append((path, alt))
        for key, sub in node.get("properties", {}).items():
            child = f"{path}.{key}" if path else key
            if child.split(".")[0] == "relationships":
                out.add("relationships")
                continue
            if any(k in sub for k in ("type", "enum", "const", "$ref", "anyOf")):
                out.add(child)
            stack.append((child, sub))
        items = node.get("items")
        if isinstance(items, dict):
            out.add(f"{path}[]")
            stack.append((f"{path}[]", items))
    # the leaf of a $ref'd sha256Digest ("x.sha256") is part of the `sha256` kind, not a separate path
    return {p for p in out if not p.endswith(".sha256")}


def _maximal() -> dict:
    """The deny example with every optional field the schema names filled with a valid value."""
    p = copy.deepcopy(DENY)
    p["delegationRefs"] = []
    p["traceContext"] = {}
    p["evidenceRefs"][0]["artifactDigest"] = {"sha256": "a" * 64}
    p["actionOutcome"] = {"status": "executed", "performedAt": "2026-07-09T10:00:02Z",
                          "outcomeRef": {"uri": "urn:x", "digest": {"sha256": "b" * 64}}}
    return p


def _leaf_paths(o, pre=()):
    if pre:
        yield pre
    if isinstance(o, dict):
        for k, v in o.items():
            yield from _leaf_paths(v, pre + (k,))
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from _leaf_paths(v, pre + (i,))


def _set(o, path, value):
    o = copy.deepcopy(o)
    cur = o
    for k in path[:-1]:
        cur = cur[k]
    cur[path[-1]] = value
    return o


def _schema_ok(instance) -> bool:
    """The schema's verdict, `pattern` read as ECMA-262 (python-jsonschema alone reads it with `re`)."""
    return schema_accepts(instance, SCHEMA)


class EveryTypedSchemaPathHasACheck(unittest.TestCase):

    def test_the_type_table_and_the_dedicated_checks_cover_the_schema(self):
        covered = set(_NESTED_TYPES) | set(DEDICATED) | set(UNTYPED)
        missing = sorted(_typed_schema_paths() - covered)
        self.assertEqual(missing, [], "a schema path has a type and no check; add it to decision._NESTED_TYPES "
                                      "or give it its own check and name it in DEDICATED")

    def test_no_entry_names_a_path_the_schema_does_not_have(self):
        """Counter-direction: a stale entry would check a field the format no longer carries."""
        self.assertEqual(sorted(set(_NESTED_TYPES) - _typed_schema_paths()), [])


@unittest.skipIf(jsonschema is None, "NOT MEASURABLE: jsonschema is not installed (dev extra); the generator "
                                     "did NOT run")
class WhateverTheSchemaRefusesTheValidatorRefuses(unittest.TestCase):

    def test_the_maximal_predicate_passes_both(self):
        """Positive control: without it every refusal below could come from a broken base."""
        self.assertTrue(_schema_ok(_maximal()))
        for strict in (True, False):
            self.assertEqual(validate_decision_predicate(_maximal(), strict=strict), [])

    def test_every_leaf_and_every_confused_value(self):
        base, measured, leaks = _maximal(), 0, []
        for path in _leaf_paths(base):
            if path[0] == "relationships":
                continue
            for label, value in MAL.items():
                m = _set(base, path, value)
                if _schema_ok(m):
                    continue
                measured += 1
                for strict in (True, False):
                    if not validate_decision_predicate(m, strict=strict):
                        leaks.append(f"{'/'.join(map(str, path))} <- {label} (strict={strict})")
        self.assertGreater(measured, 300, "the generator measured almost nothing; the base or MAL broke")
        self.assertEqual(leaks, [])

    def test_a_string_entry_is_the_deprecated_legacy_form(self):
        """Owner decision, 2026-09-26: a bare string in notChecked stays allowed, the schema
        marks that form deprecated, the object form comes first. Both judges accept both forms; neither
        accepts an entry of any other type."""
        forms = SCHEMA["properties"]["notChecked"]["items"]["anyOf"]
        self.assertEqual([f["type"] for f in forms], ["object", "string"])
        self.assertIs(forms[1].get("deprecated"), True)
        self.assertNotIn("deprecated", forms[0])
        for entry in ("adversarial-robustness", {"field": "f", "reason": "r", "impact": "i"}):
            m = _set(_maximal(), ("notChecked", 0), entry)
            with self.subTest(entry=entry):
                self.assertTrue(_schema_ok(m))
                self.assertEqual(validate_decision_predicate(m, strict=True), [])
        for entry in (5, None, ["x"], True):
            m = _set(_maximal(), ("notChecked", 0), entry)
            with self.subTest(entry=entry):
                self.assertFalse(_schema_ok(m))
                self.assertNotEqual(validate_decision_predicate(m, strict=True), [])


class NullIsNotAValue(unittest.TestCase):

    def test_null_at_every_required_field_is_refused(self):
        for strict, fields in ((False, decision._REQUIRED_ALWAYS), (True, decision._REQUIRED_STRICT)):
            for field in fields:
                with self.subTest(field=field, strict=strict):
                    self.assertNotEqual(validate_decision_predicate(_set(DENY, (field,), None), strict=strict), [])

    def test_a_signed_receipt_with_a_null_schema_version_is_not_safe_for_automation(self):
        """L3-Z195-03 end to end, as the gate measured it: pinned signer, --strict, a policy."""
        import rfc8785
        from proofbundle.cli import main as cli
        from proofbundle.dsse import sign_envelope
        from proofbundle.emit import generate_signer
        from proofbundle.subject_binding import derive_subject_digest
        sk = generate_signer()
        pub_b64 = base64.b64encode(sk.public_key().public_bytes_raw()).decode()
        stmt = decision.build_decision_statement(DENY)
        policy = {"schema": "proofbundle/trust-policy/v0.2", "policy_id": "p",
                  "allowed_schema_versions": ["proofbundle/v0.1"],
                  "signature": {"allowed_algs": ["ed25519"], "require_expected_signer": True},
                  "decision_receipt": {"accepted_predicate_types": [stmt["predicateType"]],
                                       "trusted_decision_makers": [{"id": DENY["decisionMaker"]["id"],
                                                                    "public_key_b64": pub_b64}],
                                       "allowed_decision_types": [DENY["decisionType"]],
                                       "allowed_verdicts": ["ALLOW", "DENY"], "required_evidence_relations": [],
                                       "require_policy_digest": True, "require_external_anchor": False,
                                       "allow_pending": False}}
        with tempfile.TemporaryDirectory() as d:
            pol = Path(d) / "pol.json"
            pol.write_text(json.dumps(policy), encoding="utf-8")
            for label, pred in (("control", DENY), ("schemaVersion null", _set(DENY, ("schemaVersion",), None))):
                s = dict(stmt, predicate=pred,
                         subject=[{"name": "decision", "digest": {"sha256": derive_subject_digest(pred)}}])
                env = sign_envelope(rfc8785.dumps(s), sk, payload_type=decision.INTOTO_STATEMENT_PAYLOAD_TYPE)
                path = Path(d) / "m.json"
                path.write_text(json.dumps(env), encoding="utf-8")
                out = io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                    try:
                        rc = cli(["decision", "verify", str(path), "--pub", pub_b64, "--json", "--strict",
                                  "--require-derived-subject", "--policy", str(pol)])
                    except SystemExit as e:
                        rc = e.code
                j = json.loads(out.getvalue())
                with self.subTest(case=label):
                    want = (0, True, True) if label == "control" else (2, False, False)
                    self.assertEqual((rc, j["structure_ok"], j["automation"]["safeForAutomation"]), want)


class TheWalkerStaysInsideItsBudget(unittest.TestCase):

    def test_a_deep_structure_is_a_finding_not_a_crash(self):
        from proofbundle.subject_binding import nested_type_violations
        deep: object = "leaf"
        for _ in range(5000):
            deep = {"k": deep}
        found = nested_type_violations({"traceContext": deep}, {"traceContext": "object"})
        self.assertTrue(any("depth budget" in f for f in found), found[:3])

    def test_an_unknown_kind_is_a_programming_error_named_as_such(self):
        from proofbundle.subject_binding import nested_type_violations
        with self.assertRaises(ValueError):
            nested_type_violations({"a": 1}, {"a": "integer-ish"})


if __name__ == "__main__":
    unittest.main()
