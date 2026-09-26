"""Every predicate validator refuses what its published schema refuses, the schema read as ECMA-262.

WHERE THIS COMES FROM. The gate on 3562dc71 (the decision validator against its schema) found the class
one level down: lens A, 228bcA-01, a digest object with a second key passed although `sha256Digest` is
closed; 228bcA-02, outcome's nested value types were never read; lens B, 228bcB-03, the generator of
tests/test_the_decision_validator_refuses_what_its_schema_refuses.py tried no value of the right type
and the wrong shape. Measuring the premise showed two more readings. trust_pack still anchored with
`^..$` after a9269f65 changed eight other modules and its guard named the ones it checked. And every RFC3339 and 0.1.x pattern in nine
modules took Unicode digits, which the schemas' ECMA-262 `\\d` does not, while the oracle itself,
python-jsonschema, reads `pattern` with Python's `re` and could see neither.

WHAT IS PINNED. (1) The oracle (tests/_schema_oracle.py) reads `pattern` as ECMA-262, and a case shows
plain jsonschema does not. (2) One generator per predicate schema: over a predicate that fills every
optional field, every leaf replaced by eleven values of the wrong type and, for a string, by the same
string with a trailing newline, with an Arabic-Indic digit, and in upper case; every object given one
undeclared key. Whatever the oracle refuses, the validator refuses, strict or lenient. Measured with
this generator on main 10f3466b, leaking paths: decision 64, outcome 13, run_ledger 4,
verification_summary 3, trust_pack 7 (two of them raised TypeError out of the validator). (3) Every
regular expression literal under src/proofbundle that judges a whole value reads it as the schema
does: `\\A..\\Z`, no Unicode class. (4) End to end, the three consequences that were measured.

NAMED EXCEPTIONS. None among the predicates: the one this change started with, a bare string in
decision's notChecked, is the schema's deprecated legacy form since the owner decided it (owner decision,
2026-09-26). The regex sweep: agent_review keeps its own `\\d` patterns; that predicate has no published
schema, the module was not read for this change, and the follow-up is recorded in the step list. The
reverse direction (the validator refusing what the schema accepts) is deliberate where a validator asks
more than its schema, and is not pinned here.
"""
from __future__ import annotations

import ast
import base64
import copy
import json
import pathlib
import re
import subprocess
import tempfile
import unittest

from _schema_oracle import EcmaValidator, ecma_pattern, mutations, schema_accepts

try:
    import jsonschema
except ImportError:  # pragma: no cover - dev-only dependency
    jsonschema = None

REPO = pathlib.Path(__file__).resolve().parents[1]
SCHEMAS = REPO / "schemas"
H = lambda c: c * 64  # noqa: E731 - a 64-hex digest of one repeated character
T = "2026-09-26T00:00:00Z"
EDGE = {"relation": "supersedes", "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": H("c")},
        "targetSubjectDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": H("d")}, "reason": "r",
        "reasonCode": "correction", "declaredAt": T}


def _decision():
    p = json.loads((REPO / "examples" / "decision_receipt_deny.json").read_text(encoding="utf-8"))
    p["delegationRefs"] = []
    p["traceContext"] = {}
    p["evidenceRefs"][0]["artifactDigest"] = {"sha256": H("a")}
    p["actionOutcome"] = {"status": "executed", "performedAt": "2026-07-09T10:00:02Z",
                          "outcomeRef": {"uri": "urn:x", "digest": {"sha256": H("b")}}}
    p["relationships"] = [copy.deepcopy(EDGE)]
    return p


def _outcome():
    return {"schemaVersion": "0.1.0", "outcomeId": "o", "decisionRef": {"sha256": H("1")},
            "executor": {"id": "e", "keyId": "k"}, "requestedActionDigest": {"sha256": H("2")},
            "actualActionDigest": {"sha256": H("3")}, "responseDigest": {"sha256": H("4")},
            "effectDigest": {"sha256": H("5")}, "status": "executed", "performedAt": T, "recordedAt": T,
            "policyPurpose": "outcome", "traceContext": {"traceparent": "00-x"}, "limitations": ["l"],
            "validity": {"audience": ["a"], "nonce": "n"},
            "receiverRefs": [{"relation": "r", "digest": {"sha256": H("6")}, "receiverId": "ri",
                              "receiverKeyId": "rk", "artifactDigest": {"sha256": H("7")}}],
            "sequence": {"runId": "run", "seq": 1}, "relationships": [copy.deepcopy(EDGE)]}


def _run_ledger():
    return {"schemaVersion": "0.1.0", "studyId": "s", "runBudget": 3, "nonClaims": ["n"],
            "externalRandomnessRef": {"sha256": H("e")}, "selectedSeq": 1,
            "runs": [{"seq": 1, "status": "completed", "resultDigest": {"sha256": H("1")}, "prevDigest": None,
                      "startedAt": T, "note": "x"},
                     {"seq": 2, "status": "aborted", "resultDigest": {"sha256": H("2")},
                      "prevDigest": {"sha256": H("1")}, "startedAt": T, "note": "y"}]}


def _verification_summary():
    return {"schemaVersion": "0.1.0", "summaryId": "v", "producedAt": T, "producer": {"id": "p", "keyId": "k"},
            "chainRef": {"sha256": H("9")}, "nonClaims": ["n"],
            "levels": [{"kind": "decision", "receiptRef": {"sha256": H("8")}, "status": "VERIFIED",
                        "evidenceClass": "decision_claim", "checks": ["c"]}]}


def _trust_pack():
    roles = {r: {"keyIds": ["k1"], "threshold": 1} for r in (
        "root", "evalIssuers", "decisionMakers", "outcomeExecutors", "outcomeReceivers", "timeAuthorities",
        "witnesses")}
    return {"schemaVersion": "0.1.0", "trustPackId": "t", "version": 2, "expires": "2099-01-01T00:00:00Z",
            "prevVersionDigest": {"sha256": H("f")}, "roles": roles,
            "keys": {"k1": {"publicKey": base64.b64encode(b"\x01" * 32).decode(), "scheme": "ed25519",
                            "alg": "ed25519"},
                     "k2": {"publicKey": base64.b64encode(b"\x02" * 32).decode(), "alg": "hybrid-ed25519-mldsa65",
                            "publicKeyPq": base64.b64encode(b"\x03" * 1952).decode()}},
            "revoked": ["k2"], "nonClaims": ["n"]}


def _validators():
    from proofbundle import decision, outcome, run_ledger, trust_pack, verification_summary
    return {"decision": decision.validate_decision_predicate, "outcome": outcome.validate_outcome_predicate,
            "run_ledger": run_ledger.validate_run_ledger_predicate,
            "verification_summary": verification_summary.validate_summary_predicate,
            "trust_pack": trust_pack.validate_trust_pack_predicate}


# name -> (schema file, fully populated base, floor for the number of refused mutations measured)
PREDICATES = {
    "decision": ("decision-receipt", _decision, 1000),
    "outcome": ("action-outcome", _outcome, 500),
    "run_ledger": ("run-ledger", _run_ledger, 250),
    "verification_summary": ("verification-summary", _verification_summary, 180),
    "trust_pack": ("trust-pack", _trust_pack, 450),
}


def _schema(name):
    return json.loads((SCHEMAS / f"{PREDICATES[name][0]}-v0.1.schema.json").read_text(encoding="utf-8"))


@unittest.skipIf(jsonschema is None, "NOT MEASURABLE: jsonschema is not installed (dev extra); the oracle "
                                     "and the generators did NOT run")
class TheOracleReadsPatternsAsTheSchemaMeansThem(unittest.TestCase):

    def test_the_two_readings_plain_jsonschema_gets_wrong(self):
        """Counter-direction, and the reason the oracle exists: plain jsonschema accepts both."""
        cases = (("^[0-9a-f]{64}$", "a" * 64 + "\n"), ("^0\\.1\\.\\d+$", "0.1.٣"),
                 ("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?Z$", "２０２６-01-01T00:00:00Z"))
        for pattern, value in cases:
            with self.subTest(pattern=pattern):
                schema = {"type": "string", "pattern": pattern}
                self.assertTrue(jsonschema.Draft202012Validator(schema).is_valid(value))
                self.assertFalse(EcmaValidator(schema).is_valid(value))
                self.assertTrue(EcmaValidator(schema).is_valid(value.rstrip("\n").replace("٣", "3")
                                                             .replace("２０２６", "2026")))

    def test_a_pattern_it_does_not_know_is_refused_not_guessed(self):
        for pattern in ("^\\w+$", "^a$|^b$", "[0-9]+", "^(?i)x$",
                        # in the vocabulary, and not compilable (228bc-2B-01/02)
                        "^a{4294967295}$", "^a{3,1}$", "^[9-0]$", "^(a$", "^a)$"):
            with self.subTest(pattern=pattern), self.assertRaises(ValueError):
                ecma_pattern(pattern)

    def test_every_pattern_in_the_predicate_schemas_is_one_it_translates(self):
        found = set()

        def walk(o):
            if isinstance(o, dict):
                for k, v in o.items():
                    if k == "pattern":
                        found.add(v)
                    walk(v)
            elif isinstance(o, list):
                for v in o:
                    walk(v)
        for name in PREDICATES:
            walk(_schema(name))
        self.assertGreaterEqual(len(found), 3)
        for pattern in found:
            ecma_pattern(pattern)            # raises for a construct the translation does not cover


@unittest.skipIf(jsonschema is None, "NOT MEASURABLE: jsonschema is not installed (dev extra); the generators "
                                     "did NOT run")
class EveryValidatorRefusesWhatItsSchemaRefuses(unittest.TestCase):

    def test_the_fully_populated_bases_pass_both(self):
        """Positive control: without it every refusal below could come from a broken base."""
        for name, validate in _validators().items():
            base = PREDICATES[name][1]()
            with self.subTest(predicate=name):
                self.assertTrue(schema_accepts(base, _schema(name)))
                for strict in (True, False):
                    self.assertEqual(validate(base, strict=strict), [])

    def test_every_mutation_the_schema_refuses_the_validator_refuses(self):
        for name, validate in _validators().items():
            _file, make, floor = PREDICATES[name]
            schema, base = _schema(name), make()
            measured, leaks = 0, []
            for label, path, doc in mutations(base):
                if schema_accepts(doc, schema):
                    continue
                measured += 1
                for strict in (True, False):
                    try:
                        errors = validate(doc, strict=strict)
                    except Exception as exc:  # noqa: BLE001 - a validator that raises is the finding
                        leaks.append(f"{'/'.join(map(str, path))} <- {label}: raised {type(exc).__name__}")
                        continue
                    if not errors:
                        leaks.append(f"{'/'.join(map(str, path))} <- {label} (strict={strict})")
            with self.subTest(predicate=name):
                self.assertGreater(measured, floor, "the generator measured too little; the base or the "
                                                    "mutations broke")
                self.assertEqual(leaks, [])

    def test_the_generator_reaches_the_deprecated_form(self):
        """decision's notChecked accepts a bare string (the deprecated legacy form, owner decision, 2026-09-26).
        The generator must still try the entries there: a number at notChecked[0] is refused by both."""
        from proofbundle.decision import validate_decision_predicate
        base = _decision()
        hits = [(label, doc) for label, path, doc in mutations(base) if path == ("notChecked", 0)]
        self.assertGreater(len(hits), 5)
        doc = dict(base, notChecked=[5])
        self.assertFalse(schema_accepts(doc, _schema("decision")))
        self.assertNotEqual(validate_decision_predicate(doc, strict=True), [])


# ── Every regular expression that judges a whole value reads it as the schema does ─────────────────
#
# a9269f65 (2026-07-18) moved eight modules from `^..$` to `\A..\Z`, and its guard checked the modules it
# named by hand; trust_pack was on neither list and kept `^..$` for two months. This sweep is derived: every `re.*` call with a literal pattern
# under src/proofbundle that is anchored at both ends (or is a fullmatch).
_REGEX_EXCEPTIONS = {
    # agent_review has no published schema, and the module (3243 lines) was not read for this change;
    # its two patterns keep Python's `\d`. Recorded as a follow-up in the step list, not decided here.
    ("proofbundle.agent_review", r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z\Z"),
    ("proofbundle.agent_review", r"\A0\.1\.\d+\Z"),
}
_UNICODE_CLASSES = re.compile(r"\\[dDwWsSb]")


def _whole_value_regex_findings(sources) -> list:
    """(module, source) pairs in, one finding per whole-value pattern read differently from ECMA-262."""
    found = []
    for mod, text in sources:
        for node in ast.walk(ast.parse(text)):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == "re" and node.args
                    and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
                continue
            pattern = node.args[0].value
            anchored = pattern.startswith(("^", "\\A")) and pattern.endswith(("$", "\\Z"))
            if not (anchored or node.func.attr == "fullmatch") or (mod, pattern) in _REGEX_EXCEPTIONS:
                continue
            ascii_flag = any("ASCII" in ast.unparse(a) or ast.unparse(a).endswith(".A")
                             for a in list(node.args[1:]) + [k.value for k in node.keywords])
            if pattern.endswith("$"):
                found.append(f"{mod}:{node.lineno} {pattern!r} ends in `$`, which matches before a newline")
            if _UNICODE_CLASSES.search(pattern) and not ascii_flag:
                found.append(f"{mod}:{node.lineno} {pattern!r} uses a Unicode class (`\\d` is 0-9 in ECMA-262)")
    return found


def _tree():
    for path in sorted((REPO / "src" / "proofbundle").rglob("*.py")):
        mod = path.relative_to(REPO / "src").with_suffix("").as_posix().replace("/", ".")
        yield mod.removesuffix(".__init__"), path.read_text(encoding="utf-8")


class EveryWholeValuePatternReadsAsTheSchemaDoes(unittest.TestCase):

    def test_no_pattern_under_src_reads_a_value_differently(self):
        self.assertEqual(_whole_value_regex_findings(_tree()), [])

    def test_the_sweep_sees_both_readings(self):
        """Positive control, with the sweep itself: the two old readings, planted into a module, are found;
        the ASCII flag and `\\A..\\Z` are accepted."""
        planted = ('import re\nA = re.compile(r"^[0-9a-f]{64}$")\nB = re.compile(r"\\A0\\.1\\.\\d+\\Z")\n'
                   'C = re.compile(r"\\A\\d+\\Z", re.ASCII)\nD = re.compile(r"\\A[0-9]+\\Z")\n')
        found = _whole_value_regex_findings([("proofbundle.planted", planted)])
        self.assertEqual(len(found), 2, found)
        self.assertIn("ends in `$`", found[0] + found[1])
        self.assertIn("Unicode class", found[0] + found[1])

    def test_the_named_exceptions_are_still_there(self):
        """Counter-direction: an exception whose pattern is gone is stale and must be removed."""
        text = dict(_tree())
        for mod, pattern in _REGEX_EXCEPTIONS:
            with self.subTest(module=mod, pattern=pattern):
                self.assertIn(pattern, text[mod])


class TheMeasuredConsequencesAreGone(unittest.TestCase):
    """The three consequences measured on 3562dc71, end to end."""

    def _signer(self):
        from proofbundle.emit import generate_signer
        return generate_signer()

    def test_a_signed_trust_pack_whose_expiry_ends_in_a_newline_does_not_verify(self):
        from proofbundle import trust_pack
        sk = self._signer()
        pub = base64.b64encode(sk.public_key().public_bytes_raw()).decode()
        base = {"schemaVersion": "0.1.0", "trustPackId": "t", "version": 1, "expires": "2099-01-01T00:00:00Z",
                "prevVersionDigest": None, "roles": {"root": {"keyIds": ["r"], "threshold": 1}},
                "keys": {"r": {"publicKey": pub}}, "nonClaims": ["n"]}
        self.assertIs(trust_pack.verify_trust_pack(trust_pack.sign_trust_pack(base, {"r": sk}))["ok"], True)
        import rfc8785
        from proofbundle import dsse
        bent = dict(base, expires="2099-01-01T00:00:00Z\n")
        stmt = dict(trust_pack.build_trust_pack_statement(base), predicate=bent)
        body = rfc8785.dumps(stmt)
        sig = sk.sign(dsse.pae(trust_pack.INTOTO_STATEMENT_PAYLOAD_TYPE, body))
        env = {"payload": base64.b64encode(body).decode(), "payloadType": trust_pack.INTOTO_STATEMENT_PAYLOAD_TYPE,
               "signatures": [{"keyid": "r", "sig": base64.b64encode(sig).decode()}]}
        r = trust_pack.verify_trust_pack(env)
        self.assertEqual((r["ok"], r["structure_ok"], r["root_threshold_met"]), (False, False, None))

    def test_a_trust_pack_with_a_list_for_alg_is_a_verdict_not_a_raise(self):
        """Signed by a key the pack does not name: the crash came before any signature was counted."""
        import rfc8785
        from proofbundle import dsse, trust_pack
        sk = self._signer()
        pred = {"schemaVersion": "0.1.0", "trustPackId": "t", "version": 1, "expires": "2099-01-01T00:00:00Z",
                "prevVersionDigest": None, "roles": {"root": {"keyIds": ["r"], "threshold": 1}},
                "keys": {"r": {"publicKey": base64.b64encode(b"\x07" * 32).decode(), "alg": []}},
                "nonClaims": ["n"]}
        stmt = {"_type": "https://in-toto.io/Statement/v1",
                "subject": [{"name": "x", "digest": {"sha256": H("a")}}],
                "predicateType": trust_pack.TRUST_PACK_PREDICATE_TYPE, "predicate": pred}
        env = dsse.sign_envelope(rfc8785.dumps(stmt), sk, payload_type=trust_pack.INTOTO_STATEMENT_PAYLOAD_TYPE)
        r = trust_pack.verify_trust_pack(env)
        self.assertIs(r["ok"], False)
        self.assertTrue(any("alg must be one of" in e for e in r["errors"]), r["errors"])

    def test_python_refuses_the_declared_at_rust_refuses(self):
        """On one signed relation statement whose edge `declaredAt` uses fullwidth digits, Python said ok
        (exit 0) and the Rust verifier FAIL (exit 2). Python refuses it now; with the binary built, both
        verdicts are compared."""
        import contextlib
        import io
        from proofbundle.cli import main as cli
        from proofbundle.relation_statement import (RelationStatementError, emit_relation_statement,
                                                    validate_relation_statement_predicate)
        edge = dict(EDGE, declaredAt="２０２６-01-01T00:00:00Z")
        edge.pop("targetSubjectDigest")
        pred = {"schemaVersion": "0.1.0", "statementId": "s", "relationships": [edge]}
        self.assertTrue(any("declaredAt" in e for e in validate_relation_statement_predicate(pred)))
        sk = self._signer()
        with self.assertRaises(RelationStatementError):
            emit_relation_statement(pred, sk)
        import rfc8785
        from proofbundle import dsse
        from proofbundle.relation_statement import INTOTO_STATEMENT_PAYLOAD_TYPE, build_relation_statement
        ok_pred = dict(pred, relationships=[dict(edge, declaredAt=T)])
        stmt = dict(build_relation_statement(ok_pred), predicate=pred)
        env = dsse.sign_envelope(rfc8785.dumps(stmt), sk, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE)
        pub = base64.b64encode(sk.public_key().public_bytes_raw()).decode()
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "s.json"
            path.write_text(json.dumps(env), encoding="utf-8")
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                try:
                    rc = cli(["relation-statement", "verify", str(path), "--pub", pub, "--json"])
                except SystemExit as e:
                    rc = e.code
            self.assertEqual((rc, json.loads(out.getvalue())["ok"]), (2, False))
            rust = REPO / "tools" / "pb_verify_rs" / "target" / "release" / "pb_verify_rs"
            if not rust.exists():
                self.skipTest("NOT MEASURABLE here: the Rust binary is not built; the Python half ran")
            p = subprocess.run([str(rust), "verify-relation-statement", str(path), pub],
                               capture_output=True, text=True, timeout=60)
            self.assertEqual(p.returncode, 2, p.stdout + p.stderr)


if __name__ == "__main__":
    unittest.main()
