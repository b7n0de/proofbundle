"""Every predicate validator refuses what its published schema refuses, the schema read as ECMA-262.

WHERE THIS COMES FROM. The gate on 3562dc71 (the decision validator against its schema) found the class
one level down: lens A, 228bcA-01, a digest object with a second key passed although `sha256Digest` is
closed; 228bcA-02, outcome's nested value types were never read; lens B, 228bcB-03, the generator of
tests/test_the_decision_validator_refuses_what_its_schema_refuses.py tried no value of the right type
and the wrong shape. Measuring the premise showed two more readings. trust_pack still anchored with
`^..$` after a9269f65 changed eight other modules and its guard named the ones it checked. And every
RFC3339 and 0.1.x pattern in eight modules took Unicode digits, which the schemas' ECMA-262 `\\d` does
not, while the oracle itself, python-jsonschema, reads `pattern` with Python's `re` and could see
neither.

WHAT IS PINNED. (1) The oracle (tests/_schema_oracle.py) reads `pattern` as ECMA-262, and a case shows
plain jsonschema does not. (2) One generator per predicate schema: over a predicate that fills every
optional field, every leaf replaced by eleven values of the wrong type and, for a string, by the same
string with a trailing newline, with an Arabic-Indic digit, and in upper case; every object given one
undeclared key. Whatever the oracle refuses, the validator refuses, strict or lenient. Measured with
this generator on main 10f3466b, leaking paths: decision 64, outcome 13, run_ledger 4,
verification_summary 3, trust_pack 7 (two of them raised TypeError out of the validator). (3) Every
regular expression literal under src/proofbundle that judges a whole value reads it as the schema
does: `\\A..\\Z`, no Unicode class; under scripts/ and tools/, no Unicode class either. (4) End to
end, the three consequences that were measured, and agent-review's time and version in non-ASCII
digits.

NAMED EXCEPTIONS. None among the predicates: the one this change started with, a bare string in
decision's notChecked, is the schema's deprecated legacy form since the owner decided it (owner decision,
2026-09-26). The regex sweep: agent_review's two patterns, the last ones with `\\d` under src/,
are fixed as a bug in v0.1, v0.2 and v0.3 (owner decision, 2026-09-26); outside src/ the sweep names what
it has not judged yet (see `_REGEX_EXCEPTIONS` and `_DOLLAR_OPEN_OUTSIDE_SRC`). The reverse direction
(the validator refusing what the schema accepts) is deliberate where a validator asks more than its
schema, and is not pinned here.
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

try:
    import jsonschema
except ImportError:  # pragma: no cover - dev-only dependency
    jsonschema = None
else:
    # only with jsonschema: the oracle needs it, and a bare install must still collect this
    # module, whose regex sweep and end-to-end cases do not
    from _schema_oracle import EcmaValidator, ecma_pattern, mutations, schema_accepts

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
                        # in the vocabulary, and not compilable (228bc-2B-01/02, 228bc-3-01)
                        "^a{4294967295}$", "^a{3,1}$", "^[9-0]$", "^(a$", "^a)$",
                        "^" + "(" * 1100 + "a" + ")" * 1100 + "$"):
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
# named by hand; trust_pack was on neither list and kept `^..$` for two months. This sweep is derived: every
# `re.*` call with a literal pattern that is anchored at both ends (or is a fullmatch) and not MULTILINE.
#
# WHERE IT SWEEPS. Under src/proofbundle, both readings. Under scripts/ and tools/ (follow-up 235 of this
# class, 2026-09-26) the Unicode half: the release tools carried their own RFC3339 copies with `\d`
# (audit_candidate_matrix, findings_register, the one of them behind `__import__("re")`, which the first
# form of this sweep did not see). The `$` half outside src/ is listed site by site in
# `_DOLLAR_OPEN_OUTSIDE_SRC`: whether a newline can reach each of them depends on its callers, which
# were not all read for this change. The list is exact in both directions, so a new site turns this file
# red and so does a fixed one that stays listed.
#: (module, pattern) pairs this sweep leaves out, each with its reason. agent_review's two patterns were
#: entries here until the owner decision, 2026-09-26; they read ASCII digits now.
_REGEX_EXCEPTIONS = {
    # required_check_reachability_gate reads a GitHub expression, not a schema value: `\s` stands against
    # GitHub's expression grammar, and which whitespace GitHub accepts there was not measured. Its `$`
    # follows `\s*`, which takes a trailing newline either way. Follow-up 236.
    ("scripts.required_check_reachability_gate",
     r"^\s*(?:\$\{\{\s*)?(?:always\(\s*\)|!\s*cancelled\(\s*\))\s*(?:\}\})?\s*$"),
    # The release-scope title form, read through its f-strings since the fold reads a placeholder
    # (2026-09-26). Its identifier digits are ASCII now; its `\S` asks that the subject start with a
    # character that is whitespace in no script, and an ASCII class there would accept U+00A0, the
    # separator the gate's own comment refuses. A title, not a schema value.
    ("scripts.b7_release_scope_title_gate",
     r"^\[ *(?P<version>[0-9]+(?:\.[0-9]+)*) +(?P<kennung>[A-Z]\.?-?[A-Z]?[0-9]+(?:[.\-][0-9a-z]+)*) *\]"
     r" +(?P<typ>[a-z][a-z0-9]*)(?:\([^()]+\))?: +\S[^\r\n]*\Z"),
}
#: The `$` half outside src/, open and named (follow-up 236): each pattern ends in `$`, which also
#: matches before a trailing newline, and whether one can reach it depends on the callers.
_DOLLAR_OPEN_OUTSIDE_SRC = {
    ("scripts.check_version_and_changelog",
     r"^([0-9]+)\.([0-9]+)\.([0-9]+)(?:\.?(a|b|rc)([0-9]+))?(?:\.post([0-9]+))?(?:\.dev([0-9]+))?$"),
    ("scripts.codex_threads_check", r"^ {0,3}(`{3,}|~{3,})(.*)$"),
    ("scripts.fork_pr_secret_isolation", r"^[0-9a-f]{40}$"),
    ("scripts.mutant_signature_guard", r"^src/proofbundle/.*\.py$"),
}
#: Every call whose pattern the fold cannot state completely, keyed by (module, enclosing definition,
#: re function, argument form), with how many such calls there are and why none of them is a
#: whole-value pattern the sweep would have to judge. Deny by default: a new unfolded call, or one more
#: under a listed key, turns the sweep red until it is read and listed here (measured 2026-09-26 under
#: src/, scripts/ and tools/: four calls, each read in its source).
_UNFOLDED_PATTERN_SITES = {
    ("scripts.claims_hygiene_check", "<module>", "compile", "Name p"): (
        1, "a loop variable over _FORBIDDEN: 37 word patterns, none anchored at both ends (read by "
           "importing the module), so it judges no whole value"),
    ("scripts.codex_threads_check", "register_threads", "compile", "JoinedStr"): (
        1, "a run-time value (re.escape of the repository and pull request) in a pattern that is not "
           "anchored at its start, so it judges no whole value"),
    ("scripts.gen_findings_register", "_titel", "sub", "JoinedStr"): (
        1, "a run-time value (re.escape of the identifier) in a pattern anchored at the start only, a "
           "prefix strip that judges no whole value"),
    ("scripts.gen_findings_register", "baue_v2", "search", "JoinedStr"): (
        1, "a run-time value (re.escape of an identifier) in an unanchored search, which judges no "
           "whole value"),
}
_UNICODE_CLASSES = re.compile(r"\\[dDwWsSb]")
DOLLAR, UNICODE = "ends in `$`, which matches before a newline", "uses a Unicode class (`\\d` is 0-9 in ECMA-262)"


#: The functions of `re` that take a pattern first; what `from re import *` binds among them.
_RE_FUNCTIONS = ("compile", "match", "fullmatch", "search", "findall", "finditer", "sub", "subn", "split")


def _re_names(tree) -> tuple:
    """The names `re` is bound to in a module (`re` itself and every `import re as x`), and the names
    bound to one of its functions, mapped to the function: `from re import compile as c`,
    `from re import *`, and an assignment `c = re.compile`.

    Lens 235 (run 1) planted `from re import compile as recompile` with a `\\d` pattern: the first form
    of this sweep read only calls written as an attribute of `re`, and found nothing."""
    names = {"re"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {a.asname for a in node.names if a.name == "re" and a.asname}
    functions: dict = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "re" and not node.level:
            for a in node.names:
                if a.name == "*":
                    functions.update({f: f for f in _RE_FUNCTIONS})
                else:
                    functions[a.asname or a.name] = a.name
        elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            bound = _re_function(node.value, names, {})
            if bound:
                functions[node.targets[0].id] = bound
    return names, functions


def _is_re(value, names) -> bool:
    """`re`, an alias of it, or `__import__("re")` (scripts/findings_register.py writes the last one)."""
    if isinstance(value, ast.Name):
        return value.id in names
    return (isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id == "__import__"
            and len(value.args) == 1 and isinstance(value.args[0], ast.Constant) and value.args[0].value == "re")


def _re_function(func, names, functions):
    """The `re` function a callee names, or None: an attribute of `re` (or of an alias, or of
    `__import__("re")`), `getattr(re, "<literal>")`, or a name bound to one of them."""
    if isinstance(func, ast.Attribute) and _is_re(func.value, names):
        return func.attr
    if isinstance(func, ast.Name):
        return functions.get(func.id)
    if (isinstance(func, ast.Call) and isinstance(func.func, ast.Name) and func.func.id == "getattr"
            and len(func.args) >= 2 and _is_re(func.args[0], names)
            and isinstance(func.args[1], ast.Constant) and isinstance(func.args[1].value, str)):
        return func.args[1].value
    return None


def _module_bindings(tree) -> dict:
    """Module-level name -> every expression it is bound to at module level. A name bound twice holds
    either value at a call site, so both count (a lens on the 228bc stack delta, 235 D-2: the first form
    kept a name bound once only, and a rebound pattern name was invisible)."""
    bound: dict = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            bound.setdefault(node.targets[0].id, []).append(node.value)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
            bound.setdefault(node.target.id, []).append(node.value)
    return bound


#: How many values one expression may fold to, and how long one folded text may grow, before the fold
#: stops widening it. Past either bound the fold records a gap (`_folded`), it does not cut silently.
_FOLD_CAP = 64
_FOLD_SIZE = 10_000
_FOLD_OPS = {ast.Add: lambda a, b: a + b, ast.Mod: lambda a, b: a % b, ast.Mult: lambda a, b: a * b}


_WIDE_FIELD = re.compile(r"[0-9]{5,}")


def _too_large(a, b) -> bool:
    """`*` would build a text or sequence longer than `_FOLD_SIZE` (the third delta run on 9aaa79c0
    folded `r"\\A\\d+\\Z" * 100000000` and used 0.68 GB for one call), or a format text asks for a
    field five digits wide or wider (`"%100000000s" % x`, `"{:100000000}".format(x)`)."""
    for seq, n in ((a, b), (b, a)):
        if isinstance(seq, (str, bytes, list, tuple)) and isinstance(n, int) and len(seq) * n > _FOLD_SIZE:
            return True
    return False


def _wide_format(head) -> bool:
    text = head.decode("latin-1") if isinstance(head, bytes) else head
    return isinstance(text, str) and bool(_WIDE_FIELD.search(text))


def _folded(expr, bound, classes, _seen=frozenset(), gaps=None) -> list:
    """Every value an expression can have as the source states it, folded without running the module:
    str, bytes, int, and literal lists, tuples, dicts and slices of them.

    Read: literals; an f-string whose placeholders fold (no conversion, no format spec); `+`, `%` and `*`
    between folded values; both branches of a conditional; a module-level name through every value it
    is bound to; an attribute of a class defined at module level, through its class body; an index or a
    slice of a folded list, tuple or string; `str.join` and `str.format` on folded values, keywords
    included. The 228bc stack delta planted a conditional, a partial, a name bound twice, bytes, an
    f-string and `+` (run 1), then a class attribute, `%`, `str.join` and a list index (run 2), then `%`
    with a dict, a slice and `format` with keywords (run 3) past a sweep that dropped what it could not
    fold.

    DENY BY DEFAULT: every part the fold cannot state is appended to `gaps` (when given), and the values
    of the other parts are still returned. A parameter, a loop variable, a local name, a call other than
    `str.join` or `str.format`, an inherited or instance attribute, a fold past `_FOLD_CAP` values or
    `_FOLD_SIZE` characters: each is a gap, and a pattern site with a gap is reported by
    `_unfolded_pattern_sites`, so a form nobody listed turns the sweep red instead of passing it."""
    gaps = [] if gaps is None else gaps

    def each(sub):
        return _folded(sub, bound, classes, _seen, gaps)

    def capped(values):
        if len(values) > _FOLD_CAP:
            gaps.append("more than _FOLD_CAP values")
        kept = [v for v in values if not (isinstance(v, (str, bytes)) and len(v) > _FOLD_SIZE)]
        if len(kept) < len(values):
            gaps.append("a text longer than _FOLD_SIZE")
        return kept[:_FOLD_CAP]

    def combos(parts):
        out = [[]]
        for values in parts:
            out = [c + [v] for c in out for v in values]
            if len(out) > _FOLD_CAP:
                gaps.append("more than _FOLD_CAP values")
                out = out[:_FOLD_CAP]
        return out

    if isinstance(expr, ast.Constant):
        if isinstance(expr.value, (str, bytes, int)) and not isinstance(expr.value, bool):
            return [expr.value]
        if expr.value is None:
            return [None]
    elif isinstance(expr, ast.JoinedStr):
        parts = []
        for v in expr.values:
            if isinstance(v, ast.Constant):
                parts.append([v.value])
            elif isinstance(v, ast.FormattedValue) and v.conversion == -1 and v.format_spec is None:
                parts.append([x for x in each(v.value) if isinstance(x, str)])
            else:
                gaps.append(ast.unparse(v))
                return []
        return capped(["".join(c) for c in combos(parts)])
    elif isinstance(expr, (ast.List, ast.Tuple)):
        return [tuple(c) if isinstance(expr, ast.Tuple) else c for c in combos([each(e) for e in expr.elts])]
    elif isinstance(expr, ast.Dict) and None not in expr.keys:
        keys, values = combos([each(k) for k in expr.keys]), combos([each(v) for v in expr.values])
        out = []
        for ks in keys:
            for vs in values:
                try:
                    out.append(dict(zip(ks, vs)))
                except TypeError:
                    gaps.append(ast.unparse(expr))
        return capped(out)
    elif isinstance(expr, ast.UnaryOp) and isinstance(expr.op, (ast.USub, ast.UAdd)):
        return [(-v if isinstance(expr.op, ast.USub) else v) for v in each(expr.operand)
                if isinstance(v, int) and not isinstance(v, bool)]
    elif isinstance(expr, ast.Slice):
        ends = [each(e) if e is not None else [None] for e in (expr.lower, expr.upper, expr.step)]
        return capped([slice(*c) for c in combos(ends)])
    elif isinstance(expr, ast.BinOp) and type(expr.op) in _FOLD_OPS:
        out = []
        for a in each(expr.left):
            for b in each(expr.right):
                if ((isinstance(expr.op, ast.Mult) and _too_large(a, b))
                        or (isinstance(expr.op, ast.Mod) and _wide_format(a))):
                    gaps.append("a text longer than _FOLD_SIZE")
                    continue
                try:
                    out.append(_FOLD_OPS[type(expr.op)](a, b))
                except (TypeError, ValueError, OverflowError, MemoryError, KeyError):
                    gaps.append(ast.unparse(expr))
        return capped(out)
    elif isinstance(expr, ast.IfExp):
        return capped(each(expr.body) + each(expr.orelse))
    elif isinstance(expr, ast.Name) and expr.id in bound and expr.id not in _seen:
        return capped([v for value in bound[expr.id]
                       for v in _folded(value, bound, classes, _seen | {expr.id}, gaps)])
    elif (isinstance(expr, ast.Attribute) and isinstance(expr.value, ast.Name) and expr.value.id in classes
            and expr.attr in classes[expr.value.id]
            and (key := f"{expr.value.id}.{expr.attr}") not in _seen):
        return capped([v for value in classes[expr.value.id][expr.attr]
                       for v in _folded(value, bound, classes, _seen | {key}, gaps)])
    elif isinstance(expr, ast.Subscript):
        out = []
        for container in each(expr.value):
            for index in each(expr.slice):
                try:
                    out.append(container[index])
                except (TypeError, IndexError, KeyError):
                    gaps.append(ast.unparse(expr))
        return capped(out)
    elif (isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute)
            and expr.func.attr in ("join", "format") and all(k.arg for k in expr.keywords)):
        out = []
        names = [k.arg for k in expr.keywords]
        for head in each(expr.func.value):
            if (not isinstance(head, (str, bytes)) or (expr.func.attr == "format" and not isinstance(head, str))
                    or (expr.func.attr == "format" and _wide_format(head))):
                gaps.append(ast.unparse(expr))
                continue
            for args in combos([each(a) for a in expr.args] + [each(k.value) for k in expr.keywords]):
                positional, keywords = args[:len(expr.args)], dict(zip(names, args[len(expr.args):]))
                try:
                    if expr.func.attr == "join" and len(positional) == 1 and not keywords:
                        out.append(head.join(positional[0]))
                    elif expr.func.attr == "format":
                        out.append(head.format(*positional, **keywords))
                    else:
                        gaps.append(ast.unparse(expr))
                except (TypeError, ValueError, IndexError, KeyError):
                    gaps.append(ast.unparse(expr))
        return capped(out)
    gaps.append(ast.unparse(expr))
    return []


def _module_classes(tree) -> dict:
    """Class name -> {attribute: [values bound in the class body]} for classes defined at module level."""
    classes: dict = {}
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            body: dict = {}
            for stmt in node.body:
                if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                    body.setdefault(stmt.targets[0].id, []).append(stmt.value)
                elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value:
                    body.setdefault(stmt.target.id, []).append(stmt.value)
            classes[node.name] = body
    return classes


def _pattern_texts(expr, bound, classes=None, gaps=None) -> list:
    """The pattern texts among the folded values: (text, is_bytes) pairs. A fold nested too deep for
    the interpreter is a gap, not an error that ends the collection (the third delta run on 9aaa79c0
    planted 3000 `+` in a row and `RecursionError` left the sweep)."""
    out = []
    try:
        values = _folded(expr, bound, classes or {}, gaps=gaps)
    except RecursionError:
        if gaps is not None:
            gaps.append("nested deeper than the interpreter's recursion limit")
        values = []
    for v in values:
        if isinstance(v, str):
            out.append((v, False))
        elif isinstance(v, bytes):
            out.append((v.decode("latin-1"), True))
    return out


def _partial_names(tree) -> tuple:
    """The names `functools` is bound to, and the names bound to `functools.partial`."""
    modules, partials = {"functools"}, set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules |= {a.asname for a in node.names if a.name == "functools" and a.asname}
        elif isinstance(node, ast.ImportFrom) and node.module == "functools" and not node.level:
            partials |= {a.asname or a.name for a in node.names if a.name == "partial"}
    return modules, partials


def _is_partial(func, modules, partials) -> bool:
    if isinstance(func, ast.Name):
        return func.id in partials
    return (isinstance(func, ast.Attribute) and func.attr == "partial"
            and isinstance(func.value, ast.Name) and func.value.id in modules)


def _pattern_calls(tree):
    """(call, re function, pattern argument or None, flag texts, line-anchored) for every call of a
    function of `re` in a module, however the module names it."""
    names, functions = _re_names(tree)
    modules, partials = _partial_names(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        function, args = _re_function(node.func, names, functions), list(node.args)
        # `functools.partial(re.compile, PATTERN)` binds the pattern where the partial is made (235 D-2).
        if not function and _is_partial(node.func, modules, partials) and args:
            function, args = _re_function(args[0], names, functions), args[1:]
        if not function:
            continue
        # The pattern as the first argument or as `pattern=` (a review lens of another family planted
        # `re.compile(pattern=...)`, which the first form of this sweep did not see).
        arg = args[0] if args else next((k.value for k in node.keywords if k.arg == "pattern"), None)
        flags = [ast.unparse(a) for a in args[1:] + [k.value for k in node.keywords if k.arg != "pattern"]]
        # `^` and `$` are line anchors under MULTILINE, not whole-value ones.
        multiline = any("MULTILINE" in f or re.search(r"\.M\b", f) for f in flags)
        yield node, function, arg, flags, multiline


def _whole_value_regex_readings(sources) -> list:
    """(module, source) pairs in; one (module, line, pattern, reading) per whole-value pattern read
    differently from ECMA-262, the named exceptions left out."""
    found = []
    for mod, text in sources:
        tree = ast.parse(text)
        bound, classes = _module_bindings(tree), _module_classes(tree)
        for node, function, arg, flags, multiline in _pattern_calls(tree):
            if arg is None or multiline:
                continue
            ascii_flag = any("ASCII" in f or re.search(r"\.A\b", f) for f in flags)
            for pattern, is_bytes in _pattern_texts(arg, bound, classes, gaps=[]):
                anchored = pattern.startswith(("^", "\\A")) and pattern.endswith(("$", "\\Z"))
                if not (anchored or function == "fullmatch") or (mod, pattern) in _REGEX_EXCEPTIONS:
                    continue
                if pattern.endswith("$"):
                    found.append((mod, node.lineno, pattern, DOLLAR))
                # A bytes pattern's `\d` is 0-9 in Python too; its `$` still matches before a newline.
                if _UNICODE_CLASSES.search(pattern) and not ascii_flag and not is_bytes:
                    found.append((mod, node.lineno, pattern, UNICODE))
    return found


def _definitions(tree) -> dict:
    """id(node) -> qualified name of the def or class around it, '<module>' at module level."""
    where: dict = {}
    stack = [(tree, "<module>")]
    while stack:                     # a loop, not recursion: a planted 3000-deep `+` chain is valid source
        node, name = stack.pop()
        for child in ast.iter_child_nodes(node):
            inner = (f"{name}.{child.name}" if name != "<module>" else child.name) if isinstance(
                child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) else name
            where[id(child)] = inner
            stack.append((child, inner))
    return where


def _unfolded_pattern_sites(sources) -> dict:
    """(module, enclosing definition, re function, argument form) -> the gaps of each such call, for
    every call of a pattern-taking function of `re` whose pattern the fold cannot state completely. MULTILINE calls are
    left out as they are by the readings. The argument form is the node type (and a name's identifier),
    so the key does not depend on how one Python version unparses an f-string."""
    sites: dict = {}
    for mod, text in sources:
        tree = ast.parse(text)
        bound, classes, where = _module_bindings(tree), _module_classes(tree), _definitions(tree)
        for node, function, arg, _flags, multiline in _pattern_calls(tree):
            if function not in _RE_FUNCTIONS or multiline:
                continue
            gaps: list = []
            if arg is None:
                gaps.append("no pattern argument the sweep can read")
                form = "none"
            else:
                _pattern_texts(arg, bound, classes, gaps=gaps)
                form = f"Name {arg.id}" if isinstance(arg, ast.Name) else type(arg).__name__
            if gaps:
                sites.setdefault((mod, where.get(id(node), "<module>"), function, form), []).append(gaps)
    return sites


def _whole_value_regex_findings(sources) -> list:
    return [f"{mod}:{line} {pattern!r} {reading}" for mod, line, pattern, reading in
            _whole_value_regex_readings(sources)]


def _modules(root: str):
    base = REPO / root
    for path in sorted(base.rglob("*.py")):
        rel = path.relative_to(REPO / "src" if root.startswith("src") else REPO).with_suffix("")
        yield rel.as_posix().replace("/", ".").removesuffix(".__init__"), path.read_text(encoding="utf-8")


def _tree():
    yield from _modules("src/proofbundle")


def _tree_outside_src():
    yield from _modules("scripts")
    yield from _modules("tools")


class EveryWholeValuePatternReadsAsTheSchemaDoes(unittest.TestCase):

    def test_no_pattern_under_src_reads_a_value_differently(self):
        self.assertEqual(_whole_value_regex_findings(_tree()), [])

    def test_no_pattern_under_scripts_or_tools_reads_digits_differently(self):
        readings = _whole_value_regex_readings(_tree_outside_src())
        self.assertEqual([r for r in readings if r[3] == UNICODE], [])
        self.assertEqual({(mod, pattern) for mod, _line, pattern, reading in readings if reading == DOLLAR},
                         _DOLLAR_OPEN_OUTSIDE_SRC, "a `$` site outside src/ came or went; list it or remove it")

    def test_the_sweep_sees_both_readings(self):
        """Positive control, with the sweep itself: the two old readings, planted into a module, are found;
        the ASCII flag and `\\A..\\Z` are accepted."""
        planted = ('import re\nA = re.compile(r"^[0-9a-f]{64}$")\nB = re.compile(r"\\A0\\.1\\.\\d+\\Z")\n'
                   'C = re.compile(r"\\A\\d+\\Z", re.ASCII)\nD = re.compile(r"\\A[0-9]+\\Z")\n')
        found = _whole_value_regex_findings([("proofbundle.planted", planted)])
        self.assertEqual(len(found), 2, found)
        self.assertIn("ends in `$`", found[0] + found[1])
        self.assertIn("Unicode class", found[0] + found[1])

    def test_the_sweep_sees_the_routes_the_scripts_use(self):
        """An alias of `re` and `__import__("re")` are seen; a MULTILINE pattern is a line anchor and is not.
        The first form of this sweep read only a name spelled `re`, and the copy in findings_register
        passed it."""
        planted = ('import re as rx\nA = rx.compile(r"\\A\\d+\\Z")\n'
                   'B = __import__("re").compile(r"\\A\\d+\\Z")\n'
                   'import re\nC = re.search(r"^x\\s*:\\s*(.+)$", "", re.M)\n'
                   'D = re.search(r"^\\d+$", "", flags=re.MULTILINE)\n')
        found = _whole_value_regex_readings([("scripts.planted", planted)])
        self.assertEqual(sorted(line for _mod, line, _p, _r in found), [2, 3], found)

    def test_the_sweep_sees_every_way_a_module_names_a_re_function(self):
        """A function of `re` imported by name, under another name, by `*`, bound by assignment or taken
        with getattr is seen; the clean pattern on the last line is not a finding."""
        planted = ('from re import compile as recompile\nA = recompile(r"\\A\\d+\\Z")\n'
                   'from re import fullmatch\nB = fullmatch(r"[0-9]+\\d", "")\n'
                   'import re\nc = re.compile\nC = c(r"\\A\\d+\\Z")\n'
                   'D = getattr(re, "compile")(r"\\A\\d+\\Z")\n'
                   'from re import *\nE = search(r"^[0-9]+$", "")\nF = compile(r"\\A[0-9]+\\Z")\n')
        found = _whole_value_regex_readings([("scripts.planted", planted)])
        self.assertEqual(sorted(line for _mod, line, _p, _r in found), [2, 4, 7, 8, 10], found)

    def test_the_sweep_sees_every_way_a_pattern_reaches_re(self):
        """As `pattern=`, and through a module-level name bound once to a string; the clean pattern
        behind the second name is not a finding."""
        planted = ('import re\nA = re.compile(pattern=r"\\A\\d+\\Z")\nP = r"\\A\\d+\\Z"\nB = re.compile(P)\n'
                   'Q = r"\\A[0-9]+\\Z"\nC = re.compile(Q)\nD = re.fullmatch(pattern=r"[0-9]+\\d", string="1")\n')
        found = _whole_value_regex_readings([("scripts.planted", planted)])
        self.assertEqual(sorted(line for _mod, line, _p, _r in found), [2, 4, 7], found)

    def test_the_sweep_reads_every_form_a_pattern_text_takes(self):
        """The 228bc stack delta (235 D-2) planted these past the sweep: both branches of a conditional,
        `functools.partial` under either name, a name bound twice, a bytes pattern ending in `$`, an
        f-string without a placeholder and two literals joined by `+`. A bytes pattern's `\\d` is ASCII in
        Python and is no finding; the clean conditional on the last line is none either."""
        planted = ('import re, functools\nfrom functools import partial as fp\n'
                   'A = re.compile(r"\\A\\d+\\Z" if X else r"\\A[0-9]+\\Z")\n'
                   'B = functools.partial(re.compile, r"\\A\\d+\\Z")\n'
                   'C = fp(re.fullmatch, r"[0-9]+\\d")\n'
                   'D_NAME = r"\\A[0-9]+\\Z"\nD_NAME = r"\\A\\d+\\Z"\nD = re.compile(D_NAME)\n'
                   'E = re.compile(rb"^[0-9]+$")\nF = re.compile(rb"\\A\\d+\\Z")\n'
                   'G = re.compile(f"\\\\A\\\\d+\\\\Z")\nH = re.compile("\\\\A\\\\d" + "+\\\\Z")\n'
                   'I = re.compile(r"\\A[0-9]+\\Z" if X else r"\\A[0-9]+\\Z")\n')
        found = _whole_value_regex_readings([("scripts.planted", planted)])
        self.assertEqual(sorted(line for _mod, line, _p, _r in found), [3, 4, 5, 8, 9, 11, 12], found)

    def test_the_sweep_folds_what_the_source_states(self):
        """The second delta run on ea6db077 wrote four more forms past the sweep: a class attribute,
        `%`-formatting, `str.join` and an index into a module-level list. The fold reads each; a
        clean pattern built the same way is no finding."""
        planted = ('import re\nclass K:\n    PAT = r"\\A\\d+\\Z"\nA = re.compile(K.PAT)\n'
                   'B = re.compile(r"\\A\\d+%s" % (r"\\Z",))\n'
                   'C = re.compile("".join([r"\\A\\d", r"+\\Z"]))\n'
                   'PATS = [r"\\A[0-9]+\\Z", r"^[0-9]+$"]\nD = re.compile(PATS[1])\n'
                   'E = re.compile("{}{}".format(r"\\A\\d", "+\\\\Z"))\n'
                   'F = re.compile(PATS[0] * 1)\n')
        found = _whole_value_regex_readings([("scripts.planted", planted)])
        self.assertEqual(sorted(line for _mod, line, _p, _r in found), [4, 5, 6, 8, 9], found)

    def test_a_value_computed_at_run_time_is_reported_unfolded_not_passed(self):
        """A call other than `str.join` or `str.format` is not run by the sweep, and a loop variable is
        not resolved; neither is read as a pattern. Each is reported as an unfolded site instead of
        passing silently, which the fold did until the third delta run on 9aaa79c0."""
        planted = ('import re\nA = re.compile(str(r"\\A\\d+\\Z"))\nB = re.compile(r"\\A\\d+\\Z".strip())\n'
                   'for _p in (r"\\A\\d+\\Z",):\n    re.compile(_p)\n')
        self.assertEqual(_whole_value_regex_readings([("scripts.planted", planted)]), [])
        self.assertEqual(sorted((k[3], len(v)) for k, v in
                                _unfolded_pattern_sites([("scripts.planted", planted)]).items()),
                         [("Call", 2), ("Name _p", 1)])

    def test_the_third_delta_forms_are_folded(self):
        """The third delta run on 9aaa79c0 wrote three forms the fold dropped without a word: `%` with a
        dict, a slice, and `str.format` with keywords. The fold reads each now, and an f-string whose
        placeholder names a module constant; a clean pattern built the same way is no finding."""
        planted = ('import re\nA = re.compile(r"\\A\\d+%(z)s" % {"z": r"\\Z"})\n'
                   'PAT = r"\\A\\d+\\Zx"\nB = re.compile(PAT[:-1])\n'
                   'C = re.compile("{x}{y}".format(x=r"\\A\\d", y="+\\\\Z"))\n'
                   'D_PART = r"\\d+"\nD = re.compile(rf"\\A{D_PART}\\Z")\n'
                   'E = re.compile(rf"\\A{PAT[:-1][2:4]}\\Z")\nF = re.compile("{x}".format(x=r"\\A[0-9]+\\Z"))\n')
        found = _whole_value_regex_readings([("scripts.planted", planted)])
        self.assertEqual(sorted(line for _mod, line, _p, _r in found), [2, 4, 5, 7, 8], found)
        self.assertEqual(_unfolded_pattern_sites([("scripts.planted", planted)]), {})

    def test_a_fold_too_deep_or_too_large_is_a_gap_not_a_crash(self):
        """3000 `+` in a row raised RecursionError out of the sweep and ended the collection, and
        `r"\\A\\d+\\Z" * 100000000` folded to 0.68 GB for one call (both measured in the third delta
        run). Each is a gap now: reported as unfolded, not read, not raised."""
        import time
        deep = "import re\nA = re.compile(" + " + ".join(['r"\\A\\d+\\Z"'] + ['""'] * 3000) + ")\n"
        large = ('import re\nB = re.compile(r"\\A\\d+\\Z" * 100000000)\n'
                 'C = re.compile("%100000000s" % "x")\nD = re.compile("{:100000000}".format("x"))\n')
        t0 = time.monotonic()
        for planted in (deep, large):
            with self.subTest(planted=planted[:40]):
                self.assertEqual(_whole_value_regex_readings([("scripts.planted", planted)]), [])
                self.assertTrue(_unfolded_pattern_sites([("scripts.planted", planted)]))
        self.assertLess(time.monotonic() - t0, 30)

    def test_every_unfolded_site_in_the_tree_is_listed_with_its_count(self):
        """Deny by default, in both directions: a site the fold cannot state is listed with the reason
        it judges no whole value, and a listed site that is gone leaves the list."""
        seen = {k: len(v) for k, v in _unfolded_pattern_sites(list(_tree()) + list(_tree_outside_src())).items()}
        self.assertEqual(seen, {k: n for k, (n, _why) in _UNFOLDED_PATTERN_SITES.items()},
                         "an unfolded pattern site came, went or changed its count: read it and list it")
        for key, (_n, why) in _UNFOLDED_PATTERN_SITES.items():
            with self.subTest(site=key):
                self.assertRegex(why, r"judges no whole value")

    def test_the_named_exceptions_are_still_there(self):
        """Counter-direction: an exception whose pattern is gone is stale and must be removed. Read as
        the sweep reads it, folded, since a pattern built in an f-string is in no source line whole."""
        text = dict(_tree()) | dict(_tree_outside_src())
        for mod, pattern in _REGEX_EXCEPTIONS:
            with self.subTest(module=mod, pattern=pattern):
                tree = ast.parse(text[mod])
                bound, classes = _module_bindings(tree), _module_classes(tree)
                folded = {p for _n, _f, arg, _fl, _m in _pattern_calls(tree) if arg is not None
                          for p, _b in _pattern_texts(arg, bound, classes, gaps=[])}
                self.assertIn(pattern, folded)


class TheMeasuredConsequencesAreGone(unittest.TestCase):
    """The three consequences measured on 3562dc71, end to end, and the agent-review digits."""

    def test_an_agent_review_time_or_version_in_other_digits_is_refused(self):
        """Owner decision, 2026-09-26. agent_review read RFC3339 times and schemaVersion with Python's `\\d`,
        which takes every Unicode decimal digit. On our published v0.1 receipt, a declaredAt in fullwidth
        digits and a schemaVersion with an Arabic-Indic digit were valid before this change; now each is
        refused by the check v0.1, v0.2 and v0.3 share (for v0.2 and v0.3, over the errors the base
        already has there). `revisedAt` reads the same constant as declaredAt."""
        from proofbundle import agent_review as ar
        env = json.loads((REPO / "receipts" / "agent_review" / "inspect_ai_5141.r3.receipt.json")
                         .read_text(encoding="utf-8"))
        base = json.loads(base64.b64decode(env["payload"]))["predicate"]
        self.assertEqual(ar.validate_agent_review_predicate(base), [])
        versions = (("v0.1", ar.validate_agent_review_predicate), ("v0.2", ar.validate_agent_review_v02_predicate),
                    ("v0.3", ar.validate_agent_review_v03_predicate))
        for field, path, value in (("declaredAt", ("times", "declaredAt"), "２０２６-09-26T00:00:00Z"),
                                   ("schemaVersion", ("schemaVersion",), "0.1.٣")):
            doc = copy.deepcopy(base)
            target = doc
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            for name, validate in versions:
                with self.subTest(field=field, version=name):
                    added = set(validate(doc)) - set(validate(base))
                    self.assertTrue(any(field in e for e in added), added)

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
