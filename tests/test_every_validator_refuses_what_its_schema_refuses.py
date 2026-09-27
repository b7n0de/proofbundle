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
does: `\\A..\\Z`, no Unicode class, and so does every one under scripts/ and tools/. (4) End to
end, the three consequences that were measured, and agent-review's time and version in non-ASCII
digits.

NAMED EXCEPTIONS. None among the predicates: the one this change started with, a bare string in
decision's notChecked, is the schema's deprecated legacy form since the owner decided it (owner decision,
2026-09-26). The regex sweep: agent_review's two patterns, the last ones with `\\d` under src/,
are fixed as a bug in v0.1, v0.2 and v0.3 (owner decision, 2026-09-26), and one script that reads a GitHub
expression keeps Python's `\\s` (see `_REGEX_EXCEPTIONS`). The reverse direction (the validator
refusing what the schema accepts) is deliberate where a validator asks more than its schema, and is
not pinned here.
"""
from __future__ import annotations

import ast
import base64
import collections
import copy
import functools
import itertools
import json
import operator
import pathlib
import re
import string
import subprocess
import sys
import tempfile
import unicodedata
import unittest
import unittest.mock

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
# call of a function of `re` that takes a pattern, the pattern folded from the source (`_Fold`), read under
# every flag value the call can pass and in every way it is matched (`_readings`). A pattern judges a whole
# value when it is matched with fullmatch, or when one of its branches is anchored at the start (`\A`, `^`
# outside MULTILINE, or `match`, which anchors there by itself) and at the end (`\Z`, `$` outside
# MULTILINE, or a lookahead that is one of these). The pattern is read in one pass after its leading inline
# flags, its comments and VERBOSE whitespace (`_lesung`): an anchor counts wherever it stands on the
# pattern's own path, at its top level or in a group there that is matched at least once, quantified or
# not (`\A\d+\Z()`, `(?:\A\d+){1}\Z`); an alternation, the top-level one included, is a set of
# branches (`\A\d+\Z|none`, `(?:^|/)x$`); a group matched zero times or more anchors nothing; and a
# lookaround is read as an anchor in the forms `(?=\Z)`, `(?=$)`, `(?=\n?\Z)` (the `$` of re), `(?!.)`
# under DOTALL and a negative lookahead of a class of every character. An anchor in a lookaround or a
# conditional group in another form, inline flags past the start, a group that is not closed, and more
# than `_ANCHOR_WORK` steps for one call leave it undecided, and the call is an unfolded site.
#
# A CALLEE is resolved through the bindings of the scope it is read in, the machinery of the fold
# (`_Module.funktionen`): an import from `re`, an assignment (chained, annotated, a literal tuple, an
# assignment expression), a name bound to such a name, both branches of a conditional, each operand of `or`
# and `and`, a binding through `global` in a function, an attribute of a module-level class or of a class
# it inherits from. A name bound to a function of `re` and, in the same scope, to anything else makes the
# call an unfolded site (lens on ac05d85d; the lens on fb6eda0d planted `global`, `or` and inheritance).
#
# WHAT IT DOES NOT SEE (named limits). `vars(re)[...]`, `importlib.import_module("re")`,
# `re.compile.__call__`, `re` bound to another name by assignment, an instance attribute or a parameter
# bound to a function of `re`, and a function of `re` passed on as a value such as `map(re.compile, ...)`
# or held in a container: none is resolved, and a call through one is not seen. A pattern that reaches `re`
# only through another module's caller is not followed. A compiled pattern is read as a scan and as the
# `match` or `fullmatch` its module takes of the name or attribute it is bound to, or of another name that
# name is bound to, as `R.match`, `re.Pattern.match(R, ...)`, `type(R).match(R, ...)`,
# `R.__class__.match(R, ...)` or `getattr(R, "match")` (a `getattr` by a name the sweep cannot read makes
# it an unfolded site); one that reaches `.match` or `.fullmatch` through a parameter, a container, a loop
# variable, a return value or a pattern type bound to another name is judged by its own anchors.
#
# WHERE IT SWEEPS. Under src/proofbundle, scripts/ and tools/, both readings. The release tools carried
# their own RFC3339 copies with `\d` (audit_candidate_matrix, findings_register, the one of them behind
# `__import__("re")`, which the first form of this sweep did not see; follow-up 235). Four script
# patterns ended in `$` (check_version_and_changelog, codex_threads_check, fork_pr_secret_isolation,
# mutant_signature_guard); each caller was read, none can pass a trailing newline, and each ends in
# `\Z` now, so the change moves no verdict (follow-up 236). Three more ended in `$` inside an alternation
# the first anchor reader did not enter (`_ANFORDERUNGSDATEI` in check_version_and_changelog, the two line
# forms of claims_hygiene_check); their inputs are a `git ls-files` line and lines split at `\n`, and they
# end in `\Z` too (lens on ac05d85d).
#: (module, pattern) pairs this sweep leaves out, each with its reason. agent_review's two patterns were
#: entries here until the owner decision, 2026-09-26; they read ASCII digits now.
_REGEX_EXCEPTIONS = {
    # required_check_reachability_gate reads a GitHub expression, not a schema value. GitHub's lexer skips
    # whitespace with .NET `Char.IsWhiteSpace` (actions/runner at 15231bede4aa,
    # src/Sdk/Expressions/Tokens/LexicalAnalyzer.cs, read 2026-09-26), and that set is Python's `\s` less
    # U+001C..U+001F (25 against 29 code points, measured). ASCII would be further from GitHub, not
    # nearer. The gate reads GitHub expressions with Python's whitespace in many places (patterns with
    # `\s`, folds with `str.split()`), so the fix sits where a condition enters the file: one holding any
    # of U+001C..U+001F is not measurable before a pattern reads it (`fremder_leerraum`, lens 236-B,
    # whose U+001C before `always()` read as a status function). On every condition the gate does read,
    # `\s` is GitHub's set. What GitHub does with such a condition was read in its source
    # (WorkflowTemplateConverter.ConvertToIfCondition, then the lexer), not measured against GitHub.
    # Its `$` follows `\s*`, which takes a trailing newline either way. Its `${{` and `}}` come as a
    # pair since a lens on ac05d85d read `${{ always()`, which GitHub refuses, as a status function,
    # and its names are ASCII classes instead of `re.I`, which folded `faılure()` onto `failure()`.
    ("scripts.required_check_reachability_gate",
     r"^\s*(?:\$\{\{\s*(?:[aA][lL][wW][aA][yY][sS]\(\s*\)|!\s*[cC][aA][nN][cC][eE][lL][lL][eE][dD]\(\s*\))\s*\}\}"
     r"|[aA][lL][wW][aA][yY][sS]\(\s*\)|!\s*[cC][aA][nN][cC][eE][lL][lL][eE][dD]\(\s*\))\s*$"),
    # The release-scope title form, read through its f-strings since the fold reads a placeholder
    # (2026-09-26). Its identifier digits are ASCII now; its `\S` asks that the subject start with a
    # character that is whitespace in no script, and an ASCII class there would accept U+00A0, the
    # separator the gate's own comment refuses. A title, not a schema value.
    ("scripts.b7_release_scope_title_gate",
     r"^\[ *(?P<version>[0-9]+(?:\.[0-9]+)*) +(?P<kennung>[A-Z]\.?-?[A-Z]?[0-9]+(?:[.\-][0-9a-z]+)*) *\]"
     r" +(?P<typ>[a-z][a-z0-9]*)(?:\([^()]+\))?: +\S[^\r\n]*\Z"),
}
#: Every call whose pattern or flags the fold cannot state completely, keyed by (module, enclosing
#: definition, re function, argument form), with how many such calls there are and why none of them is
#: a whole-value pattern the sweep would have to judge. Deny by default: a new unfolded call, or one
#: more under a listed key, turns the sweep red until it is read and listed here. Measured 2026-09-26
#: under src/, scripts/ and tools/: eight calls under six keys, each read in its source. The last two
#: keys are MULTILINE calls, which the sweep left out of this list until review 5 on e176414c.
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
    ("scripts.gen_findings_register", "schneide_beleg", "search", "JoinedStr"): (
        3, "run-time values (the heading level `ebene`, a loop variable, and re.escape of the "
           "identifier) in three MULTILINE searches for a heading or a table row: `^` is a line anchor "
           "there, and they end in a lookahead, a space and a literal `|`, so each judges no whole value"),
    ("scripts.pre_tag_audit_gate", "changelog_section", "compile", "BinOp"): (
        1, "a run-time value (re.escape of the version) in a MULTILINE and DOTALL section search: its "
           "`^` is a line anchor and it ends in a lookahead, not an anchor, so it judges no whole value"),
}
_UNICODE_CLASSES = re.compile(r"\\[dDwWsSbB]")
DOLLAR, UNICODE = "ends in `$`, which matches before a newline", "uses a Unicode class (`\\d` is 0-9 in ECMA-262)"


#: The functions of `re` that take a pattern first, each with the position of its flags argument.
#: `_compile` is the one the others call (review 5 on e176414c planted it past the sweep).
_FLAGS_AT = {"compile": 1, "_compile": 1, "match": 2, "fullmatch": 2, "search": 2, "findall": 2, "finditer": 2,
             "sub": 4, "subn": 4, "split": 3}
#: The flags of `re` by every name it gives them, as ints (NOFLAG exists from Python 3.11 on).
_RE_FLAGS = {name: int(flag) for name, flag in re.RegexFlag.__members__.items()} | {"NOFLAG": 0}
_ALL_FLAGS = functools.reduce(operator.or_, _RE_FLAGS.values(), 0)
#: The attributes of `re` that take no pattern. A call of any OTHER attribute of `re` whose first
#: argument can be a text is a gap: an unknown function is reported, not skipped.
_RE_NO_PATTERN = frozenset({"escape", "purge", "error", "Pattern", "Match", "RegexFlag"} | set(_RE_FLAGS))
_INLINE_FLAGS = {"a": re.A, "i": re.I, "L": re.L, "m": re.M, "s": re.S, "u": re.U, "x": re.X}
#: What a fold step can raise on a value the source states (review 5 on e176414c: `PAT[::0]`,
#: `PATS[1 % 0]`, `"{0.x}".format("a")` and a width of 2**63-1 each raised out of the sweep).
_FOLD_ERRORS = (ArithmeticError, ValueError, TypeError, AttributeError, IndexError, KeyError, MemoryError,
                OverflowError, RecursionError)


def _re_names(tree) -> tuple:
    """The names `re` is bound to in a module (`re` itself and every `import re as x`), and the names a
    `from re import *` binds (what `re.__all__` names). Every other name bound to a function of `re`
    (`from re import compile as c`, `c = re.compile`, ...) is resolved through the bindings of the scope
    it is read in (`_Module.funktionen`).

    Lens 235 (run 1) planted `from re import compile as recompile` with a `\\d` pattern: the first form
    of this sweep read only calls written as an attribute of `re`, and found nothing."""
    names, star = {"re"}, {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {a.asname for a in node.names if a.name == "re" and a.asname}
        elif (isinstance(node, ast.ImportFrom) and node.module == "re" and not node.level
              and any(a.name == "*" for a in node.names)):
            star.update({f: f for f in re.__all__})
    return names, star


def _nennt_re(tree) -> bool:
    """Can a call in this module reach `re`: does it import `re`, name `re`, or call `__import__`?"""
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and any(a.name == "re" for a in node.names):
            return True
        if isinstance(node, ast.ImportFrom) and node.module == "re" and not node.level:
            return True
        if isinstance(node, ast.Name) and node.id in ("re", "__import__"):
            return True
    return False


def _is_re(value, names) -> bool:
    """`re`, an alias of it, or `__import__("re")` (scripts/findings_register.py writes the last one)."""
    if isinstance(value, ast.Name):
        return value.id in names
    return (isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id == "__import__"
            and len(value.args) == 1 and isinstance(value.args[0], ast.Constant) and value.args[0].value == "re")


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


def _pattern_calls(module):
    """(call, attribute of `re`, positional arguments, keywords, doubts) for every call that can reach an
    attribute of `re` in a module, however the module names it (`_Module.funktionen`), once per attribute
    its callee can be; for `functools.partial(re.f, ...)` the arguments the partial binds (235 D-2: the
    partial binds the pattern where it is made). The doubts say where the callee may be something other
    than a function of `re`; each is a gap of the call."""
    modules, partials = _partial_names(module.tree)
    for node in ast.walk(module.tree):
        if not isinstance(node, ast.Call):
            continue
        args = list(node.args)
        functions, doubts = module.funktionen(node.func)
        if not functions and _is_partial(node.func, modules, partials) and args:
            functions, doubts = module.funktionen(args[0])
            args = args[1:]
        for function in sorted(functions):
            yield node, function, args, node.keywords, doubts


def _arguments(function, args, keywords) -> tuple:
    """(pattern, flags, why): the pattern and the flags expression of a call where its signature puts them,
    as the first argument or `pattern=` (a lens of another family planted `re.compile(pattern=...)`), and
    `flags=` or its position; None when absent, and why they cannot be placed when `*` or `**` spreads the
    arguments. The first form of this sweep took every other argument as a flag text, so a replacement
    text or a searched string reading "ASCII" switched the Unicode reading off."""
    named = {k.arg: k.value for k in keywords if k.arg}
    spread = any(isinstance(a, ast.Starred) for a in args) or any(k.arg is None for k in keywords)
    at = _FLAGS_AT[function]
    pattern = args[0] if args and not isinstance(args[0], ast.Starred) else named.get("pattern")
    flags = args[at] if len(args) > at else named.get("flags")
    return pattern, flags, ("arguments spread with * or **" if spread else None)


# ── Where a name is bound: the scopes of a module, read without running it ─────────────────────────

_FUNCTION_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
_NO_SCOPE = {"bound": frozenset(), "global": frozenset(), "nonlocal": frozenset(), "star": ()}
_BOUND_BY = {ast.AugAssign: "an augmented assignment", ast.For: "a for loop", ast.AsyncFor: "a for loop",
             ast.comprehension: "a comprehension", ast.withitem: "a with statement",
             ast.NamedExpr: "an assignment expression", ast.Starred: "a starred target",
             ast.ExceptHandler: "an except clause", ast.arg: "a parameter", ast.MatchAs: "a match pattern",
             ast.MatchStar: "a match pattern", ast.MatchMapping: "a match pattern"}


def _scope_name(scope) -> str:
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return scope.name
    return "a lambda" if isinstance(scope, ast.Lambda) else "a comprehension"


def _children(node, chain) -> list:
    """(child, scopes around it, innermost first) for each child of a node. What a new scope owns gets the
    scope in front; what Python evaluates outside it keeps the chain it had: a function's decorators,
    defaults and annotations, a class's bases, a comprehension's first iterable."""
    if isinstance(node, _FUNCTION_SCOPES):
        a, inner = node.args, (node,) + chain
        params = a.posonlyargs + a.args + a.kwonlyargs + [p for p in (a.vararg, a.kwarg) if p]
        outside = (getattr(node, "decorator_list", []) + a.defaults + [d for d in a.kw_defaults if d]
                   + [p.annotation for p in params if p.annotation]
                   + [r for r in [getattr(node, "returns", None)] if r] + list(getattr(node, "type_params", [])))
        body = node.body if isinstance(node.body, list) else [node.body]
        return [(c, chain) for c in outside] + [(c, inner) for c in params + body]
    if isinstance(node, ast.ClassDef):
        outside = node.decorator_list + node.bases + node.keywords + list(getattr(node, "type_params", []))
        return [(c, chain) for c in outside] + [(c, (node,) + chain) for c in node.body]
    if isinstance(node, _COMPREHENSIONS):
        inner, first = (node,) + chain, node.generators[0]
        owned = [node.key, node.value] if isinstance(node, ast.DictComp) else [node.elt]
        for g in node.generators:
            owned += [g.target] + ([] if g is first else [g.iter]) + g.ifs
        return [(first.iter, chain)] + [(c, inner) for c in owned]
    if isinstance(node, ast.arg):
        return []                    # its annotation was taken with the function, outside its scope
    return [(c, chain) for c in ast.iter_child_nodes(node)]


def _binding(node, up, parent):
    """What one binding gives a name, for the fold: an expression, a class, ("re", attribute) for a name
    imported from `re`, the reason the fold cannot read it, or None when it binds no value (`del`, an
    annotation without a value)."""
    if isinstance(node, ast.ClassDef):
        return node
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return "a function"
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        return ("re", up.name) if isinstance(node, ast.ImportFrom) and node.module == "re" and not node.level \
            else "an imported name"
    if not isinstance(node, ast.Name):
        return f"a name bound by {_BOUND_BY.get(type(node), type(node).__name__)}"
    if isinstance(node.ctx, ast.Del):
        return None
    if isinstance(up, ast.Assign) and any(t is node for t in up.targets):
        return up.value
    if isinstance(up, ast.AnnAssign):
        return up.value
    if isinstance(up, ast.NamedExpr) and up.target is node:
        return up.value
    if isinstance(up, (ast.Tuple, ast.List)):
        assign = parent.get(id(up))
        if (isinstance(assign, ast.Assign) and any(t is up for t in assign.targets)
                and isinstance(assign.value, (ast.Tuple, ast.List)) and len(assign.value.elts) == len(up.elts)
                and not any(isinstance(e, ast.Starred) for e in assign.value.elts + up.elts)):
            return assign.value.elts[next(i for i, e in enumerate(up.elts) if e is node)]
        return "a name bound by unpacking"
    return f"a name bound by {_BOUND_BY.get(type(up), type(up).__name__)}"


class _Global:
    """A module-level name bound through `global` in a function or class body. To the fold it is a
    run-time value (`grund` is the gap); a callee is still followed to what it binds (`eintrag`, as
    `_binding` reads it), since the name reaches that once the function ran. Lens on fb6eda0d: with
    `global c; c = re.compile` in a function and `c(r"\\A\\d+\\Z")` at module level the call was
    not seen at all, a regression against ac05d85d, where such an alias was read."""

    __slots__ = ("grund", "eintrag")

    def __init__(self, grund, eintrag):
        self.grund, self.eintrag = grund, eintrag


def _scopes(tree) -> tuple:
    """One pass over a module, a loop and not recursion (a planted 3000-deep chain is valid source):
    for every node the scopes around it (innermost first) and its parent; for every scope the names it
    binds and the names it declares global or nonlocal; and every binding of a name at module level
    (inside if, for, while, with and try bodies too) or in a class body, with what it binds.

    Review 5 on e176414c planted a parameter and a local of the name of a module constant, `P += ...`,
    a module-level `for P in ...`, `if FLAG: P = ...` and `global P` in a function: the fold read only
    top-level assignments and folded each of these to the module's other value, or not at all."""
    scope_of, parent, info, events = {}, {}, {}, []

    def of(scope):
        return info.setdefault(id(scope), {"bound": set(), "global": set(), "nonlocal": set(), "star": []})

    stack = [(tree, (), None)]
    while stack:
        node, chain, up = stack.pop()
        scope_of[id(node)], parent[id(node)] = chain, up
        owner = chain[0] if chain else tree
        if isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Load):
            if isinstance(up, ast.NamedExpr):         # binds outside every comprehension around it (PEP 572)
                owner = next((s for s in chain if not isinstance(s, _COMPREHENSIONS)), tree)
            events.append((owner, node.id, node, up))
        elif isinstance(node, ast.arg):
            events.append((owner, node.arg, node, up))
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for a in node.names:
                if a.name == "*":
                    of(owner)["star"].append(node.module or ".")
                else:
                    events.append((owner, a.asname or a.name.split(".")[0], node, a))
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            of(owner)["global" if isinstance(node, ast.Global) else "nonlocal"].update(node.names)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            events.append((owner, node.name, node, up))
        elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name:
            events.append((owner, node.name, node, up))
        elif isinstance(node, ast.MatchMapping) and node.rest:
            events.append((owner, node.rest, node, up))
        for child, inner in _children(node, chain):
            stack.append((child, inner, node))
    for owner, name, _node, _up in events:
        of(owner)["bound"].add(name)
    module: dict = {}
    classes: dict = {}
    functions: dict = {}
    for owner, name, node, up in sorted(events, key=lambda e: (getattr(e[2], "lineno", 0),
                                                                getattr(e[2], "col_offset", 0))):
        if owner is not tree and name in of(owner)["global"]:
            if not (isinstance(node, ast.Name) and isinstance(node.ctx, ast.Del)):
                module.setdefault(name, []).append(_Global(
                    f"`{name}` is rebound through `global` in {_scope_name(owner)}", _binding(node, up, parent)))
            continue
        if owner is tree:
            target = module
        elif isinstance(owner, ast.ClassDef):
            target = classes.setdefault(id(owner), {})
        else:
            # A function, lambda or comprehension: its bindings are run-time values to the fold, and what
            # they are bound to is still read, for a name called as a function of `re`. A `nonlocal`
            # binding belongs to the enclosing function that binds the name.
            if name in of(owner)["nonlocal"]:
                chain = scope_of.get(id(node), ())
                at = next((k for k, scope in enumerate(chain) if scope is owner), -1)
                owner = next((scope for scope in chain[at + 1:] if isinstance(scope, _FUNCTION_SCOPES)
                              and name in of(scope)["bound"] and name not in of(scope)["nonlocal"]), owner)
            target = functions.setdefault(id(owner), {})
        entry = _binding(node, up, parent)
        if entry is not None:
            target.setdefault(name, []).append(entry)
    return scope_of, parent, info, module, classes, functions


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


def _wert_schluessel(wert) -> list:
    """The names and attributes a value may be: itself, both branches of a conditional, each operand of
    `or` and `and`, and both sides of an assignment expression. A loop, not recursion: a planted chain of
    conditionals thousands deep is valid source."""
    aus, todo = [], [wert]
    while todo:
        w = todo.pop()
        if isinstance(w, (ast.Name, ast.Attribute)):
            aus.append(_receiver_key(w))
        elif isinstance(w, ast.IfExp):
            todo += [w.body, w.orelse]
        elif isinstance(w, ast.BoolOp):
            todo += w.values
        elif isinstance(w, ast.NamedExpr):
            todo.append(w.value)
            aus.append(_receiver_key(w.target))
    return aus


def _alias_paare(ziel, wert) -> list:
    """(target, source) pairs of names or attributes an assignment binds to one another, literal tuples
    element by element, in a loop."""
    aus, todo = [], [(ziel, wert)]
    while todo:
        z, w = todo.pop()
        if isinstance(z, (ast.Tuple, ast.List)) and isinstance(w, (ast.Tuple, ast.List)) \
                and len(z.elts) == len(w.elts):
            todo += list(zip(z.elts, w.elts))
            continue
        key = _receiver_key(z) if isinstance(z, (ast.Name, ast.Attribute)) else None
        aus += [(key, q) for q in _wert_schluessel(w) if key and q and q != key]
    return aus


def _receiver_key(node):
    """The name or attribute a compiled pattern is read through: `R` for `R`, `rx` for `self.rx`."""
    return node.id if isinstance(node, ast.Name) else node.attr if isinstance(node, ast.Attribute) else None


class _Module:
    """What the sweep reads of one module before it folds anything: the names of `re` and of its
    attributes, the scopes and bindings (`_scopes`), the definition around each node, and the names a
    compiled pattern's `match` or `fullmatch` is called on, as `R.match`, `re.Pattern.match(R, ...)` or
    `getattr(R, "match")` (lens on ac05d85d: the last two were not read); a name an attribute is taken of
    by `getattr` with a name the sweep cannot read is kept apart (`unread_receivers`)."""

    def __init__(self, tree):
        self.tree = tree
        (self.scope_of, self.parent, self.info, self.module_entries, self.class_entries,
         self.function_entries) = _scopes(self.tree)
        self.re_names, self.star = _re_names(self.tree)
        self.where = _definitions(self.tree)
        self.receivers: dict = {}
        self.unread_receivers: set = set()
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Attribute) and node.attr in ("match", "fullmatch"):
                key = _receiver_key(node.value)
                if key:
                    self.receivers.setdefault(key, set()).add(node.attr)
            elif isinstance(node, ast.Call) and node.args:
                taken = self.takes_match(node)
                key = _receiver_key(node.args[0]) if taken else None
                if key and taken[1] is None:
                    self.unread_receivers.add(key)
                elif key:
                    self.receivers.setdefault(key, set()).add(taken[1])
        self._aliases()

    def _aliases(self):
        """A compiled pattern bound to a second name is matched through that one too: the way the second
        name is matched counts for the first, along every assignment of one name or attribute to another
        (both branches of a conditional, each operand of `or` and `and`), until nothing changes. Lens on
        fb6eda0d: `S = R` and `S.match(s)` read `R = re.compile(r"\\d+\\Z")` as a scan."""
        kanten = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Assign):
                ziele, wert = node.targets, node.value
            elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)) and node.value is not None:
                ziele, wert = [node.target], node.value
            else:
                continue
            for ziel in ziele:
                kanten += _alias_paare(ziel, wert)
        geaendert = bool(kanten)
        while geaendert:
            geaendert = False
            for ziel, quelle in kanten:
                neu = self.receivers.get(ziel, set()) - self.receivers.get(quelle, set())
                if neu:
                    self.receivers.setdefault(quelle, set()).update(neu)
                    geaendert = True
                if ziel in self.unread_receivers and quelle not in self.unread_receivers:
                    self.unread_receivers.add(quelle)
                    geaendert = True

    def mustertyp(self, expr) -> bool:
        """Is `expr` the type of a compiled pattern: `re.Pattern` by a name the sweep resolves, `type(R)` or
        `R.__class__`? Lens on fb6eda0d: `type(R).match(R, s)` was read as a scan."""
        if (isinstance(expr, ast.Call) and isinstance(expr.func, ast.Name) and expr.func.id == "type"
                and len(expr.args) == 1):
            return True
        if isinstance(expr, ast.Attribute) and expr.attr == "__class__":
            return True
        return "Pattern" in self.funktionen(expr)[0]

    def takes_match(self, call):
        """(receiver, attribute) when a call takes `match` or `fullmatch` of its first argument: for
        `re.Pattern.match(R, ...)`, `type(R).match(R, ...)`, `getattr(R, "match")` and
        `getattr(type(R), "match")(R, ...)` that attribute, for a `getattr` by a name the sweep cannot
        read None; None when the call takes neither."""
        func = call.func
        if isinstance(func, ast.Name) and func.id == "getattr" and len(call.args) >= 2:
            name = call.args[1]
            if isinstance(name, ast.Constant) and isinstance(name.value, str):
                return (call.args[0], name.value) if name.value in ("match", "fullmatch") else None
            return call.args[0], None
        if isinstance(func, ast.Attribute) and func.attr in ("match", "fullmatch") and self.mustertyp(func.value):
            return call.args[0], func.attr
        if (isinstance(func, ast.Call) and isinstance(func.func, ast.Name) and func.func.id == "getattr"
                and len(func.args) >= 2 and self.mustertyp(func.args[0])):
            name = func.args[1]
            if isinstance(name, ast.Constant) and isinstance(name.value, str):
                return (call.args[0], name.value) if name.value in ("match", "fullmatch") else None
            return call.args[0], None
        return None

    def bindungen(self, ident, chain) -> tuple:
        """(key, bindings) of a name read inside `chain`, found as `resolve` finds them, except that a name
        bound in a function, lambda or comprehension resolves to its bindings there instead of to a
        run-time value: a callee is known where it is bound, whatever scope that is. A star import of `re`
        binds what `re.__all__` names."""
        for i, scope in enumerate(chain):
            info = self.info.get(id(scope), _NO_SCOPE)
            if ident in info["global"]:
                break
            if isinstance(scope, ast.ClassDef):
                if i == 0 and ident in info["bound"]:
                    _key, outside = self.bindungen(ident, chain[1:])
                    return ("class", id(scope), ident), self.class_entries.get(id(scope), {}).get(ident, []) + outside
                continue
            if ident in info["nonlocal"]:
                continue
            if ident in info["bound"]:
                return ("scope", id(scope), ident), list(self.function_entries.get(id(scope), {}).get(ident, []))
        found = list(self.module_entries.get(ident, []))
        if ident in self.star:
            found.append(("re", ident))
        return ("module", ident), found

    def funktionen(self, callee) -> tuple:
        """(the attributes of `re` a callee can be, why it can be something else). Read through the
        bindings of the scope each name is read in (`bindungen`), with a work list, not recursion: an
        attribute of `re` or of `__import__("re")`, `getattr(re, "<literal>")` (`getattr(re, <anything
        else>)` is named as such, a function the sweep cannot tell), a name imported from `re`, a name
        bound to any of these by assignment, chained or annotated, by a literal tuple or an assignment
        expression, a name bound to such a name, both branches of a conditional, and an attribute of a
        module-level class. Lens on ac05d85d: `c = d = re.compile`, `c: object = re.compile`,
        `d = c` after `c = re.compile`, and `c = re.compile if X else re.match` each passed the sweep
        without a reading and without a gap. Any other binding of such a name is a reason; with no
        attribute of `re` found, the callee is not a function of `re`."""
        functions, reasons, seen, todo = set(), [], set(), [callee]
        while todo:
            expr = todo.pop()
            if isinstance(expr, ast.Attribute) and _is_re(expr.value, self.re_names):
                functions.add(expr.attr)
            elif (isinstance(expr, ast.Call) and isinstance(expr.func, ast.Name) and expr.func.id == "getattr"
                    and len(expr.args) >= 2 and _is_re(expr.args[0], self.re_names)):
                name = expr.args[1]
                functions.add(name.value if isinstance(name, ast.Constant) and isinstance(name.value, str)
                              else "getattr(re, ...)")
            elif isinstance(expr, ast.IfExp):
                todo += [expr.body, expr.orelse]
            elif isinstance(expr, ast.BoolOp):
                todo += expr.values                     # `re.compile or None` is one of its operands
            elif isinstance(expr, ast.NamedExpr):
                todo.append(expr.value)
            elif isinstance(expr, (ast.Name, ast.Attribute)):
                if isinstance(expr, ast.Name):
                    key, bindings = self.bindungen(expr.id, self.scope_of.get(id(expr), ()))
                    keys = [(key, bindings, expr.id)]
                elif isinstance(expr.value, ast.Name):
                    _key, owners = self.bindungen(expr.value.id, self.scope_of.get(id(expr.value), ()))
                    classes = [b for b in owners if isinstance(b, ast.ClassDef)]
                    keys = []
                    for c in classes:
                        gefunden, warum = self.klassen_attribut(c, expr.attr)
                        keys += gefunden
                        reasons += warum
                        if not gefunden and not warum:
                            reasons.append(f"`{c.name}.{expr.attr}` is not bound where it is read")
                    if not classes:
                        reasons.append(f"`{_describe(expr)}` is no attribute of a class the sweep reads")
                else:
                    keys = []
                    reasons.append(f"`{_describe(expr)}`")
                for key, bindings, label in keys:
                    if key in seen:
                        continue
                    seen.add(key)
                    for b in bindings:
                        if isinstance(b, _Global):
                            b = b.eintrag
                            if b is None:
                                continue
                        if isinstance(b, tuple):
                            functions.add(b[1])
                        elif isinstance(b, ast.expr):
                            todo.append(b)
                        else:
                            reasons.append(b if isinstance(b, str) else f"`{label}` is bound to a class or an import")
                    if not bindings:
                        reasons.append(f"`{label}` is not bound where it is read")
            else:
                reasons.append(f"`{_describe(expr)}`")
        return functions, [f"the callee may be bound to something other than a function of re: {r}"
                           for r in dict.fromkeys(reasons)] if functions else []

    def klassen_attribut(self, klasse, attr) -> tuple:
        """Where `klasse.attr` is bound: in the class body, else in its bases in turn, as far as each base
        is a class the sweep reads. ((key, bindings, label) per class that binds it, why a base was not
        followed). Lens on fb6eda0d: `L.j(...)` with `class L(K)` and `j = re.compile` in `K` passed the
        sweep, since only the body of `L` was read."""
        gefunden, warum, gesehen, todo = [], [], set(), [klasse]
        while todo:
            k = todo.pop(0)
            if id(k) in gesehen:
                continue
            gesehen.add(id(k))
            eigene = self.class_entries.get(id(k), {}).get(attr)
            if eigene:
                gefunden.append((("class", id(k), attr), eigene, f"{k.name}.{attr}"))
                continue
            for base in k.bases:
                if not isinstance(base, ast.Name):
                    warum.append(f"`{k.name}` inherits from `{_describe(base)}`, which is no class the sweep reads")
                    continue
                _key, owners = self.bindungen(base.id, self.scope_of.get(id(base), ()))
                klassen = [b for b in owners if isinstance(b, ast.ClassDef)]
                todo += klassen
                if not owners or len(klassen) < len(owners):
                    warum.append(f"`{k.name}` inherits from `{base.id}`, which is no class the sweep reads")
        return gefunden, warum

    def resolve(self, ident, chain) -> tuple:
        """(key, bindings) for a name read inside `chain`, as Python resolves it: a parameter or a name bound
        anywhere in an enclosing function, lambda or comprehension is a run-time value (key None, one
        gap); a class body sees its own names (with what lies outside, since the body may read the name
        before binding it) and a function inside it does not; `global` goes to the module."""
        for i, scope in enumerate(chain):
            info = self.info.get(id(scope), _NO_SCOPE)
            if ident in info["global"]:
                break
            if isinstance(scope, ast.ClassDef):
                if i == 0 and ident in info["bound"]:
                    _key, outside = self.resolve(ident, chain[1:])
                    return ("class", id(scope), ident), self.class_entries.get(id(scope), {}).get(ident, []) + outside
                continue
            if ident in info["nonlocal"]:
                continue
            if ident in info["bound"]:
                return None, [f"`{ident}` is bound at run time in {_scope_name(scope)}"]
        found = list(self.module_entries.get(ident, []))
        found += [f"the module star-imports {m}, which can bind `{ident}`" for m in self.info.get(
            id(self.tree), _NO_SCOPE)["star"]]
        return ("module", ident), found or [f"`{ident}` is not bound at module level"]


# ── The fold: every value a pattern or a flags argument can have, as the source states it ──────────

#: How many values one expression may fold to, how large one folded value may grow (characters of a text,
#: elements of a list, summed through what it holds), and how many fold steps one call may take. Past
#: any bound the fold records a gap, it does not cut silently.
_FOLD_CAP = 64
_FOLD_SIZE = 10_000
_FOLD_WORK = 200_000
_FOLD_OPS = {ast.Add: lambda a, b: a + b, ast.Mod: lambda a, b: a % b, ast.Mult: lambda a, b: a * b}
#: A run of five ASCII digits in a `%` format, a width past `_FOLD_SIZE`; `%` refuses any other digit
#: (measured, Python 3.10: `"%\u0664s" % "x"` raises ValueError).
_WIDE_FIELD = re.compile(r"[0-9]{5,}")
_STAR_FIELD = re.compile(r"%[-#0 +]*(?:\*|[0-9]*\.\*)")
_LARGE, _WIDE = "a value larger than _FOLD_SIZE", "a format field wider than _FOLD_SIZE"
_NESTED = "a format field whose spec holds another field, whose width the sweep does not judge"


def _size(value, limit=_FOLD_SIZE) -> int:
    """How much a folded value holds: the characters of a text, about the digits of an int, and one per
    element of a list, tuple or dict plus what the element holds. Counting stops once past `limit`, so a
    value shared a million times over is not walked a million times."""
    total, stack = 0, [value]
    while stack and total <= limit:
        v = stack.pop()
        if isinstance(v, (str, bytes)):
            total += len(v)
        elif isinstance(v, int):
            total += v.bit_length() // 3 + 1
        elif isinstance(v, (list, tuple)):
            total += len(v)
            stack.extend(v[:limit + 1])
        elif isinstance(v, dict):
            total += len(v)
            stack.extend(itertools.islice(v.items(), limit + 1))
        elif isinstance(v, slice):
            total += 1
            stack.extend((v.start, v.stop, v.step))
        else:
            total += 1
    return total


def _text(value) -> str:
    return value.decode("latin-1") if isinstance(value, bytes) else value if isinstance(value, str) else ""


def _walk_values(value):
    """Every value inside a folded value, itself included, without recursion."""
    stack = [value]
    while stack:
        v = stack.pop()
        yield v
        if isinstance(v, (list, tuple)):
            stack.extend(v)
        elif isinstance(v, dict):
            stack.extend(v)
            stack.extend(v.values())


def _wide_argument(value) -> bool:
    """Something in a value that, taken as a width or a precision, asks for a field wider than `_FOLD_SIZE`:
    an int past it, or a text with a run of five digits."""
    return any((isinstance(v, int) and not isinstance(v, bool) and abs(v) > _FOLD_SIZE)
               or (isinstance(v, (str, bytes)) and _WIDE_FIELD.search(_text(v))) for v in _walk_values(value))


def _zu_breit(lauf: str) -> bool:
    """A run of decimal digits, of any script, read as a number past `_FOLD_SIZE` (leading zeros dropped
    first, so a run of any length is judged without building the number)."""
    ziffern = [unicodedata.decimal(z) for z in lauf]
    while ziffern and ziffern[0] == 0:
        ziffern.pop(0)
    return len(ziffern) > len(str(_FOLD_SIZE)) or int("".join(map(str, ziffern)) or "0") > _FOLD_SIZE


def _format_zu_breit(head) -> str | None:
    """Why `head.format(...)` would build a field past `_FOLD_SIZE`, judged on the spec each field gets
    before anything is built; None when none would. `str.format` reads a width in any decimal digit
    (`"{:\u0664}".format("x")` is four wide, measured) and joins a spec from its nested fields
    (`{0:{1}{2}{2}{2}}` with "4" and "000" is 4000000000). Lens on ac05d85d: those two forms, and a width in
    Arabic-Indic digits passed as an argument, each took the process to a peak of about 3840 MiB, since
    the first form of this check looked at ASCII digits in the head alone. A spec holding another field is
    not judged now, it is a gap; any other spec is judged by its runs of digits."""
    try:
        felder = list(string.Formatter().parse(head))
    except ValueError:
        return None                      # `format` raises on the same text before it builds anything
    for _text, _name, spec, _konversion in felder:
        if not spec:
            continue
        if "{" in spec:
            return _NESTED
        laeufe, lauf = [], ""
        for z in spec + " ":
            if z.isdecimal():
                lauf += z
            elif lauf:
                laeufe.append(lauf)
                lauf = ""
        if any(_zu_breit(x) for x in laeufe):
            return _WIDE
    return None


def _too_large(op, a, b):
    """Why `a <op> b` would build a value past `_FOLD_SIZE`, judged before it is built; None when it would
    not. Review 5 on e176414c: fourteen doublings of a list used 2547 MiB, a width passed as an argument
    3841 MiB (both peak memory of the process), and `"%*s"` took its width from the tuple."""
    if op is ast.Add and _size(a) + _size(b) > _FOLD_SIZE:
        return _LARGE
    if op is ast.Mult:
        if isinstance(a, int) and isinstance(b, int):
            return _LARGE if _size(a) + _size(b) > _FOLD_SIZE else None
        for seq, n in ((a, b), (b, a)):
            if isinstance(n, int) and _size(seq) * max(n, 0) > _FOLD_SIZE:
                return _LARGE
    if op is ast.Mod and isinstance(a, (str, bytes)):
        text = _text(a)
        if _WIDE_FIELD.search(text) or (_STAR_FIELD.search(text) and _wide_argument(b)):
            return _WIDE
        return _prozent_zu_gross(a, b)
    return None


def _too_large_call(attr, head, positional, keywords):
    """The same for `head.join(parts)` and `head.format(...)` (`_format_zu_breit`, `_format_zu_gross`)."""
    if attr == "join":
        parts = positional[0] if positional else ()
        count = len(parts) if isinstance(parts, (str, bytes, list, tuple, dict)) else 0
        return _LARGE if _size(parts) + len(head) * count > _FOLD_SIZE else None
    return _format_zu_breit(head) or _format_zu_gross(head, positional, keywords)


def _format_zu_gross(head, positional, keywords):
    """`_LARGE` when `head.format(...)` would build a text past `_FOLD_SIZE`, judged field by field before
    the whole is built; None when it would not, or when `format` raises on it anyway (then the fold step
    raises, and that is a gap). Each field is formatted alone, which `_format_zu_breit` bounds, and the
    sizes are summed until they pass the bound. Lens on fb6eda0d: only widths were judged, so
    `"{0}" * 3333` formatted with a text of 10000 characters, once per value of four, built 33 million
    characters per value and took the process to a peak of 541 MiB."""
    try:
        felder = list(string.Formatter().parse(head))
    except ValueError:
        return None
    gesamt, automatisch = 0, 0
    for literal, name, spec, konversion in felder:
        gesamt += len(literal)
        if name is not None:
            if name == "" or name[0] in ".[":
                name, automatisch = f"{automatisch}{name}", automatisch + 1
            feld = "{" + name + ("!" + konversion if konversion else "") + (":" + spec if spec else "") + "}"
            try:
                gesamt += len(feld.format(*positional, **keywords))
            except _FOLD_ERRORS:
                return None
        if gesamt > _FOLD_SIZE:
            return _LARGE
    return None


def _prozent_felder(text):
    """(literal characters, key or None, flags, width, precision or None, conversion) per conversion of a
    `%` format, as `str.__mod__` reads them, and the literal characters after the last; raises
    ValueError where `%` would (an incomplete format or key)."""
    felder, i, n, literal = [], 0, len(text), 0
    while True:
        j = text.find("%", i)
        if j < 0:
            return felder, literal + n - i
        literal += j - i
        i = j + 1
        key = None
        if i < n and text[i] == "(":
            tiefe, k = 1, i + 1
            while k < n and tiefe:
                tiefe += {"(": 1, ")": -1}.get(text[k], 0)
                k += 1
            if tiefe:
                raise ValueError("incomplete format key")
            key, i = text[i + 1:k - 1], k
        start = i
        while i < n and text[i] in "-+ #0":
            i += 1
        flags = text[start:i]
        start = i
        if i < n and text[i] == "*":
            i += 1
        else:
            while i < n and text[i] in "0123456789":
                i += 1
        width = text[start:i]
        precision = None
        if i < n and text[i] == ".":
            start = i = i + 1
            if i < n and text[i] == "*":
                i += 1
            else:
                while i < n and text[i] in "0123456789":
                    i += 1
            precision = text[start:i]
        while i < n and text[i] in "hlL":
            i += 1
        if i >= n:
            raise ValueError("incomplete format")
        konversion, i = text[i], i + 1
        if konversion == "%" and key is None and not flags and not width and precision is None:
            literal += 1
            continue
        felder.append((literal, key, flags, width, precision, konversion))
        literal = 0


def _prozent_zu_gross(head, arg):
    """`_LARGE` when `head % arg` would build a value past `_FOLD_SIZE`, judged conversion by conversion
    before the whole is built; None when it would not, or when `%` raises on it anyway. A mapping on
    the right repeats a value as often as the format names its key (`"%(a)s" * 2000 % {"a": W}`), the
    same class as the `format` above."""
    try:
        felder, rest = _prozent_felder(_text(head))
    except ValueError:
        return None
    werte = list(arg) if isinstance(arg, tuple) else [arg]
    zuordnung = arg if isinstance(arg, dict) else None
    gesamt, k = rest, 0
    try:
        for literal, key, flags, width, precision, konversion in felder:
            gesamt += literal
            if width == "*":
                width, k = str(int(werte[k])), k + 1
            if precision == "*":
                precision, k = str(int(werte[k])), k + 1
            if key is not None:
                wert = zuordnung[key]
            else:
                wert, k = werte[k], k + 1
            spec = "%" + flags + width + ("." + precision if precision is not None else "") + konversion
            gesamt += len((spec.encode("latin-1") if isinstance(head, bytes) else spec) % (wert,))
            if gesamt > _FOLD_SIZE:
                return _LARGE
    except _FOLD_ERRORS:
        return None
    return None


def _describe(node) -> str:
    """A node as source text for a gap's reason, never an error (unparse recurses, and review 5 on
    e176414c made it raise RecursionError on a flags argument of 400 terms)."""
    try:
        text = ast.unparse(node)
    except Exception:  # noqa: BLE001 - RecursionError and whatever else unparse raises: the reason stays
        return type(node).__name__
    return text if len(text) <= 80 else text[:77] + "..."


class _Fold:
    """Every value an expression can have as the source states it, folded without running the module:
    str, bytes, int, and literal lists, tuples, dicts and slices of them; and every value of a flags
    argument, as ints. One instance folds one call, with its own memo, work budget and gaps.

    Read: literals; an f-string whose placeholders fold to a str or an int (no conversion, no format
    spec); `+`, `%` and `*` between folded values; both branches of a conditional, and every operand of
    `or` and `and`; a name through the scopes around it to every value it is bound to at module level or
    in a class body; an attribute of a class defined at module level, through its class body or the
    bodies of the classes it inherits from; an index or a slice of a folded list, tuple
    or string; `str.join` and `str.format` on folded values, keywords included; for flags, the flags of
    `re` by attribute or imported name, ints made only of flag bits, and `|` and `+` of them. The 228bc
    stack delta planted a conditional, a partial, a name bound twice, bytes, an f-string and `+` (run 1),
    then a class attribute, `%`, `str.join` and a list index (run 2), then `%` with a dict, a slice and
    `format` with keywords (run 3) past a sweep that dropped what it could not fold; review 5 planted an
    int placeholder, shadowing and rebinding, flags read by name, and inputs that raised or ran unbounded.

    DENY BY DEFAULT: every part the fold cannot state is a gap (`self.gaps`), and the values of the other
    parts are still returned. A parameter, a loop variable, a local or a rebound name, a call other than
    `str.join` or `str.format`, an instance attribute or one inherited from a class the sweep does not
    read, a placeholder of another type, flags the sweep does not read, an error a step raises, a fold
    past `_FOLD_CAP` values, a value past `_FOLD_SIZE` (judged before it is built, the result of `%` and
    `str.format` included), or `_FOLD_WORK` steps: each is a gap, and a call with a gap is reported by `_unfolded_pattern_sites`,
    so a form nobody listed turns the sweep red instead of passing it. A name or an attribute is folded
    once per call (a chain of names each doubling the one before took longer than a minute)."""

    def __init__(self, module):
        self.m, self.gaps, self._gapset, self.memo, self.steps = module, [], set(), {}, 0

    def gap(self, reason):
        if reason not in self._gapset:
            self._gapset.add(reason)
            self.gaps.append(reason)

    def charge(self, n=1) -> bool:
        self.steps += n
        if self.steps > _FOLD_WORK:
            self.gap("more than _FOLD_WORK fold steps")
            return False
        return True

    def capped(self, values) -> list:
        if len(values) > _FOLD_CAP:
            self.gap("more than _FOLD_CAP values")
        kept = [v for v in values[:_FOLD_CAP] if _size(v) <= _FOLD_SIZE]
        if len(kept) < len(values[:_FOLD_CAP]):
            self.gap(_LARGE)
        return kept

    def product(self, parts) -> list:
        """Every combination of one value from each part, at most `_FOLD_CAP` of them."""
        if all(len(p) == 1 for p in parts):
            return [[p[0] for p in parts]]
        out = list(itertools.islice(itertools.product(*parts), _FOLD_CAP + 1))
        if len(out) > _FOLD_CAP:
            self.gap("more than _FOLD_CAP values")
        self.charge(len(out))
        return [list(c) for c in out[:_FOLD_CAP]]

    def call(self, node, function, args, keywords):
        """(pattern argument, pattern texts, flag values, ways it is matched) for one call of an attribute
        of `re`, or None for an attribute that takes no pattern."""
        if function in _RE_NO_PATTERN:
            return None
        if function not in _FLAGS_AT:
            first = args[0] if args else next((k.value for k in keywords), None)
            if first is None:
                return None
            before = len(self.gaps)
            texts = any(_holds_text(v) for v in self.values(first))
            if texts or len(self.gaps) > before:
                self.gap(f"`{function}` is an attribute of re the sweep does not read")
            return first, [], {0}, {"search"}
        pattern, flags, why = _arguments(function, args, keywords)
        if why:
            self.gap(why)
        texts = []
        if pattern is None:
            self.gap("no pattern argument the sweep can read")
        else:
            for v in self.values(pattern):
                if isinstance(v, (str, bytes)):
                    texts.append((_text(v), isinstance(v, bytes)))
                else:
                    self.gap(f"a pattern value of type {type(v).__name__}")
        values = {0} if flags is None else self.flags(flags)
        modes, why = _modes(self.m, node, function)
        if why:
            self.gap(why)
        return pattern, texts, values or {0}, modes

    def values(self, expr, seen=frozenset()) -> list:
        if not self.charge():
            return []
        if isinstance(expr, ast.Constant):
            v = expr.value
            if (isinstance(v, (str, bytes, int)) and not isinstance(v, bool)) or v is None:
                return [v]
        elif isinstance(expr, ast.JoinedStr):
            return self._joined(expr, seen)
        elif isinstance(expr, (ast.List, ast.Tuple)):
            combos = self.product([self.values(e, seen) for e in expr.elts])
            return self.capped([tuple(c) if isinstance(expr, ast.Tuple) else c for c in combos])
        elif isinstance(expr, ast.Dict) and None not in expr.keys:
            keys = self.product([self.values(k, seen) for k in expr.keys])
            items = self.product([self.values(v, seen) for v in expr.values])
            return self._each(expr, [(ks, vs) for ks in keys for vs in items][:_FOLD_CAP + 1],
                              lambda kv: dict(zip(*kv)))
        elif isinstance(expr, ast.UnaryOp) and isinstance(expr.op, (ast.USub, ast.UAdd)):
            return [(-v if isinstance(expr.op, ast.USub) else v) for v in self.values(expr.operand, seen)
                    if isinstance(v, int) and not isinstance(v, bool)]
        elif isinstance(expr, ast.Slice):
            ends = [self.values(e, seen) if e is not None else [None] for e in (expr.lower, expr.upper, expr.step)]
            return self.capped([slice(*c) for c in self.product(ends)])
        elif isinstance(expr, ast.BinOp) and type(expr.op) in _FOLD_OPS:
            op, fold = type(expr.op), _FOLD_OPS[type(expr.op)]
            lefts, rights = self.values(expr.left, seen), self.values(expr.right, seen)
            pairs = [(a, b) for a in lefts for b in rights]
            return self._each(expr, pairs, lambda ab: fold(*ab), lambda ab: _too_large(op, *ab))
        elif isinstance(expr, ast.IfExp):
            return self.capped(self.values(expr.body, seen) + self.values(expr.orelse, seen))
        elif isinstance(expr, ast.BoolOp):
            # `a or b` and `a and b` are one of their operands: every operand's values (lens on fb6eda0d)
            return self.capped([v for operand in expr.values for v in self.values(operand, seen)])
        elif isinstance(expr, ast.NamedExpr):
            return self.values(expr.value, seen)
        elif isinstance(expr, ast.Name):
            return self._through(*self.m.resolve(expr.id, self.m.scope_of.get(id(expr), ())), seen)
        elif isinstance(expr, ast.Attribute) and isinstance(expr.value, ast.Name):
            return self._attribute(expr, seen)
        elif isinstance(expr, ast.Subscript):
            containers, indices = self.values(expr.value, seen), self.values(expr.slice, seen)
            pairs = [(c, i) for c in containers for i in indices]
            return self._each(expr, pairs, lambda ci: ci[0][ci[1]])
        elif (isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute)
                and expr.func.attr in ("join", "format") and all(k.arg for k in expr.keywords)):
            return self._join_or_format(expr, seen)
        self.gap(_describe(expr))
        return []

    def _each(self, expr, inputs, step, too_large=lambda _x: None) -> list:
        """One fold step over each input, bounded before it runs and caught if it raises."""
        out = []
        for x in inputs:
            if len(out) > _FOLD_CAP or not self.charge():
                break
            why = too_large(x)
            if why:
                self.gap(why)
                continue
            try:
                out.append(step(x))
            except _FOLD_ERRORS:
                self.gap(_describe(expr))
        return self.capped(out)

    def _joined(self, expr, seen) -> list:
        parts = []
        for v in expr.values:
            if isinstance(v, ast.Constant):
                parts.append([v.value])
            elif isinstance(v, ast.FormattedValue) and v.conversion == -1 and v.format_spec is None:
                texts = []
                for x in self.values(v.value, seen):
                    if isinstance(x, str):
                        texts.append(x)
                    elif isinstance(x, int) and not isinstance(x, bool):
                        try:
                            texts.append(str(x))
                        except ValueError:       # past sys.int_info.default_max_str_digits (3.11+)
                            self.gap(_LARGE)
                    else:
                        self.gap(f"a placeholder of type {type(x).__name__}")
                parts.append(texts)
            else:
                self.gap(_describe(v))
                return []
        return self._each(expr, self.product(parts), "".join,
                          lambda c: _LARGE if sum(map(len, c)) > _FOLD_SIZE else None)

    def _join_or_format(self, expr, seen) -> list:
        attr, names = expr.func.attr, [k.arg for k in expr.keywords]
        arguments = self.product([self.values(a, seen) for a in expr.args]
                                 + [self.values(k.value, seen) for k in expr.keywords])
        calls = []
        for head in self.values(expr.func.value, seen):
            if not isinstance(head, str if attr == "format" else (str, bytes)):
                self.gap(_describe(expr))
                continue
            for args in arguments:
                calls.append((head, args[:len(expr.args)], dict(zip(names, args[len(expr.args):]))))

        def step(call):
            head, positional, keywords = call
            if attr == "join" and len(positional) == 1 and not keywords:
                return head.join(positional[0])
            if attr == "format":
                return head.format(*positional, **keywords)
            raise TypeError(attr)

        return self._each(expr, calls[:_FOLD_CAP + 1], step, lambda c: _too_large_call(attr, *c))

    def _attribute(self, expr, seen) -> list:
        _key, bindings = self.m.resolve(expr.value.id, self.m.scope_of.get(id(expr.value), ()))
        out = []
        for b in bindings:
            if isinstance(b, ast.ClassDef):
                gefunden, warum = self.m.klassen_attribut(b, expr.attr)
                for key, eintraege, _label in gefunden:
                    out += self._through(key, eintraege, seen)
                for grund in warum:
                    self.gap(grund)
                if not gefunden and not warum:
                    self.gap(f"`{b.name}.{expr.attr}` is not bound in the class body")
            elif isinstance(b, _Global):
                self.gap(b.grund)
            else:
                self.gap(b if isinstance(b, str) else f"`{_describe(expr)}` is not a class attribute")
        return self.capped(out)

    def _through(self, key, bindings, seen) -> list:
        """Every value of every binding of a name, once per (name, seen) within one call."""
        if key is not None:
            if key in seen:
                self.gap(f"`{key[-1]}` refers to itself")
                return []
            memo = ("values", key, seen)
            if memo in self.memo:
                return self.memo[memo]
            seen = seen | {key}
        out = []
        for b in bindings:
            if isinstance(b, str):
                self.gap(b)
            elif isinstance(b, _Global):
                self.gap(b.grund)
            elif isinstance(b, ast.expr):
                out += self.values(b, seen)
            else:
                self.gap(f"`{key[-1]}` is bound to a class or an import, not a value")
        out = self.capped(out)
        if key is not None:
            self.memo[memo] = out
        return out

    def flags(self, expr, seen=frozenset()) -> set:
        """Every value a flags argument can have. Review 5 on e176414c: flags were recognised by a
        substring of their source text, so a name `NON_ASCII_INPUT` switched the Unicode reading off and
        `MULTILINE_OFF = 0` left the call out."""
        if not self.charge():
            return set()
        if (isinstance(expr, ast.Constant) and type(expr.value) is int and expr.value >= 0
                and not expr.value & ~_ALL_FLAGS):
            return {expr.value}
        if isinstance(expr, ast.Attribute) and _is_re(expr.value, self.m.re_names) and expr.attr in _RE_FLAGS:
            return {_RE_FLAGS[expr.attr]}
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.BitOr, ast.Add)):
            lefts, rights = self.flags(expr.left, seen), self.flags(expr.right, seen)
            out = {a | b if isinstance(expr.op, ast.BitOr) else a + b for a in lefts for b in rights}
            if any(v & ~_ALL_FLAGS for v in out):
                self.gap(f"flags `{_describe(expr)}` hold a bit re does not define")
            return {v for v in out if not v & ~_ALL_FLAGS}
        if isinstance(expr, ast.IfExp):
            return self.flags(expr.body, seen) | self.flags(expr.orelse, seen)
        if isinstance(expr, ast.BoolOp):
            return set().union(*(self.flags(v, seen) for v in expr.values))
        if isinstance(expr, ast.NamedExpr):
            return self.flags(expr.value, seen)
        if isinstance(expr, ast.Name):
            key, bindings = self.m.resolve(expr.id, self.m.scope_of.get(id(expr), ()))
            if key is not None:
                if key in seen:
                    self.gap(f"`{key[-1]}` refers to itself")
                    return set()
                memo = ("flags", key, seen)
                if memo in self.memo:
                    return self.memo[memo]
                seen = seen | {key}
            out = set()
            for b in bindings:
                if isinstance(b, str):
                    self.gap(b)
                elif isinstance(b, _Global):
                    self.gap(b.grund)
                elif isinstance(b, tuple) and b[1] in _RE_FLAGS:
                    out.add(_RE_FLAGS[b[1]])
                elif isinstance(b, ast.expr):
                    out |= self.flags(b, seen)
                else:
                    self.gap(f"`{expr.id}` is bound to something other than flags of re")
            if key is not None:
                self.memo[memo] = out
            return out
        self.gap(f"flags `{_describe(expr)}` the sweep does not read")
        return set()


def _holds_text(value) -> bool:
    return any(isinstance(v, (str, bytes)) for v in _walk_values(value))


def _modes(module, node, function) -> tuple:
    """(how a call's pattern is matched, why that is not decided): `match` anchors it at the start and
    `fullmatch` at both ends (review 5 on e176414c: `re.match(r"\\d+\\Z", s)` judges a whole value and was
    not read), the rest scan. A compiled pattern is read as a scan and as every one of the two its module
    takes of it, directly, as `re.Pattern.match(R, ...)` or as `getattr(R, "match")`, on the pattern
    itself or on the name or attribute it is bound to (`_Module`). Where the module takes an attribute of
    that name by a name the sweep cannot read, which may be `match`, it is not decided."""
    if function in ("match", "fullmatch"):
        return {function}, None
    if function not in ("compile", "_compile"):
        return {"search"}, None
    up = module.parent.get(id(node))
    if isinstance(up, ast.Attribute) and up.value is node:
        return {"search"} | ({up.attr} & {"match", "fullmatch"}), None
    taken = module.takes_match(up) if isinstance(up, ast.Call) and up.args and up.args[0] is node else None
    if taken:
        return ({"search", taken[1]}, None) if taken[1] else ({"search"}, _UNREAD_RECEIVER)
    targets = (up.targets if isinstance(up, ast.Assign) and up.value is node
               else [up.target] if isinstance(up, (ast.AnnAssign, ast.NamedExpr)) and up.value is node else [])
    keys = {t.id if isinstance(t, ast.Name) else t.attr for t in targets if isinstance(t, (ast.Name, ast.Attribute))}
    return ({"search"}.union(*(module.receivers.get(k, set()) for k in keys)),
            _UNREAD_RECEIVER if keys & module.unread_receivers else None)


_UNREAD_RECEIVER = ("the module takes an attribute of the compiled pattern by a name the sweep cannot read, "
                    "which may be match or fullmatch")


# ── How `re` reads a pattern's anchors ────────────────────────────────────────────────────────────

_GLOBAL_FLAGS = re.compile(r"\(\?([aiLmsux]+)\)")
_SCOPED_FLAGS = re.compile(r"\(\?([aiLmsux]*)(?:-([imsx]+))?:")
_NAMED_GROUP = re.compile(r"\(\?P<[^>]*>")
#: A class that holds every character, in Python's reading and in ECMA-262's.
_ANY_CHARACTER = frozenset({r"[\s\S]", r"[\S\s]", r"[\d\D]", r"[\D\d]", r"[\w\W]", r"[\W\w]"})
#: How many characters and set steps the anchor reader may spend on the patterns of one call. Past it,
#: the call is an unfolded site (lens on fb6eda0d: a pattern of 4257 characters with 100 nested groups
#: and 64 end branches took 51.5 s, since the first reader walked each chain once per branch and level).
_ANCHOR_WORK = 500_000


def _flag_bits(letters) -> int:
    return functools.reduce(operator.or_, (_INLINE_FLAGS[c] for c in letters), 0)


def _stripped(text, verbose) -> str:
    """A pattern without its `(?#...)` comments and, under VERBOSE, without the whitespace and the `#`
    comments outside a character class. A loop over characters, since an escape or a class decides what
    a `#` or a space is."""
    out, i, end, in_class, first = [], 0, len(text), False, 0
    while i < end:
        c = text[i]
        if c == "\\":
            out.append(text[i:i + 2])
            i += 2
            continue
        if in_class:
            in_class = not (c == "]" and i > first)
        elif c == "[":
            in_class, first = True, i + 1 + (text[i + 1:i + 2] == "^")
        elif text.startswith("(?#", i):
            while i < end and text[i] != ")":
                i += 2 if text[i] == "\\" else 1
            i += 1
            continue
        elif verbose and c in " \t\n\r\f\v":
            i += 1
            continue
        elif verbose and c == "#":
            newline = text.find("\n", i)
            i = end if newline < 0 else newline + 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _as_read(pattern, flags) -> tuple:
    """(text, flags) as `re` reads a pattern before its first item: comments removed, the leading inline
    flags `(?aiLmsux)` applied, VERBOSE whitespace and comments removed. Review 5 on e176414c: `(?s)`,
    `(?x)` and a VERBOSE pattern with a trailing comment were not read. A group is read by `_lesung`."""
    text = _stripped(pattern, flags & re.X)
    while (m := _GLOBAL_FLAGS.match(text)):
        flags |= _flag_bits(m.group(1))
        text = text[m.end():]
    if flags & re.X:
        text = _stripped(text, True)
    return text, flags


class _Unentschieden(Exception):
    """An anchor the sweep cannot place: one in a lookaround or a conditional group in a form it does not
    read, inline flags past the start of a pattern, a group or class that is not closed, or more than
    `_ANCHOR_WORK` steps for one call. The call becomes an unfolded site (deny by default)."""


class _Budget:
    """The steps the anchor reader may still spend on the patterns of one call."""

    def __init__(self, most=_ANCHOR_WORK):
        self.left = most

    def charge(self, n=1):
        self.left -= n
        if self.left < 0:
            raise _Unentschieden(f"more than {_ANCHOR_WORK} steps reading the anchors of one call")


# A branch of a pattern is read as (anchored at the start, its end anchor, a Unicode class in it, what is
# not decided); the end anchor is 0 for none, 1 for `$` and 2 for `\Z`, and what is not decided is 1 for
# a start anchor and 2 for an end anchor this reader cannot place. A pattern is read as the set of the
# readings of its branches, at most 48 of them, however many alternatives it has.
_NICHTS = frozenset({(False, 0, False, 0)})
_START = frozenset({(True, 0, False, 0)})
_ENDE_DOLLAR = frozenset({(False, 1, False, 0)})
_ENDE_Z = frozenset({(False, 2, False, 0)})


def _folge(a, b, budget) -> frozenset:
    """The readings of `a` followed by `b`: an anchor on either holds for the sequence."""
    if b == _NICHTS:
        return a
    if a == _NICHTS:
        return b
    budget.charge(len(a) * len(b))
    return frozenset((s1 or s2, max(e1, e2), u1 or u2, x1 | x2)
                     for s1, e1, u1, x1 in a for s2, e2, u2, x2 in b)


def _abseits(a) -> frozenset:
    """The readings of an item off the path: one matched zero times or more, whose anchors need not
    hold; a Unicode class in it still reads a value."""
    return frozenset((False, 0, u, 0) for _s, _e, u, _x in a)


def _wiederholt(a, most, budget) -> frozenset:
    """The readings of an item repeated one to `most` times (None: without bound): each repetition may
    take another branch, and the anchors of all of them hold."""
    out, n = a, 1
    while most is None or n < most:
        more = out | _folge(out, a, budget)
        if more == out:
            break
        out, n = more, n + 1
    return out


def _quantifier(text, i) -> tuple:
    """(least, most or None for no bound, position after it) of the quantifier at `i`, (1, 1, i) for none.
    `{` begins one only as `re` reads it (ASCII digits, a comma, ASCII digits, `}`), and a lazy `?` or a
    possessive `+` after it belongs to it."""
    if i >= len(text):
        return 1, 1, i
    c = text[i]
    if c in "*+?":
        least, most, j = (1 if c == "+" else 0), (1 if c == "?" else None), i + 1
    elif c == "{":
        j = i + 1
        while j < len(text) and text[j] in "0123456789":
            j += 1
        low = text[i + 1:j]
        if j < len(text) and text[j] == ",":
            k = j + 1
            while k < len(text) and text[k] in "0123456789":
                k += 1
            high, j = text[j + 1:k], k
        else:
            high = low
        if j >= len(text) or text[j] != "}" or j == i + 1:
            return 1, 1, i
        least, most, j = int(low or 0), (int(high) if high else None), j + 1
    else:
        return 1, 1, i
    if j < len(text) and text[j] in "?+":
        j += 1
    return least, most, j


def _ueberspringen(text, i) -> int:
    """The position after VERBOSE whitespace and comments at `i`."""
    while i < len(text):
        if text[i] in " \t\n\r\f\v":
            i += 1
        elif text[i] == "#":
            newline = text.find("\n", i)
            i = len(text) if newline < 0 else newline + 1
        else:
            break
    return i


def _klasse(text, i) -> tuple:
    """(position after it, whether it holds a Unicode class) of the character class at `i`; a `]` right
    after `[` or `[^` is a character, and `\\b` inside a class is a backspace, not a boundary."""
    j = i + 1
    if text[j:j + 1] == "^":
        j += 1
    if text[j:j + 1] == "]":
        j += 1
    unicode = False
    while j < len(text):
        c = text[j]
        if c == "\\":
            unicode = unicode or text[j + 1:j + 2] in ("d", "D", "w", "W", "s", "S")
            j += 2
            continue
        if c == "]":
            return j + 1, unicode
        j += 1
    raise _Unentschieden("a character class that is not closed")


def _oeffner(text, i) -> tuple:
    """(kind, flags turned on, flags turned off, where its inside starts) of the group opened at `i`: a
    `gruppe` (plain, non-capturing, named, atomic or with scoped flags), a lookaround (`=`, `!`, `<=`,
    `<!`) or a conditional group (`bedingt`)."""
    if not text.startswith("(?", i):
        return "gruppe", "", "", i + 1
    for anfang, art in (("(?<=", "<="), ("(?<!", "<!"), ("(?=", "="), ("(?!", "!")):
        if text.startswith(anfang, i):
            return art, "", "", i + len(anfang)
    if text.startswith(("(?:", "(?>"), i):
        return "gruppe", "", "", i + 3
    if (m := _NAMED_GROUP.match(text, i)):
        return "gruppe", "", "", m.end()
    if text.startswith("(?(", i):
        ende = text.find(")", i + 3)
        if ende < 0:
            raise _Unentschieden("a conditional group that is not closed")
        return "bedingt", "", "", ende + 1
    if (m := _SCOPED_FLAGS.match(text, i)):
        return "gruppe", m.group(1) or "", m.group(2) or "", m.end()
    if _GLOBAL_FLAGS.match(text, i):
        raise _Unentschieden("inline flags that are not at the start of the pattern")
    raise _Unentschieden("a group the sweep does not read")


class _Rahmen:
    """One group while a pattern is read: its kind, its flags, whether VERBOSE is read in it, and per
    alternative its readings, which anchors stand in it (1 a start anchor, 2 an end anchor), and where it
    starts and ends."""

    __slots__ = ("art", "flags", "verbose", "beginn", "fertig", "laufend", "anker")

    def __init__(self, art, flags, verbose, beginn):
        self.art, self.flags, self.verbose, self.beginn = art, flags, verbose, beginn
        self.fertig, self.laufend, self.anker = [], _NICHTS, 0

    def strich(self, i):
        self.fertig.append((self.laufend, self.anker, self.beginn, i))
        self.laufend, self.anker, self.beginn = _NICHTS, 0, i + 1

    def alternativen(self, i) -> list:
        return self.fertig + [(self.laufend, self.anker, self.beginn, i)]


def _anhaengen(rahmen, menge, text, i, budget) -> int:
    """Append one item's readings, under the quantifier after it, to the alternative being read; returns
    the position after that quantifier. Matched zero times or more, the item is off the path."""
    if rahmen.verbose:
        i = _ueberspringen(text, i)
    least, most, i = _quantifier(text, i)
    if least == 0:
        menge = _abseits(menge)
    elif most is None or most > 1:
        menge = _wiederholt(menge, most, budget)
    rahmen.laufend = _folge(rahmen.laufend, menge, budget)
    return i


def _umschau_anker(art, innen, flags):
    """The readings of a lookaround that is an anchor, or None: `(?=\\Z)` ends the value, `(?=$)` and
    `(?=\\n?\\Z)` end it as `$` does, `(?!.)` under DOTALL and a negative lookahead of a class holding
    every character end it, and their mirrors, and `(?=\\A)`, start it."""
    zeilen = flags & re.M
    if art == "=":
        if innen == r"\Z":
            return _ENDE_Z
        if innen in (r"\n?\Z", r"(?:\n)?\Z") or (innen == "$" and not zeilen):
            return _ENDE_DOLLAR
    if art in ("=", "<=") and (innen == r"\A" or (innen == "^" and not zeilen)):
        return _START
    if art in ("!", "<!") and ((innen == "." and flags & re.S) or innen in _ANY_CHARACTER):
        return _START if art == "<!" else _ENDE_Z
    return None


def _umschau_lesung(rahmen, menge, anker, innen) -> frozenset:
    """The readings of one lookaround alternative: its anchor when it is one, not decided when an anchor
    stands in it in another form, and off the path otherwise."""
    if rahmen.verbose:
        innen = _stripped(innen, True)
    erkannt = _umschau_anker(rahmen.art, innen, rahmen.flags)
    if erkannt is not None:
        return erkannt
    if anker:
        return frozenset({(False, 0, any(u for _s, _e, u, _x in menge), anker)})
    return _abseits(menge)


def _schliessen(rahmen, i, text, budget) -> frozenset:
    """The readings of the group closed at `i`. A positive lookaround is read per alternative (one of
    `(?=\\s|$)` ends the value like `$`); a negative one and a conditional group as a whole."""
    alternativen = rahmen.alternativen(i)
    koerper = frozenset().union(*(m for m, _a, _b, _e in alternativen))
    budget.charge(len(koerper) + len(alternativen))
    if rahmen.art == "gruppe":
        return koerper
    anker = functools.reduce(operator.or_, (a for _m, a, _b, _e in alternativen), 0)
    if rahmen.art in ("=", "<="):
        return frozenset().union(*(_umschau_lesung(rahmen, m, a, text[b:e]) for m, a, b, e in alternativen))
    if rahmen.art in ("!", "<!"):
        return _umschau_lesung(rahmen, koerper, anker, text[alternativen[0][2]:i])
    return frozenset({(False, 0, any(u for _s, _e, u, _x in koerper), anker)}) if anker else _abseits(koerper)


def _lesung(text, is_bytes, flags, budget) -> frozenset:
    """The readings of the branches of a pattern `_as_read` has read the start of. One pass with a stack
    of groups, not recursion (a planted pattern nests groups thousands deep), so its cost is linear in
    the pattern and bounded by `budget`.

    An anchor counts where it stands on the pattern's own path: at its top level, or in a group there
    that is matched at least once (a plain, non-capturing, named, atomic or flag group, quantified or
    not). Every item after `\\Z` can only match the empty text at the end, and every item before `\\A`
    the empty text at the start, so the anchor holds wherever it stands on that path. The first reader
    looked only at the first and the last item (lens on fb6eda0d: `\\A\\d+\\Z()` and
    `(?:\\A\\d+){1}\\Z` read as not anchored) and never split an alternation at the top level
    (`\\A\\d+\\Z|none`, `n/a|^[0-9]+$`). An alternation is a set of branches, a repeated group combines
    the branches of its repetitions, and a group matched zero times or more, a lookaround and a
    conditional group are off the path; a lookaround that is an anchor is read as one (`(?=\\n?\\Z)`
    like `$`, `(?!.)` under DOTALL like `\\Z`), and one holding an anchor in another form leaves its
    branch undecided. `^` and `$` under MULTILINE are line anchors, never the value's. A Unicode class
    counts under the flags of the group it stands in, so `(?a:\\d)` reads ASCII."""
    budget.charge(len(text))
    stapel = [_Rahmen("gruppe", flags, False, 0)]
    i, n = 0, len(text)
    while i < n:
        budget.charge()
        rahmen = stapel[-1]
        c = text[i]
        if rahmen.verbose and (c in " \t\n\r\f\v" or c == "#"):
            i = _ueberspringen(text, i)
            continue
        if c == "\\":
            zeichen = text[i + 1:i + 2]
            if zeichen == "A":
                rahmen.anker, menge = rahmen.anker | 1, _START
            elif zeichen == "Z":
                rahmen.anker, menge = rahmen.anker | 2, _ENDE_Z
            elif zeichen in ("d", "D", "w", "W", "s", "S", "b", "B"):
                menge = frozenset({(False, 0, not rahmen.flags & re.A and not is_bytes, False)})
            else:
                menge = _NICHTS
            i = _anhaengen(rahmen, menge, text, i + 2, budget)
        elif c == "[":
            j, unicode = _klasse(text, i)
            budget.charge(j - i)
            menge = frozenset({(False, 0, unicode and not rahmen.flags & re.A and not is_bytes, False)})
            i = _anhaengen(rahmen, menge, text, j, budget)
        elif c == "(" and text.startswith(("(?#", "(?P="), i):
            ende = text.find(")", i)
            if ende < 0:
                raise _Unentschieden("a comment or back reference that is not closed")
            i = ende + 1 if text.startswith("(?#", i) else _anhaengen(rahmen, _NICHTS, text, ende + 1, budget)
        elif c == "(":
            art, an, aus, j = _oeffner(text, i)
            innen = (rahmen.flags | _flag_bits(an)) & ~_flag_bits(aus)
            stapel.append(_Rahmen(art, innen, (rahmen.verbose or "x" in an) and "x" not in aus, j))
            i = j
        elif c == ")":
            if len(stapel) == 1:
                raise _Unentschieden("a `)` that closes no group")
            gruppe = stapel.pop()
            for _m, anker, _b, _e in gruppe.alternativen(i):
                stapel[-1].anker |= anker
            i = _anhaengen(stapel[-1], _schliessen(gruppe, i, text, budget), text, i + 1, budget)
        elif c == "|":
            rahmen.strich(i)
            i += 1
        elif c in "^$" and not rahmen.flags & re.M:
            rahmen.anker |= 1 if c == "^" else 2
            i = _anhaengen(rahmen, _START if c == "^" else _ENDE_DOLLAR, text, i + 1, budget)
        else:
            i = _anhaengen(rahmen, _NICHTS, text, i + 1, budget)
    if len(stapel) != 1:
        raise _Unentschieden("a group that is not closed")
    return frozenset().union(*(m for m, _a, _b, _e in stapel[0].alternativen(n)))


def _menge(pattern, is_bytes, flags, budget) -> frozenset:
    """The readings of a pattern's branches under these flags (`_as_read`, then `_lesung`)."""
    budget.charge(len(pattern))
    text, flags = _as_read(pattern, flags)
    return _lesung(text, is_bytes, flags, budget)


def _aus_menge(menge, mode) -> list:
    """How a pattern whose branches read as `menge`, matched this way (`search`, `match`, `fullmatch`),
    reads a whole value differently from ECMA-262; empty when it judges no whole value. A branch judges
    a whole value when it is anchored at the start (`match` anchors it there by itself) and at the end;
    `fullmatch` judges the whole value in every branch. `$` lets a trailing newline through only where
    the match may end before it, not under fullmatch; a bytes pattern's `\\d` is ASCII in Python too.
    Under MULTILINE `^` and `$` are line anchors, and `\\A`, `\\Z`, `match` and `fullmatch` still judge
    the whole value (review 5 on e176414c). Raises _Unentschieden where a branch is not decided."""
    if mode == "fullmatch":
        passend = [(2, u) for _s, _e, u, _x in menge]
    else:
        for s, e, _u, x in menge:
            # an anchor that is not placed decides only a branch the other anchor could complete
            if x and (s or mode == "match" or x & 1) and (e or x & 2):
                raise _Unentschieden("an anchor in a lookaround or a conditional group in a form the sweep "
                                     "does not place")
        passend = [(e, u) for s, e, u, _x in menge if e and (mode == "match" or s)]
    readings = []
    if any(e == 1 for e, _u in passend):
        readings.append(DOLLAR)
    if any(u for _e, u in passend):
        readings.append(UNICODE)
    return readings


def _readings(pattern, is_bytes, flags, mode, budget=None) -> list:
    """How a pattern read with these flags and matched this way reads a whole value differently from
    ECMA-262 (`_menge`, `_aus_menge`); raises _Unentschieden where that is not decided."""
    return _aus_menge(_menge(pattern, is_bytes, flags, budget or _Budget()), mode)


_Call = collections.namedtuple("_Call", "mod module node function arg texts flags modes gaps readings")


def _calls(sources):
    """One `_Call` per call of an attribute of `re` that can take a pattern, in (module, source) pairs (the
    source as bytes or as text; `ast.parse` reads bytes as Python reads a file): its pattern texts, flag
    values and ways of matching, the gaps of its fold, of its callee (`_Module.funktionen`) and of its
    anchors (`_Unentschieden`), and its readings, one per pattern, flags and way of matching that is
    decided. A call nested deeper than the interpreter recurses is a gap, not an error that ends the
    sweep (the third delta run on 9aaa79c0 planted 3000 `+` in a row; review 5 on e176414c 400 terms of
    flags). The anchors of all the patterns of one call share one `_Budget`, and each pattern is read
    once per flags value, whatever the ways of matching."""
    for mod, text in sources:
        tree = ast.parse(text)
        if not _nennt_re(tree):
            continue                                    # no call in it can reach `re`
        module = _Module(tree)
        for node, function, args, keywords, doubts in _pattern_calls(module):
            fold = _Fold(module)
            for doubt in doubts:
                fold.gap(doubt)
            try:
                read = fold.call(node, function, args, keywords)
            except RecursionError:
                fold.gap("nested deeper than the interpreter's recursion limit")
                read = (args[0] if args else None), [], {0}, {"search"}
            if read is None:
                continue
            budget, mengen, readings = _Budget(), {}, {}
            for pattern, is_bytes in read[1]:
                for flags in read[2]:
                    key = (pattern, is_bytes, flags)
                    if key not in mengen:
                        try:
                            mengen[key] = _menge(pattern, is_bytes, flags, budget)
                        except _Unentschieden as exc:
                            mengen[key] = None
                            fold.gap(str(exc))
                    if mengen[key] is None:
                        continue
                    for mode in read[3]:
                        try:
                            readings[key + (mode,)] = _aus_menge(mengen[key], mode)
                        except _Unentschieden as exc:
                            fold.gap(str(exc))
            yield _Call(mod, module, node, function, *read, fold.gaps, readings)


def _whole_value_regex_readings(sources) -> list:
    """(module, source) pairs in; one (module, line, pattern, reading) per whole-value pattern read
    differently from ECMA-262, under every flag value its call can pass and in every way it is matched,
    the named exceptions left out."""
    found = []
    for call in _calls(sources):
        seen = set()
        for pattern, is_bytes in call.texts:
            if (call.mod, pattern) in _REGEX_EXCEPTIONS:
                continue
            for flags in sorted(call.flags):
                for mode in sorted(call.modes):
                    readings = call.readings.get((pattern, is_bytes, flags, mode))
                    if readings is None:
                        continue                        # a gap of the call, listed by `_unfolded_pattern_sites`
                    for reading in readings:
                        if (pattern, reading) not in seen:
                            seen.add((pattern, reading))
                            found.append((call.mod, call.node.lineno, pattern, reading))
    return found


def _unfolded_pattern_sites(sources) -> dict:
    """(module, enclosing definition, re function, argument form) -> the gaps of each such call, for every
    call of an attribute of `re` that can take a pattern and whose pattern or flags the fold cannot
    state completely, MULTILINE calls included. The argument form is the node type (and a name's
    identifier), so the key does not depend on how one Python version unparses an f-string."""
    sites: dict = {}
    for call in _calls(sources):
        if call.gaps:
            arg = call.arg
            form = "none" if arg is None else f"Name {arg.id}" if isinstance(arg, ast.Name) else type(arg).__name__
            where = call.module.where.get(id(call.node), "<module>")
            sites.setdefault((call.mod, where, call.function, form), []).append(call.gaps)
    return sites


def _whole_value_regex_findings(sources) -> list:
    return [f"{mod}:{line} {pattern!r} {reading}" for mod, line, pattern, reading in
            _whole_value_regex_readings(sources)]


def _modules(root: str):
    """(module, source) under `root`, the source as bytes: `ast.parse` then reads it as Python does, a UTF-8
    BOM and a coding cookie included (lens on ac05d85d: a script saved with a BOM, which Python runs, raised
    `SyntaxError: invalid non-printable character U+FEFF` out of the sweep when it was read as text)."""
    base = REPO / root
    for path in sorted(base.rglob("*.py")):
        rel = path.relative_to(REPO / "src" if root.startswith("src") else REPO).with_suffix("")
        yield rel.as_posix().replace("/", ".").removesuffix(".__init__"), path.read_bytes()


def _tree():
    yield from _modules("src/proofbundle")


def _tree_outside_src():
    yield from _modules("scripts")
    yield from _modules("tools")


class EveryWholeValuePatternReadsAsTheSchemaDoes(unittest.TestCase):

    def test_no_pattern_under_src_reads_a_value_differently(self):
        self.assertEqual(_whole_value_regex_findings(_tree()), [])

    def test_no_pattern_under_scripts_or_tools_reads_a_value_differently(self):
        self.assertEqual(_whole_value_regex_findings(_tree_outside_src()), [])

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
        `r"\\A\\d+\\Z" * 100000000` folded to a text of 700,000,000 characters (0.65 GiB) for one call,
        which raised the peak memory of the process by 2.51 GiB (both measured on 9aaa79c0, the second
        again on 2026-09-26). Each is a gap now: reported as unfolded, not read, not raised."""
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
                folded = {p for call in _calls([(mod, text[mod])]) for p, _b in call.texts}
                self.assertIn(pattern, folded)


#: The child that runs the sweep over review 5's inputs: its own process, so that a peak of memory is
#: measured and a run that does not end is ended. Its address space is capped, so an unbounded fold
#: raises MemoryError instead of taking the host with it.
_BOUNDED_CHILD = r'''
import importlib.util, json, pathlib, resource, sys, time
try:
    resource.setrlimit(resource.RLIMIT_AS, (2 << 30, 2 << 30))
except (ValueError, OSError):
    pass
path, inputs = sys.argv[1], json.load(sys.stdin)
sys.path.insert(0, str(pathlib.Path(path).parent))
spec = importlib.util.spec_from_file_location("_sweep_under_test", path)
sweep = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sweep)
out = {}
for name, source in inputs.items():
    t0 = time.monotonic()
    try:
        sites = sweep._unfolded_pattern_sites([("scripts.planted", source)])
        readings = sweep._whole_value_regex_readings([("scripts.planted", source)])
        out[name] = {"seconds": time.monotonic() - t0, "readings": len(readings),
                     "gaps": sorted({g for calls in sites.values() for gaps in calls for g in gaps})}
    except BaseException as exc:
        out[name] = {"seconds": time.monotonic() - t0, "raised": type(exc).__name__}
peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
out["_peak_bytes"] = peak if sys.platform == "darwin" else peak * 1024
print(json.dumps(out))
'''


class TheSweepResolvesScopesFlagsAndStaysBounded(unittest.TestCase):
    """Review 5 on e176414c planted each form below past the sweep; every counter-example was planted, none
    was live in the tree. Each case was measured on e176414c before it was fixed, and fails there."""

    @staticmethod
    def _lines(planted):
        return sorted(line for _mod, line, _p, _r in _whole_value_regex_readings([("scripts.planted", planted)]))

    @staticmethod
    def _sites(planted):
        return sorted((where, function, form, len(calls)) for (_mod, where, function, form), calls
                      in _unfolded_pattern_sites([("scripts.planted", planted)]).items())

    def test_an_int_placeholder_is_folded_and_any_other_type_is_a_gap(self):
        """`rf"\\A\\d{{{N}}}\\Z"` with `N = 4` passed without a reading and without a gap: the fold kept
        the str values of a placeholder and dropped the rest. An int is formatted with str() now, and a
        placeholder of any other type is a gap."""
        planted = ('import re\nN = 4\nA = re.compile(rf"\\A\\d{{{N}}}\\Z")\n'
                   'W = None\nB = re.compile(rf"\\A[0-9]{{{W}}}\\Z")\n'
                   'C = re.compile(rf"\\A[0-9]{{{N}}}\\Z")\n')
        self.assertEqual(self._lines(planted), [3])
        self.assertEqual(self._sites(planted), [("<module>", "compile", "JoinedStr", 1)])

    def test_a_name_is_read_in_the_scope_that_binds_it(self):
        """A parameter, a local, a lambda parameter and a comprehension variable named like a module
        constant were each folded to the constant's value. Each is a run-time value now; a function that
        reads the module name, or declares it global, still folds it."""
        planted = ('import re\nP = r"\\A\\d+\\Z"\n'
                   'def f(P=r"\\A[0-9]+\\Z"):\n    return re.compile(P)\n'
                   'def g():\n    P = r"\\A[0-9]+\\Z"\n    return re.compile(P)\n'
                   'h = lambda P: re.compile(P)\n'
                   'I = [re.compile(P) for P in (r"\\A[0-9]+\\Z",)]\n'
                   'def j():\n    return re.compile(P)\n'
                   'def k():\n    global P\n    return re.compile(P)\n')
        self.assertEqual(self._lines(planted), [11, 14])
        self.assertEqual(self._sites(planted), [("<module>", "compile", "Name P", 2),
                                                ("f", "compile", "Name P", 1), ("g", "compile", "Name P", 1)])

    def test_every_binding_of_a_module_name_is_folded_or_a_gap(self):
        """The fold read top-level assignments only. A binding inside `if` or `try` and a tuple unpacking
        of literals are folded now; `+=`, a module-level `for` and a `global` rebinding from a function
        are gaps (the clean first value of each would otherwise have passed alone)."""
        planted = ('import re\nA = r"\\A[0-9]+\\Z"\nif FLAG:\n    A = r"\\A\\d+\\Z"\nRA = re.compile(A)\n'
                   'B = r"\\A[0-9]"\nB += r"+\\Z"\nRB = re.compile(B)\n'
                   'C = r"\\A[0-9]+\\Z"\nfor C in (r"\\A\\d+\\Z",):\n    pass\nRC = re.compile(C)\n'
                   'D = r"\\A[0-9]+\\Z"\ndef rebind():\n    global D\n    D = r"\\A\\d+\\Z"\nRD = re.compile(D)\n'
                   'E, F = r"\\A\\d+\\Z", r"\\A[0-9]+\\Z"\nRE_ = re.compile(E)\nRF = re.compile(F)\n'
                   'try:\n    G = r"\\A\\d+\\Z"\nexcept ImportError:\n    G = r"\\A[0-9]+\\Z"\nRG = re.compile(G)\n')
        self.assertEqual(self._lines(planted), [5, 19, 25])
        self.assertEqual(self._sites(planted), [("<module>", "compile", "Name B", 1),
                                                ("<module>", "compile", "Name C", 1),
                                                ("<module>", "compile", "Name D", 1)])

    def test_match_anchors_at_the_start_by_itself(self):
        """`re.match(r"\\d+\\Z", s)` judges a whole value and was not read, since only `^` and `\\A` counted
        as a start. `match` counts now, for `re.match` and for a compiled pattern whose `match` or
        `fullmatch` its module calls, directly or through the name or attribute it is bound to; a search
        with the same pattern still judges no whole value."""
        planted = ('import re\nA = re.match(r"\\d+\\Z", s)\nB = re.match(r"[0-9]+$", s)\n'
                   'C = re.search(r"\\d+\\Z", s)\nR = re.compile(r"\\d+\\Z")\nM = R.match(s)\n'
                   'F = re.compile(r"\\d+").fullmatch(s)\n'
                   'class K:\n    def __init__(self):\n        self.rx = re.compile(r"\\d{4}\\Z")\n'
                   '    def ok(self, s):\n        return self.rx.match(s)\n'
                   'N = re.compile(r"\\d+\\Z").search(s)\n')
        self.assertEqual(self._lines(planted), [2, 3, 5, 7, 10])

    def test_multiline_leaves_a_whole_value_whole(self):
        """Every MULTILINE call was left out, and an unfoldable one was not even listed. Under MULTILINE
        only `^` and `$` are line anchors: `\\A..\\Z`, `match` with `\\Z` and fullmatch still judge a whole
        value, and a MULTILINE call the fold cannot state is an unfolded site."""
        planted = ('import re\nA = re.compile(r"\\A\\d+\\Z", re.M)\nB = re.fullmatch(r"\\d+", s, re.MULTILINE)\n'
                   'C = re.search(r"^\\d+$", s, re.M)\nD = re.match(r"\\d+\\Z", s, flags=re.M)\n'
                   'E = re.compile(r"(?m)^\\d+$")\nF = re.compile(r"(?m)\\A[0-9]+$")\n'
                   'def f(p):\n    return re.search(p, s, re.M)\n')
        self.assertEqual(self._lines(planted), [2, 3, 5])
        self.assertEqual(self._sites(planted), [("f", "search", "Name p", 1)])

    def test_inline_flags_groups_comments_and_verbose_are_read_through(self):
        """`(?s)\\A\\d+\\Z`, `(?:\\A\\d+\\Z)` and a VERBOSE pattern with a trailing comment were not seen as
        anchored. The leading flags are applied (`a` reads ASCII, also scoped as `(?a:..)`), a group
        around the whole pattern is looked through, and comments and VERBOSE whitespace are removed. An
        escaped `\\$` is a character, not an anchor, and was read as one."""
        planted = ('import re\nA = re.compile(r"(?s)\\A\\d+\\Z")\nB = re.compile(r"(?:\\A\\d+\\Z)")\n'
                   'C = re.compile("\\\\A \\\\d+ \\\\Z   # digits\\n", re.X)\n'
                   'D = re.compile(r"(?x) \\A \\d+ \\Z  # trailing")\n'
                   'E = re.compile(r"(?a)\\A\\d+\\Z")\nF = re.compile(r"(?a:\\A\\d+\\Z)")\n'
                   'G = re.compile(r"\\A\\d+\\$")\nI = re.compile(r"(?P<v>\\A\\d+\\Z)")\n'
                   'J = re.compile(r"\\A\\d+\\Z(?#end)")\n')
        self.assertEqual(self._lines(planted), [2, 3, 4, 5, 9, 10])

    def test_flags_are_read_as_flags_of_re_not_by_their_name(self):
        """A name containing ASCII switched the Unicode reading off, a name containing MULTILINE left the
        call out, and every other argument (a replacement text "ASCII" included) was read as a flag. Flags
        are the flags of `re` now, by attribute or imported name, ints of flag bits and `|` of them, in
        the flags position only; anything else there is a gap, and the pattern is still read as if no
        flag were set."""
        planted = ('import re\nNON_ASCII_INPUT = 0\nA = re.compile(r"\\A\\d+\\Z", NON_ASCII_INPUT)\n'
                   'MULTILINE_OFF = 0\nB = re.compile(r"^\\d+$", MULTILINE_OFF)\n'
                   'C = re.sub(r"\\A\\d+\\Z", "ASCII", s)\nFLAGS = re.A | re.I\n'
                   'D = re.compile(r"\\A\\d+\\Z", FLAGS)\nfrom re import ASCII as ASC\n'
                   'E = re.compile(r"\\A\\d+\\Z", ASC)\nF = re.compile(r"\\A\\d+\\Z", 256)\n'
                   'def g(flags):\n    return re.compile(r"\\A\\d+\\Z", flags)\n'
                   'H = re.compile(r"\\A[0-9]+\\Z", re.IGNORECASE | re.M)\n')
        self.assertEqual(self._lines(planted), [3, 5, 5, 6, 13])
        self.assertEqual(self._sites(planted), [("g", "compile", "Constant", 1)])

    def test_every_function_of_re_that_can_take_a_pattern_is_read(self):
        """`re._compile(p)` with a pattern the fold cannot state was skipped, as was any other function
        of `re` outside the list; `re.escape` was read as a pattern. `_compile` is read now, a call of any
        other attribute of `re` whose first argument can be a text is a gap, and `escape`, `purge`, the
        flags and the types take no pattern."""
        planted = ('import re\ndef f(p):\n    return re._compile(p, 0)\ndef g(p):\n    return re.template(p)\n'
                   'A = re.escape(r"\\A\\d+\\Z")\nB = re._compile(r"\\A\\d+\\Z", 0)\nC = re.purge()\n'
                   'D = re.Scanner([(r"\\A\\d+\\Z", None)])\n')
        self.assertEqual(self._lines(planted), [7])
        self.assertEqual(self._sites(planted), [("<module>", "Scanner", "List", 1),
                                                ("f", "_compile", "Name p", 1), ("g", "template", "Name p", 1)])

    def test_the_review_inputs_neither_raise_nor_run_unbounded(self):
        """Measured on e176414c: 400 terms of flags raised RecursionError (from ast.unparse of the flags);
        `PAT[::0]`, `PATS[1 % 0]` and `"{0.x}".format("a")` raised ValueError, ZeroDivisionError and
        AttributeError, and a width of 2**63-1 passed as an argument MemoryError; a width of 4000000000
        passed as an argument took the process to a peak of 3841 MiB, fourteen doublings of a list to
        2547 MiB in 14.9 s, and a chain of forty names each doubling the one before, and twelve levels of
        `V + (V + (V + V))`, each ran past a minute. Now every input is read without an exception, each
        gap is an unfolded site, the two chains fold to their one reading, fifty sums of 64 x 64 texts
        run out of the work budget, and the child stays under 10 s per input and 500 MB of peak memory
        (measured after the fix, 2026-09-26: each input under 0.6 s, a peak of 57 MB). The lens on ac05d85d
        added three widths that each took the process to about 3840 MiB: 4000000000 joined from nested
        fields, and 4000000000 in Arabic-Indic digits in the head and as an argument. Each is a gap now,
        judged before anything is built (measured 2026-09-27 over all sixteen inputs: each under 0.4 s, a
        peak of 63 MB)."""
        chain = 'import re\nP0 = ""\n' + "".join(f"P{i} = P{i - 1} + P{i - 1}\n" for i in range(1, 41))
        nested = 'import re\nV0 = ""\n' + "".join(f"V{i} = V{i - 1} + (V{i - 1} + (V{i - 1} + V{i - 1}))\n"
                                                  for i in range(1, 13))
        doubling = "".join(f"L{i} = L{i - 1} + L{i - 1}\n" for i in range(1, 15))
        arabisch = "\u0664" + "\u0660" * 9                  # four billion in Arabic-Indic digits
        inputs = {
            "400 terms of flags": "import re\nA = re.compile(r'\\A[0-9]+\\Z', " + " + ".join(["0"] * 400) + ")\n",
            "3000 terms of flags": "import re\nA = re.compile(r'\\A[0-9]+\\Z', " + " + ".join(["0"] * 3000) + ")\n",
            "a slice step of zero": 'import re\nPAT = r"\\A\\d+\\Z"\nA = re.compile(PAT[::0])\n',
            "an index divided by zero": 'import re\nPATS = [r"\\A\\d+\\Z"]\nA = re.compile(PATS[1 % 0])\n',
            "an attribute in a format field": 'import re\nA = re.compile("{0.x}".format("a"))\n',
            "a width of 2**63-1 as an argument":
                'import re\nA = re.compile("{0:{1}}".format("a", 9223372036854775807))\n',
            "a width of 4000000000 as an argument":
                'import re\nP = r"\\A\\d+\\Z"\nA = re.compile("{0:{1}}".format(P, 4000000000))\n',
            "a star width of 100000000": 'import re\nA = re.compile("%*s" % (100000000, "x"))\n',
            "fourteen doublings of a list":
                'import re\nL0 = [r"\\A\\d+\\Z"] * 10000\n' + doubling + "A = re.compile(L14[0])\n",
            "thirty doublings from one element": 'import re\nL0 = [r"\\A\\d+\\Z"]\n' + "".join(
                f"L{i} = L{i - 1} + L{i - 1}\n" for i in range(1, 31)) + "A = re.compile(L30[0])\n",
            "fifty sums of sixty-four texts": 'import re\n' + "".join(
                f'W = "{c}" * 9000\n' for c in "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+-")
                + "".join(f"X{i} = W + W\n" for i in range(50))
                + "A = re.compile(" + " + ".join(f"X{i}" for i in range(50)) + ")\n",
            "forty names each doubling the one before": chain + 'A = re.compile(r"\\A\\d+\\Z" + P40)\n',
            "twelve levels of V + (V + (V + V))": nested + 'A = re.compile(r"\\A\\d+\\Z" + V12)\n',
            # the lens on ac05d85d: each of these three took the process to a peak of about 3840 MiB
            "a width of 4000000000 joined from nested fields":
                'import re\nP = r"\\A\\d+\\Z"\nA = re.compile("{0:{1}{2}{2}{2}}".format(P, "4", "000"))\n',
            "a width in Arabic-Indic digits":
                'import re\nP = r"\\A\\d+\\Z"\nA = re.compile("{0:' + arabisch + '}".format(P))\n',
            "a width in Arabic-Indic digits as an argument":
                'import re\nP = r"\\A\\d+\\Z"\nA = re.compile("{0:{1}}".format(P, "' + arabisch + '"))\n',
        }
        folded = {"400 terms of flags": 0, "forty names each doubling the one before": 1,
                  "twelve levels of V + (V + (V + V))": 1}
        run = subprocess.run([sys.executable, "-c", _BOUNDED_CHILD, __file__], input=json.dumps(inputs),
                             capture_output=True, text=True, timeout=300)
        self.assertEqual(run.returncode, 0, run.stderr[-2000:])
        result = json.loads(run.stdout)
        for name in inputs:
            with self.subTest(input=name):
                got = result[name]
                self.assertNotIn("raised", got)
                self.assertLess(got["seconds"], 10)
                if name in folded:
                    self.assertEqual((got["gaps"], got["readings"]), ([], folded[name]))
                else:
                    self.assertTrue(got["gaps"], "an input the fold cannot state is an unfolded site")
        self.assertIn("more than _FOLD_WORK fold steps", result["fifty sums of sixty-four texts"]["gaps"])
        self.assertIn("nested deeper than the interpreter's recursion limit", result["3000 terms of flags"]["gaps"])
        self.assertIn(_NESTED, result["a width of 4000000000 joined from nested fields"]["gaps"])
        self.assertIn(_WIDE, result["a width in Arabic-Indic digits"]["gaps"])
        self.assertIn(_NESTED, result["a width in Arabic-Indic digits as an argument"]["gaps"])
        self.assertLess(result["_peak_bytes"], 500 * 10**6)


class TheSweepReadsAliasesAnchorsReceiversAndSourcesAsPythonDoes(unittest.TestCase):
    """The lens on ac05d85d (F1, F2, F3) planted each form below past the sweep; none was live in the tree.
    Each case was measured on an export of ac05d85d and fails there."""

    _lines = staticmethod(TheSweepResolvesScopesFlagsAndStaysBounded._lines)
    _sites = staticmethod(TheSweepResolvesScopesFlagsAndStaysBounded._sites)

    def test_every_binding_form_of_an_alias_is_read(self):
        """F2: `c = d = re.compile`, `c: object = re.compile`, `d = c` after `c = re.compile` and a
        conditional alias passed without a reading and without a gap. Each is read now through the bindings
        of its scope, and so are an assignment expression, a class attribute and a local alias; the clean
        pattern on the last line is no finding."""
        planted = ('import re\n'
                   'c = d = re.compile\nA = c(r"\\A\\d+\\Z")\nB = d(r"\\A\\d+\\Z")\n'
                   'e: object = re.compile\nC = e(r"\\A\\d+\\Z")\n'
                   'f = re.compile\ng = f\nD = g(r"\\A\\d+\\Z")\n'
                   'h = re.compile if X else re.match\nE = h(r"\\d+\\Z")\n'
                   '(i := re.fullmatch)\nF = i(r"\\d+", s)\n'
                   'class K:\n    j = re.compile\nG = K.j(r"\\A\\d+\\Z")\n'
                   'def k():\n    m = re.compile\n    return m(r"\\A\\d+\\Z")\n'
                   'H = c(r"\\A[0-9]+\\Z")\n')
        self.assertEqual(self._lines(planted), [3, 4, 6, 9, 11, 13, 16, 19])
        self.assertEqual(self._sites(planted), [])

    def test_a_name_bound_to_a_function_of_re_and_to_anything_else_is_a_gap(self):
        """Deny by default: the call may reach another function, so its clean reading is not enough."""
        planted = ('import re\nc = re.compile\nif X:\n    c = str\nA = c(r"\\A[0-9]+\\Z")\n'
                   'e = re.compile\nfor e in X:\n    pass\nB = e(r"\\A[0-9]+\\Z")\n')
        self.assertEqual(self._lines(planted), [])
        self.assertEqual(self._sites(planted), [("<module>", "compile", "Constant", 2)])

    def test_an_anchor_in_a_group_a_lookahead_or_an_alternation_is_read(self):
        """F2: `(?:\\A\\d+)\\Z`, `\\A(?:\\d+\\Z)`, `\\A\\d+(?=\\Z)` and `(?:^[0-9]+)$` judge a whole value and
        were read as unanchored, under proofbundle.* too. An alternation on the chain is read branch by
        branch: `(?:^|/)[0-9]+$` judges a whole value through `^`; `(?:^|\\s)#` and a quantified group
        judge none."""
        planted = ('import re\nA = re.compile(r"(?:\\A\\d+)\\Z")\nB = re.compile(r"\\A(?:\\d+\\Z)")\n'
                   'C = re.compile(r"\\A\\d+(?=\\Z)")\nD = re.compile(r"(?:^[0-9]+)$")\n'
                   'E = re.compile(r"(?:^|/)[0-9]+$")\nF = re.compile(r"\\A(?:x|\\d+\\Z)")\n'
                   'G = re.compile(r"(?:^|\\s)#")\nH = re.compile(r"\\A(?:[0-9]+|x)\\Z")\n'
                   'I = re.compile(r"(?:\\A|/)\\d+(?=\\Z)")\nJ = re.compile(r"(?:\\A\\d+)*\\Z")\n')
        for mod in ("scripts.planted", "proofbundle.planted"):
            with self.subTest(module=mod):
                found = _whole_value_regex_readings([(mod, planted)])
                self.assertEqual(sorted((line, reading) for _m, line, _p, reading in found),
                                 [(2, UNICODE), (3, UNICODE), (4, UNICODE), (5, DOLLAR), (6, DOLLAR),
                                  (7, UNICODE), (10, UNICODE)])
        self.assertEqual(self._sites(planted), [])

    def test_an_anchor_the_reader_cannot_place_is_a_gap(self):
        """Deny by default: an anchor in a lookaround or a conditional group in a form the reader does not
        read, inline flags past the start of a pattern, and a group that is not closed are unfolded sites,
        not passes. The two forms this case planted before are read now (lens on fb6eda0d, H): a group that
        turns VERBOSE on is read in VERBOSE, and an alternation of any width is read, since the reader keeps
        a set of at most 48 branch readings instead of expanding the branches; the first reads through its
        `\\A` branch, the second holds no Unicode class."""
        breit = "(?:" + "|".join(f"^x{i}" for i in range(65)) + ")\\Z"
        planted = ('import re\nA = re.compile(r"(?x: \\A \\d+ | y )\\Z")\n'
                   f'B = re.compile(r"{breit}")\n'
                   'C = re.compile(r"\\A\\d+(?=a\\Z)")\n'
                   'D = re.compile(r"\\A\\d+(?(1)\\Z|x)")\n'
                   'E = re.compile(r"\\A\\d+(?i)\\Z")\n'
                   'F = re.compile(r"\\A(\\d+\\Z")\n')
        self.assertEqual(self._lines(planted), [2])
        self.assertEqual(self._sites(planted), [("<module>", "compile", "Constant", 4)])

    def test_match_taken_through_the_pattern_type_or_getattr_is_read(self):
        """F2: `re.Pattern.match(R, s)` and `getattr(R, "match")(s)` on `R = re.compile(r"\\d+\\Z")` judge a
        whole value and were read as a scan; `getattr` by a name the sweep cannot read is a gap."""
        planted = ('import re\nR = re.compile(r"\\d+\\Z")\nM = re.Pattern.match(R, s)\n'
                   'Q = re.compile(r"\\d+\\Z")\nN = getattr(Q, "match")(s)\n'
                   'from re import Pattern\nT = re.compile(r"\\d+\\Z")\nO = Pattern.fullmatch(T, s)\n'
                   'U = re.compile(r"\\d+\\Z")\nV = getattr(U, name)(s)\n'
                   'W = getattr(re.compile(r"\\d{3}\\Z"), "match")(s)\n'
                   'Y = re.compile(r"\\d+\\Z")\nZ = Y.search(s)\n')
        self.assertEqual(self._lines(planted), [2, 4, 7, 11])
        self.assertEqual(self._sites(planted), [("<module>", "compile", "Constant", 1)])

    def test_a_format_width_is_judged_on_the_spec_the_field_gets(self):
        """F1: `"{0:{1}{2}{2}{2}}".format(P, "4", "000")` is 4000000000 wide, a width in Arabic-Indic digits four
        billion, and so is a nested field given those digits; `_WIDE_FIELD` saw ASCII digits in the head
        alone, and each was built. A nested field is not judged now, a width in any digit is."""
        arabisch = "\u0664" + "\u0660" * 9
        self.assertEqual(_too_large_call("format", "{0:{1}{2}{2}{2}}", ["p", "4", "000"], {}), _NESTED)
        self.assertEqual(_too_large_call("format", "{0:" + arabisch + "}", ["p"], {}), _WIDE)
        self.assertEqual(_too_large_call("format", "{0:{1}}", ["p", arabisch], {}), _NESTED)
        self.assertIsNone(_too_large_call("format", "{0:>9}{1:\u0669}", ["p", "q"], {}))
        self.assertIsNone(_too_large_call("format", "{0:0" + "0" * 30 + "7}", ["p"], {}), "leading zeros")

    def test_a_source_is_read_as_python_reads_a_file(self):
        """F3: a script saved with a UTF-8 BOM, which Python runs, raised `SyntaxError: invalid
        non-printable character U+FEFF` out of the sweep, and one with a latin-1 coding cookie
        UnicodeDecodeError, since `_modules` read text. It reads bytes, and `ast.parse` honours both."""
        with tempfile.TemporaryDirectory() as d:
            skripte = pathlib.Path(d) / "scripts"
            skripte.mkdir()
            (skripte / "bom.py").write_bytes(b'\xef\xbb\xbfimport re\nA = re.compile(r"\\A\\d+\\Z")\n')
            (skripte / "latin.py").write_bytes(b'# -*- coding: latin-1 -*-\n# caf\xe9\nimport re\n'
                                               b'B = re.compile(r"\\A\\d+\\Z")\n')
            for skript in ("bom.py", "latin.py"):
                self.assertEqual(subprocess.run([sys.executable, str(skripte / skript)],
                                                capture_output=True).returncode, 0, "Python runs it")
            with unittest.mock.patch.object(sys.modules[__name__], "REPO", pathlib.Path(d)):
                found = _whole_value_regex_readings(list(_modules("scripts")))
        self.assertEqual(sorted((mod, line) for mod, line, _p, _r in found), [("scripts.bom", 2), ("scripts.latin", 4)])


class TheSweepReadsTheFormsOfTheLensOnFb6eda0d(unittest.TestCase):
    """The lens on fb6eda0d planted eleven forms past the sweep (G), none live in the tree, and measured two
    unbounded runs (H, I). Each form is read now or is an unfolded site, each run is bounded, and each case
    fails on fb6eda0d's sweep."""

    _lines = staticmethod(TheSweepResolvesScopesFlagsAndStaysBounded._lines)
    _sites = staticmethod(TheSweepResolvesScopesFlagsAndStaysBounded._sites)

    def test_an_alias_is_read_through_global_or_and_an_inherited_attribute(self):
        """`global c; c = re.compile` in a function, a regression against ac05d85d; `d = re.compile or None`,
        read and an unfolded site, since the callee may be None; and `L.j` with `class L(K)` and
        `j = re.compile` in `K`. The clean pattern through the inherited attribute is no finding."""
        planted = ('import re\n'
                   'def setup():\n    global c\n    c = re.compile\n'
                   'setup()\nA = c(r"\\A\\d+\\Z")\n'
                   'd = re.compile or None\nB = d(r"\\A\\d+\\Z")\n'
                   'class K:\n    j = re.compile\nclass L(K):\n    pass\n'
                   'C = L.j(r"\\A\\d+\\Z")\nD = L.j(r"\\A[0-9]+\\Z")\n')
        self.assertEqual(self._lines(planted), [6, 8, 13])
        self.assertEqual(self._sites(planted), [("<module>", "compile", "Constant", 1)])

    def test_a_compiled_pattern_is_matched_through_another_name_or_its_type(self):
        """`S = R` then `S.match(s)`, `type(R).match(R, s)`, `R.__class__.fullmatch(R, s)` and
        `getattr(type(R), "match")(R, s)` judge a whole value with `R = re.compile(r"\\d+\\Z")`; the first
        two were read as a scan. A search through a second name still judges none."""
        planted = ('import re\nR = re.compile(r"\\d+\\Z")\nS = R\nA = S.match(s)\n'
                   'T = re.compile(r"\\d+\\Z")\nB = type(T).match(T, s)\n'
                   'U = re.compile(r"\\d+\\Z")\nC = U.__class__.fullmatch(U, s)\n'
                   'V = re.compile(r"\\d+\\Z")\nD = getattr(type(V), "match")(V, s)\n'
                   'W = re.compile(r"\\d+\\Z")\nX = W\nE = X.search(s)\n')
        self.assertEqual(self._lines(planted), [2, 5, 7, 9])
        self.assertEqual(self._sites(planted), [])

    def test_an_alternation_at_the_top_level_is_read_branch_by_branch(self):
        """`\\A\\d+\\Z|none` and `n/a|^[0-9]+$` judge a whole value through one branch; the first reader
        split an alternation only inside a group. One without an anchored branch judges none."""
        planted = ('import re\nA = re.compile(r"\\A\\d+\\Z|none")\nB = re.search(r"n/a|^[0-9]+$", s)\n'
                   'C = re.compile(r"\\d+|none")\nD = re.compile(r"\\A[0-9]+\\Z|none")\n')
        found = _whole_value_regex_readings([("scripts.planted", planted)])
        self.assertEqual(sorted((line, reading) for _m, line, _p, reading in found), [(2, UNICODE), (3, DOLLAR)])
        self.assertEqual(self._sites(planted), [])

    def test_an_anchor_is_read_wherever_it_stands_on_the_path(self):
        """`\\A\\d+\\Z()`, `(?s)\\A\\d+(?!.)`, `\\A\\d+(?=\\n?\\Z)` (the `$` of re) and `(?:\\A\\d+){1}\\Z`
        judge a whole value, and so do `()\\A\\d+\\Z` and `\\A\\d+\\Z\\b`; the first reader read an anchor only
        as the first or the last item of a chain. Without DOTALL `(?!.)` ends a line, not the value, and a
        group matched zero times or once anchors nothing."""
        planted = ('import re\nA = re.compile(r"\\A\\d+\\Z()")\nB = re.compile(r"(?s)\\A\\d+(?!.)")\n'
                   'C = re.compile(r"\\A\\d+(?=\\n?\\Z)")\nD = re.compile(r"(?:\\A\\d+){1}\\Z")\n'
                   'E = re.compile(r"\\A\\d+(?!.)")\nF = re.compile(r"(?:\\A\\d+){0,1}\\Z")\n'
                   'G = re.compile(r"()\\A\\d+\\Z")\nH = re.compile(r"\\A\\d+\\Z\\b")\n')
        found = _whole_value_regex_readings([("scripts.planted", planted)])
        self.assertEqual(sorted((line, reading) for _m, line, _p, reading in found),
                         [(2, UNICODE), (3, UNICODE), (4, DOLLAR), (4, UNICODE), (5, UNICODE), (8, UNICODE),
                          (9, UNICODE)])
        self.assertEqual(self._sites(planted), [])

    def test_a_format_or_percent_result_is_judged_by_its_size_before_it_is_built(self):
        """I: `"{0}" * 3333` formatted with a text of 10000 characters is 33 million characters; only the
        widths of its fields were judged. Each field is sized alone now and the sizes are summed, for
        `str.format` and for `%` with a mapping, whose key a format may name 2000 times; a small result is
        still folded to its reading."""
        planted = ('import re\nH = "{0}" * 3333\nW = "\\U0001F600" * 10000\nA = re.compile(H.format(W))\n'
                   'M = "%(a)s" * 2000\nV = "a" * 9990\nB = re.compile(M % {"a": V})\n'
                   'C = re.compile("{0}{0}".format(r"\\A\\d+\\Z"))\n'
                   'D = re.compile("%(p)s|%(p)s" % {"p": r"\\A\\d+\\Z"})\n')
        self.assertEqual(self._lines(planted), [8, 9])
        # judged BEFORE the text is built: fb6eda0d built the 33 million characters and dropped them after
        self.assertEqual(_too_large_call("format", "{0}" * 3333, ["\U0001F600" * 10000], {}), _LARGE)
        self.assertEqual(_too_large(ast.Mod, "%(a)s" * 2000, {"a": "a" * 9990}), _LARGE)
        self.assertIsNone(_too_large_call("format", "{0}{0}", [r"\A\d+\Z"], {}))
        self.assertIsNone(_too_large(ast.Mod, "%(p)s|%(p)s", {"p": r"\A\d+\Z"}))
        sites = _unfolded_pattern_sites([("scripts.planted", planted)])
        self.assertEqual(sorted(sites), [("scripts.planted", "<module>", "compile", "BinOp"),
                                         ("scripts.planted", "<module>", "compile", "Call")])
        for key, calls in sites.items():
            with self.subTest(site=key):
                self.assertEqual(calls, [[_LARGE]])

    def test_the_lens_inputs_stay_bounded(self):
        """H and I in the bounded child. A pattern of 4257 characters with 100 nested groups and 64 end
        branches took 51.5 s on fb6eda0d, since the chain walk cost depth times length per branch; read in
        one pass it keeps its two readings. Sixty-four texts of about 9000 characters for one call spend
        more than `_ANCHOR_WORK`, and the call is an unfolded site. The two results of I, with four values
        of the text, took the process to a peak of 541 MiB there; they are gaps judged before anything is
        built. Measured after the fix, 2026-09-27: each input under 0.5 s, a peak of 34 MB."""
        anfang = "(?:" + "|".join(f"^{c}" for c in "abcdefgh") + ")"
        ende = "(?:" + "|".join(f"{c}$" for c in "abcdefgh") + ")"
        tief = "(" * 100 + anfang + "\\d+" + "x" * 4000 + ")" * 100 + ende
        re.compile(tief)                                          # a real pattern
        wahl = "".join(f' + ("a" if X{i} else "b")' for i in range(6))
        vier = " if X else ".join(f'"\\U0001F60{i}"' for i in range(4))
        inputs = {
            "100 nested groups and 64 end branches": f"import re\nA = re.compile({tief!r})\n",
            "sixty-four texts of 9000 characters": ('import re\nP = "x" * 8990\n'
                                                    f'A = re.compile(r"\\A\\d" + P{wahl})\n'),
            "a format of 3333 fields, four values": ('import re\nH = "{0}" * 3333\n'
                                                     f"W = ({vier}) * 10000\nA = re.compile(H.format(W))\n"),
            "a mapping named 2000 times": ('import re\nM = "%(a)s" * 2000\nV = "a" * 9990\n'
                                          'A = re.compile(M % {"a": V})\n'),
        }
        run = subprocess.run([sys.executable, "-c", _BOUNDED_CHILD, __file__], input=json.dumps(inputs),
                             capture_output=True, text=True, timeout=600)
        self.assertEqual(run.returncode, 0, run.stderr[-2000:])
        result = json.loads(run.stdout)
        for name in inputs:
            with self.subTest(input=name):
                self.assertNotIn("raised", result[name])
                self.assertLess(result[name]["seconds"], 10)
        self.assertEqual((result["100 nested groups and 64 end branches"]["readings"],
                          result["100 nested groups and 64 end branches"]["gaps"]), (2, []))
        self.assertIn(f"more than {_ANCHOR_WORK} steps reading the anchors of one call",
                      result["sixty-four texts of 9000 characters"]["gaps"])
        for name in ("a format of 3333 fields, four values", "a mapping named 2000 times"):
            with self.subTest(input=name):
                self.assertIn(_LARGE, result[name]["gaps"])
        self.assertLess(result["_peak_bytes"], 200 * 10**6)


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
