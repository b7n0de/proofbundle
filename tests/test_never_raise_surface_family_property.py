"""Auto-enumerated never-raise class-closure test (Berkeley-gate v4 centerpiece, proof-of-concept in-repo).

The round-by-round Berkeley re-gates converged 11 -> 3 -> 2 -> 1 but never to zero in one round because the fix
target was "the one repro" and the SURFACE FAMILY was never made an explicit, machine-checked denominator. This
test IS that denominator: it AUTO-DISCOVERS every public never-raise surface (verify_*/check_*/load_*/decode_*/
count_*/recompute_*/receipt_canonical_root/sd_jwt_hidden_count) across the package via ``__all__``/``inspect``,
and fuzzes each surface's untrusted PRIMARY argument with every wrong type. A surface that terminates outside the
accepted typed set (a returned verdict, or a ``ProofBundleError`` / ``ValueError``) — i.e. a raw
``AttributeError`` / ``TypeError`` / ``RecursionError`` / ``KeyError`` / ``IndexError`` — is an escape.

Unlike the hand-curated ``test_never_raise_primary_arg_property.py`` (precise per-function args, 16 surfaces),
this test's value is the AUTO-ENUMERATED denominator: a newly-added public verify/check surface is automatically
in scope, so it fails HERE the moment it forgets a primary-arg guard, not in a future re-gate round. The empirical
one-pass sweep at authoring time: 43 surfaces x 8 bad primaries = 344 calls, zero escapes.
"""
import importlib
import inspect
import re
import unittest

from proofbundle.errors import ProofBundleError

# Modules that expose a public never-raise verify/check/load surface over untrusted input.
_MODULES = [
    "bundle", "sdjwt", "sdjwt_vc", "sdjwt_issue", "evalclaim", "kbjwt", "statuslist", "persample",
    "tlogproof", "hf_evals", "checkpoint", "merkle", "policy", "anchors", "dsse", "intoto", "decision",
    "outcome", "verification_summary", "relation_statement", "trust_pack", "run_ledger", "evidence_pack",
    "renewal", "hashalg", "prereg", "evalcard",
    # Berkeley re-gate round 8 (v4 denominator broadening — the completeness critic found these were outside
    # the sweep, hiding the decision/outcome/subject_binding RecursionError class):
    "subject_binding", "relation", "assurance", "automation_verdict", "beacon", "public_transparency",
    "signature", "policy_profiles", "canonical",
]
# Broadened name family (round 8): the predicate-validation surfaces a relying party actually calls
# (validate_*/require_valid_*/require_derived_*/classify_*/derive_*) were entirely outside the old pattern.
# Round 4 (v4): + the verdict families evaluate_*/audit_*/automation_*/evidence_ladder_* — the G2 gap the
# round-4 re-gate proved (evaluate_policy/evaluate_public_transparency/automation_summary/evidence_ladder_*).
_NAME_PATTERN = re.compile(
    r"^(verify_|check_|load_|decode_|count_|recompute_|receipt_canonical|sd_jwt_hidden"
    r"|validate_|require_valid_|require_derived_|classify_|derive_"
    r"|evaluate_|audit_|automation_|evidence_ladder_)")

# ACCEPTED terminations: a returned value, or a TYPED fail-closed error. ProofBundleError covers
# BundleFormatError / BudgetExceeded / PQUnavailable / UnsupportedError / CanonicalizerUnavailable / PolicyError
# / SdjwtVcError / EvalClaimError-as-PBError; ValueError covers EvalClaimError + the rfc8785 domain family.
_ACCEPTED = (ProofBundleError, ValueError)
# FORBIDDEN raw terminations = the type-confusion crash signatures a public verify surface must never emit.
_FORBIDDEN = (AttributeError, TypeError, RecursionError, KeyError, IndexError, UnicodeDecodeError, MemoryError)

_BAD_PRIMARIES = [None, 123, 1.5, True, b"bytes-not-str", ["a", "list"], {"k": "v"}, ("t", "u")]


def _discover_surfaces():
    """Every public never-raise surface DEFINED in one of the modules (not merely imported into it).

    Round 8 (v4): the name pattern is the public-surface signal — do NOT gate on ``__all__``. The completeness
    critic found ``evalclaim.load_claim_text`` is a documented never-raise ``load_`` primitive that is NOT in
    ``evalclaim.__all__``, so the old ``__all__`` gate silently dropped it from the denominator. A non-underscore
    function whose name matches the never-raise family IS in scope regardless of ``__all__``."""
    out = []
    for mod_name in _MODULES:
        try:
            mod = importlib.import_module(f"proofbundle.{mod_name}")
        except Exception:  # noqa: BLE001 - an optional-extra module that will not import is out of scope here
            continue
        for name, fn in inspect.getmembers(mod, inspect.isfunction):
            if fn.__module__ != mod.__name__ or name.startswith("_"):
                continue
            if _NAME_PATTERN.match(name):
                out.append((mod_name, name, fn))
    return out


def _structural_corpus():
    """Structural hostile inputs on VALID-typed dicts/lists (round 8 — the old sweep only fuzzed 8 wrong TYPES,
    so the recursion/DoS classes were outside the auto-enumerated test by design; the decision/outcome/
    subject_binding RecursionError proved it). Built lazily so import stays cheap."""
    def deep_d(n):
        o = {}
        cur = o
        for _ in range(n):
            nxt = {}
            cur["a"] = nxt
            cur = nxt
        cur["a"] = 1
        return o

    def deep_l(n):
        x = [1]
        for _ in range(n):
            x = [x]
        return x
    return [deep_d(4000), deep_l(4000), {"pad": list(range(200_050))},
            float("nan"), float("inf"), 2 ** 53, 10 ** 400]


def _stub_for(param):
    """A neutral, valid-typed stub for a non-primary required argument (so a missing-arg TypeError is not a
    false escape); the primary argument is the fuzz target, everything else must be plausibly-shaped."""
    ann = str(param.annotation).lower()
    if "bytes" in ann:
        return b""
    if "str" in ann:
        return ""
    if "int" in ann:
        return 0
    if "dict" in ann or "mapping" in ann:
        return {}
    if "bool" in ann:
        return False
    if "sequence" in ann or "list" in ann:
        return []
    return b""


class NeverRaiseSurfaceFamilyProperty(unittest.TestCase):
    def test_discovery_finds_the_expected_surface_family(self):
        surfaces = _discover_surfaces()
        # A regression floor on the denominator itself: if this drops sharply, discovery silently broke and the
        # property below would vacuously pass. 70 at round-8 broadening; allow growth, guard against collapse.
        self.assertGreaterEqual(len(surfaces), 65,
                                f"surface discovery collapsed to {len(surfaces)} — the denominator is broken")

    def test_no_public_surface_raises_raw_on_hostile_primary(self):
        # Round 8 (v4): sweep BOTH the 8 wrong TYPES and the STRUCTURAL hostile inputs (deep-nest / node-heavy /
        # NaN·Inf·bigint on valid-typed dicts) — the old test fuzzed only types, so every recursion/DoS class
        # was outside the denominator by design (the decision/outcome/subject_binding RecursionError proved it).
        import warnings
        warnings.filterwarnings("ignore")
        corpus = _BAD_PRIMARIES + _structural_corpus()
        escapes = []
        for mod_name, name, fn in _discover_surfaces():
            try:
                params = list(inspect.signature(fn).parameters.values())
            except (ValueError, TypeError):
                continue
            if not params:
                continue
            for bad in corpus:
                args, kwargs = [], {}
                for i, p in enumerate(params):
                    if p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD):
                        continue
                    if i == 0:
                        val = bad
                    elif p.default is not inspect.Parameter.empty:
                        continue
                    else:
                        val = _stub_for(p)
                    if p.kind == p.KEYWORD_ONLY:
                        kwargs[p.name] = val
                    else:
                        args.append(val)
                try:
                    fn(*args, **kwargs)              # a returned verdict is acceptable
                except _ACCEPTED:
                    pass                              # a typed fail-closed error is acceptable
                except _FORBIDDEN as exc:
                    escapes.append(f"{mod_name}.{name} on {type(bad).__name__}: raw "
                                   f"{type(exc).__name__}: {exc}")
        self.assertEqual(escapes, [], "raw type-confusion escapes over the AUTO-DISCOVERED surface family:\n"
                         + "\n".join(escapes))


    def test_var_positional_surfaces_fuzzed_with_hostile_args(self):
        """Round-4 v4 (G4): the primary sweep SKIPS *var_positional params, so *fields aggregators
        (evidence_ladder_*) were called with ZERO args and never fuzzed. Here every all-*args public surface is
        called with hostile elements — this is where the evidence_ladder non-comparable-level escape lived."""
        import warnings
        warnings.filterwarnings("ignore")
        hostile_args = [(123,), ("x",), (None,), ({"level": 1}, {"level": "z"}), ({"level": object()},), (b"b",)]
        escapes = []
        for mod_name, name, fn in _discover_surfaces():
            try:
                params = list(inspect.signature(fn).parameters.values())
            except (ValueError, TypeError):
                continue
            if not any(p.kind == p.VAR_POSITIONAL for p in params):
                continue
            if any(p.kind not in (p.VAR_POSITIONAL, p.VAR_KEYWORD)
                   and p.default is inspect.Parameter.empty for p in params):
                continue  # has a required non-*args param -> covered by the primary/regression tests
            for args in hostile_args:
                try:
                    fn(*args)
                except _ACCEPTED:
                    pass
                except _FORBIDDEN as exc:
                    escapes.append(f"{mod_name}.{name}(*{args!r}): raw {type(exc).__name__}: {exc}")
        self.assertEqual(escapes, [], "raw *var_positional escapes:\n" + "\n".join(escapes))

    def test_round4_nonprimary_regression(self):
        """Generator-hardening (Berkeley v3): each round-4 re-gate escape becomes a PERMANENT corpus entry so it
        can never silently regress. These are the exact 12 confirmed escapes at HEAD 956cbe5 — a VALID primary
        plus a hostile NON-PRIMARY / nested-sub-field / non-comparable value. Each must terminate fail-closed
        (a returned verdict or a typed _ACCEPTED error), never a raw _FORBIDDEN. Auto-fuzzing cannot reach these
        (they need a valid primary to reach the non-primary sink), so they are pinned explicitly."""
        from proofbundle.evalclaim import check_freshness
        from proofbundle.automation_verdict import automation_summary
        from proofbundle.assurance import evidence_ladder_summary, evidence_ladder_best
        from proofbundle.public_transparency import evaluate_public_transparency
        from proofbundle.policy import evaluate_decision_policy, evaluate_policy
        from proofbundle.relation import evaluate_relations_policy
        C = {"timestamp": "2026-01-01T00:00:00Z"}
        cases = [
            ("check_freshness now=int", lambda: check_freshness(C, None, 123)),
            ("check_freshness max_age=str", lambda: check_freshness(C, "x", None)),
            ("automation references=int", lambda: automation_summary({}, required_checks={"references": 5})),
            ("automation references=bool", lambda: automation_summary({}, required_checks={"references": True})),
            ("evidence_ladder mixed-level", lambda: evidence_ladder_summary({"level": 1}, {"level": "z"})),
            ("evidence_ladder obj-level", lambda: evidence_ladder_best({"level": 1}, {"level": object()})),
            ("evidence_ladder level-only", lambda: evidence_ladder_best({"level": 1})),
            ("evaluate_public_transparency vkeys=int",
             lambda: evaluate_public_transparency("x", {"witnessQuorum": {"threshold": 1}}, witness_vkeys=5)),
            ("evaluate_public_transparency vkeys=bool",
             lambda: evaluate_public_transparency("x", {"witnessQuorum": {"threshold": 1}}, witness_vkeys=True)),
            ("evaluate_decision_policy evidenceRefs=int",
             lambda: evaluate_decision_policy(
                 {"predicate": {"evidenceRefs": 5}}, {"ok": True},
                 {"schema": "proofbundle/trust-policy/v0.2", "policy_id": "p",
                  "decision_receipt": {"required_evidence_relations": ["r"]}}, signer_public_key_b64="abc")),
            ("evaluate_policy non-dict-policy", lambda: evaluate_policy({}, {"ok": True}, 5)),
            ("evaluate_relations require_res=int",
             lambda: evaluate_relations_policy({"require_relation_resolution": 5}, {"edges": []},
                                               successor_key_b64=None)),
            ("evaluate_relations signer=int",
             lambda: evaluate_relations_policy({"relation_signer": 5}, {"edges": [{"relation": "x"}]},
                                               successor_key_b64=None)),
        ]
        escapes = []
        for label, fn in cases:
            try:
                fn()
            except _ACCEPTED:
                pass
            except _FORBIDDEN as exc:
                escapes.append(f"{label}: raw {type(exc).__name__}: {exc}")
        self.assertEqual(escapes, [], "round-4 non-primary regression escapes:\n" + "\n".join(escapes))


if __name__ == "__main__":
    unittest.main()
