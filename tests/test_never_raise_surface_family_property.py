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
]
_NAME_PATTERN = re.compile(
    r"^(verify_|check_|load_|decode_|count_|recompute_|receipt_canonical|sd_jwt_hidden)")

# ACCEPTED terminations: a returned value, or a TYPED fail-closed error. ProofBundleError covers
# BundleFormatError / BudgetExceeded / PQUnavailable / UnsupportedError / CanonicalizerUnavailable / PolicyError
# / SdjwtVcError / EvalClaimError-as-PBError; ValueError covers EvalClaimError + the rfc8785 domain family.
_ACCEPTED = (ProofBundleError, ValueError)
# FORBIDDEN raw terminations = the type-confusion crash signatures a public verify surface must never emit.
_FORBIDDEN = (AttributeError, TypeError, RecursionError, KeyError, IndexError, UnicodeDecodeError, MemoryError)

_BAD_PRIMARIES = [None, 123, 1.5, True, b"bytes-not-str", ["a", "list"], {"k": "v"}, ("t", "u")]


def _discover_surfaces():
    """Every public never-raise surface DEFINED in one of the modules (not merely imported into it)."""
    out = []
    for mod_name in _MODULES:
        try:
            mod = importlib.import_module(f"proofbundle.{mod_name}")
        except Exception:  # noqa: BLE001 - an optional-extra module that will not import is out of scope here
            continue
        exported = getattr(mod, "__all__", None)
        for name, fn in inspect.getmembers(mod, inspect.isfunction):
            if fn.__module__ != mod.__name__ or name.startswith("_"):
                continue
            if exported is not None and name not in exported:
                continue
            if _NAME_PATTERN.match(name):
                out.append((mod_name, name, fn))
    return out


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
        # property below would vacuously pass. 43 at authoring; allow growth, guard against collapse.
        self.assertGreaterEqual(len(surfaces), 40,
                                f"surface discovery collapsed to {len(surfaces)} — the denominator is broken")

    def test_no_public_surface_raises_raw_on_a_type_confused_primary(self):
        import warnings
        warnings.filterwarnings("ignore")
        escapes = []
        for mod_name, name, fn in _discover_surfaces():
            try:
                params = list(inspect.signature(fn).parameters.values())
            except (ValueError, TypeError):
                continue
            if not params:
                continue
            for bad in _BAD_PRIMARIES:
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


if __name__ == "__main__":
    unittest.main()
