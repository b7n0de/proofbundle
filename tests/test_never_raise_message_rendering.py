"""The rejection path must not fail harder than the check it explains.

THE CLASS. Every public verify surface owes its caller a stable verdict rather than a raw exception, and
the checks honour that. The MESSAGES that explain a rejection did not: they interpolated the offending
caller-supplied value directly, so rendering the explanation could raise where the check would have
returned cleanly. Handing a deeply nested value to a relying-party expectation argument made ``repr()``
recurse and raised ``RecursionError`` — a forbidden termination under the never-raise contract — out of a
dict-returning verify surface.

WHY THIS FILE HAS THREE PARTS RATHER THAN ONE. A single test pinning the three reproducers that happened to
be found would close three instances and leave their neighbours untouched: a structural sweep of the
never-raise family found the same shape in eleven functions. So:

  1. BEHAVIOUR — the reproducers, which fail against the pre-fix code and pass after it.
  2. FORCING FUNCTION — a structural rule over the WHOLE family, so a site added tomorrow is in scope
     without anyone remembering to add it here.
  3. ANTI-TAUTOLOGY — proof that part 2 is capable of going red at all: a planted violation must be caught,
     and a blinded rule must stop catching it.

HONEST LIMIT of the forcing function, stated because a rule whose blind spot is undocumented reads as
stronger than it is: it follows values that are PARAMETERS of a family member. A value copied into a local
first (``st = predicate.get("status")`` and then rendered) is outside its population, and so is a value
that reaches a message through a helper it does not analyse. Closing that needs intra-procedural taint,
which is tracked as an open item rather than claimed here.
"""
from __future__ import annotations

import ast
import inspect
import pathlib
import re

import pytest

SRC = pathlib.Path(__file__).resolve().parents[1] / "src" / "proofbundle"

# The never-raise surface family, by name. Mirrors the contract stated in the module docstrings: a public
# verify_/load_/check_/decode_/validate_… surface returns a verdict, it does not raise for hostile input.
FAMILY_PATTERN = re.compile(
    r"^(verify_|load_|check_|decode_|count_|recompute_|receipt_canonical|sd_jwt_hidden"
    r"|validate_|require_valid_|require_derived_|classify_|derive_)")

# Expression shapes that are bounded WITHOUT `brief`, because what they render is not the value itself.
# `type(x).__name__` is a class name; `len(x)` is an integer. Neither can recurse or be enormous.
_BOUNDED_SHAPES = ("len", "brief")


def _reachable_params(funcs, helper_name: str) -> set[str]:
    """Which parameters of a private helper can carry a value the module did not choose itself.

    A helper called only as ``_b64d(anchor.get("proof"), "proof")`` takes its `field` from a string literal
    at every call site: no caller value can reach it, so rendering it is bounded by the source, not by luck.
    Its FIRST argument is a different matter. Distinguishing the two keeps the rule sharp — a rule that
    flags every helper parameter trains people to silence it, which is worse than not having it.
    """
    helper = funcs[helper_name]
    names = [p.arg for p in (helper.args.posonlyargs + helper.args.args + helper.args.kwonlyargs)]
    literal_only = set(names)
    seen_call = False
    for fn in funcs.values():
        for node in ast.walk(fn):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == helper_name):
                continue
            seen_call = True
            for i, arg in enumerate(node.args):
                if i < len(names) and not isinstance(arg, ast.Constant):
                    literal_only.discard(names[i])
            for kw in node.keywords:
                if kw.arg in literal_only and not isinstance(kw.value, ast.Constant):
                    literal_only.discard(kw.arg)
    if not seen_call:
        return set(names)
    return set(names) - literal_only


def _family_functions():
    """Every function in the package that is in the never-raise family, plus the private helpers those
    functions call inside the same module (a message built in a helper is still a message on the path).

    Yields ``(path, function, parameters_in_scope)``. For a family member every parameter is in scope: it
    is the surface a relying party calls. For a helper only the parameters an outside value can actually
    reach are (see :func:`_reachable_params`)."""
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        funcs = {n.name: n for n in ast.walk(tree)
                 if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        in_family = {name for name in funcs if FAMILY_PATTERN.match(name)}
        helpers = set()
        # one step of call closure: a private helper called by a family member is on the path too
        for name in sorted(in_family):
            for node in ast.walk(funcs[name]):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                        and node.func.id.startswith("_") and node.func.id in funcs \
                        and node.func.id not in in_family:
                    helpers.add(node.func.id)
        for name in sorted(in_family):
            yield path, funcs[name], _parameters(funcs[name])
        for name in sorted(helpers):
            yield path, funcs[name], _reachable_params(funcs, name)


def _parameters(fn) -> set[str]:
    a = fn.args
    names = {p.arg for p in (a.posonlyargs + a.args + a.kwonlyargs)}
    if a.vararg:
        names.add(a.vararg.arg)
    if a.kwarg:
        names.add(a.kwarg.arg)
    return names


def _isinstance_guarded(fn, param: str) -> set[int]:
    """Line numbers of `isinstance(param, ...)` tests inside `fn`.

    A message below such a test renders a value whose type has been narrowed. This checks PRESENCE, not
    dominance — a guard on a branch that does not actually reach the message would satisfy it. That is the
    documented weak point of this rule; it is deliberately permissive here so the rule stays mechanical
    rather than approximate in the unsafe direction.
    """
    lines = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "isinstance":
            if node.args and isinstance(node.args[0], ast.Name) and node.args[0].id == param:
                lines.add(node.lineno)
    return lines


def _unbounded_renderings(fn, params: set[str]) -> list[tuple[int, str]]:
    """Every place `fn` renders one of its own parameters into an f-string without bounding it."""
    out = []
    for node in ast.walk(fn):
        if not isinstance(node, ast.JoinedStr):
            continue
        for piece in node.values:
            if not isinstance(piece, ast.FormattedValue):
                continue
            expr = piece.value
            # brief(x) / len(x) — bounded by construction
            if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Name) \
                    and expr.func.id in _BOUNDED_SHAPES:
                continue
            # type(x).__name__ — renders a class name, not the value
            if isinstance(expr, ast.Attribute) and expr.attr == "__name__":
                continue
            named = {n.id for n in ast.walk(expr) if isinstance(n, ast.Name)} & params
            for param in sorted(named):
                guards = _isinstance_guarded(fn, param)
                if any(g < piece.lineno for g in guards):
                    continue
                out.append((piece.lineno, param))
    return out


# ── 1. Behaviour: the reproducers ────────────────────────────────────────────────────────────────────

def _deep(depth: int = 2000) -> dict:
    """A value whose rendering recurses. Nothing exotic: a nested object, the shape a caller can build by
    accident from parsed configuration."""
    root: dict = {}
    cur = root
    for _ in range(depth):
        nxt: dict = {}
        cur["a"] = nxt
        cur = nxt
    cur["a"] = 1
    return root


@pytest.mark.parametrize("kwarg", ["require", "require_target"])
def test_anchor_requirement_argument_does_not_crash_the_rejection(kwarg):
    """`verify_anchors` rejects an ill-typed requirement. Building the rejection MESSAGE must not raise.

    Note what is and is not asserted. The never-raise contract does not say "returns a dict": it says the
    termination stays inside the DECLARED accepted set. `verify_anchors` documents `BundleFormatError` for
    an invalid `require_target`, and that raise is the contract working. What must never happen is a
    `RecursionError` — a termination nobody declared, produced by the explanation rather than the check.
    """
    from proofbundle import anchors
    from proofbundle.errors import ProofBundleError
    try:
        outcome = anchors.verify_anchors([], target_roots={}, **{kwarg: _deep()})
    except ProofBundleError:
        return                       # declared, typed, fail-closed
    except BaseException as exc:     # noqa: BLE001 — that is the whole point of the test
        pytest.fail(f"undeclared {type(exc).__name__} escaped the rejection path")
    assert isinstance(outcome, dict), "a verdict, not an exception"


@pytest.mark.parametrize("fn_name", ["verify_intoto_dsse", "verify_svr_dsse", "verify_eval_result_dsse"])
def test_predicate_type_expectation_does_not_crash_the_rejection(fn_name):
    """The predicate-confusion defence reports what it got and what it expected. Reporting must not raise
    when the expectation itself is an awkward value."""
    from proofbundle import intoto
    result = getattr(intoto, fn_name)({}, b"", expected_predicate_type=_deep())
    assert isinstance(result, dict)
    assert result["ok"] is False, "an unverifiable envelope is never ok"


def test_outcome_policy_purpose_rejection_does_not_crash():
    from proofbundle.outcome import validate_outcome_predicate
    errors = validate_outcome_predicate({"policyPurpose": _deep()})
    assert isinstance(errors, list) and errors


def test_brief_never_raises_on_hostile_values():
    """The renderer itself is on the never-raise path, so it carries the contract it enforces."""
    from proofbundle._brief import brief

    class Hostile:
        def __repr__(self):
            raise RuntimeError("no repr for you")

        def __str__(self):
            raise RuntimeError("no str either")

    recursive: list = []
    recursive.append(recursive)
    for value in (_deep(), recursive, Hostile(), "x" * 5_000_000, 10 ** 100_000, None):
        rendered = brief(value)
        assert isinstance(rendered, str)
        assert len(rendered) <= 512, "the message stays bounded"


def test_brief_leaves_ordinary_values_unchanged():
    """Existing messages must keep saying what they said. Only the pathological input renders differently."""
    from proofbundle._brief import brief
    assert brief("receipt") == "'receipt'"
    assert brief("receipt", quote=False) == "receipt"
    assert brief(7, quote=False) == "7"
    assert brief(None) == "None"


# ── 2. Forcing function: the whole family, not the three known sites ──────────────────────────────────

# The private helpers a family member calls are on the path too, but their parameters are overwhelmingly
# internal labels the module chooses itself (`where=f"policy.{k}"`, `field="canonicalRoot"`). Wrapping those
# would be noise, and NOT looking at them would be a silent gap. So they are ENUMERATED: the set below is
# the exact remaining population, pinned. A new one fails the ratchet (the gap cannot grow quietly); closing
# one requires deleting its line (progress is visible). An enumerated gap is honest; a hidden one is not.
HELPER_CLOSURE_GAP = {
    "anchors_chia.py::_hexatom::field",
    "anchors_chia.py::_hexbytes::field",
    "bundle.py::_require::field",
    "checkpoint.py::_cosigned_message::timestamp",
    "policy.py::_reject_unknown::where",
    "policy.py::_require_bool::key",
    "policy.py::_require_dict::where",
    "policy.py::_require_list_of_str::key",
    "policy.py::_validate_checkpoint_entry::idx",
    "policy.py::_validate_pinned_ed25519_pubkey::ctx",
    "policy.py::_validate_root_b64::where",
    "pqsig.py::_mldsa_classes::level",
    "relation.py::_validate_edge_digest::path",
    "relation.py::_walk_chain::max_depth",
    "trust_pack.py::_parse_rfc3339_z::s",
}


def _split_violations():
    """(family violations, helper violations) — the enforcing population and the enumerated one."""
    family, helper = set(), set()
    for path, fn, params in _family_functions():
        target = family if FAMILY_PATTERN.match(fn.name) else helper
        for _lineno, param in _unbounded_renderings(fn, params):
            target.add(f"{path.name}::{fn.name}::{param}")
    return family, helper


def test_no_family_member_renders_a_parameter_unbounded():
    """The class-level rule over the surface a relying party actually calls. A verify surface added
    tomorrow is covered by this without anyone remembering to edit this file."""
    family, _ = _split_violations()
    assert not family, (
        "a message on a never-raise surface renders a caller value without bounding it; wrap it in "
        "proofbundle._brief.brief(...):\n  " + "\n  ".join(sorted(family)))


def test_helper_closure_gap_does_not_grow():
    """The ratchet on the part not yet closed. A NEW unbounded helper rendering fails here; a closed one
    must be removed from the pinned set, so the remaining gap is always the true one."""
    _, helper = _split_violations()
    neu = helper - HELPER_CLOSURE_GAP
    weg = HELPER_CLOSURE_GAP - helper
    assert not neu, f"new unbounded helper rendering(s) — close them or pin them deliberately: {sorted(neu)}"
    assert not weg, f"these are fixed; delete them from HELPER_CLOSURE_GAP so the gap stays true: {sorted(weg)}"


def test_the_family_is_not_empty():
    """A rule over an empty population passes for the wrong reason. This is the denominator check."""
    family = list(_family_functions())
    assert len(family) >= 50, f"the never-raise family collapsed to {len(family)} members — rule is vacuous"


# ── 3. Anti-tautology: can the rule go red at all ─────────────────────────────────────────────────────

_PLANTED = '''
def verify_planted(value, other):
    if not isinstance(other, str):
        return {"ok": False, "detail": f"other is wrong: {other}"}
    return {"ok": False, "detail": f"value is wrong: {value!r}"}
'''


def test_planted_violation_is_caught():
    """Plant the pre-fix shape in a file the rule has never seen. It must fire — on the UNGUARDED parameter
    only, so the rule is discriminating rather than merely loud."""
    tree = ast.parse(_PLANTED)
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef))
    found = _unbounded_renderings(fn, _parameters(fn))
    params = {p for _, p in found}
    assert "value" in params, "the unguarded rendering was not caught — the rule is asleep"
    assert "other" not in params, "the isinstance-guarded rendering should not be flagged"


def test_blinding_the_rule_makes_the_planted_violation_survive():
    """The other direction. If the rule were passing for a reason other than the defence it names, blinding
    it would change nothing. It must change everything."""
    tree = ast.parse(_PLANTED)
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef))
    blinded = _unbounded_renderings(fn, set())        # blind it: no parameters are interesting
    assert not blinded, "expected the blinded rule to find nothing"
    assert _unbounded_renderings(fn, _parameters(fn)), "and the seeing rule to still find the violation"


def test_the_fixed_sites_are_really_wrapped():
    """Grounded in the source rather than in the rule's own opinion: the sites the reproducers exercise
    call the bounded renderer."""
    from proofbundle import anchors, intoto
    assert "brief(require_target)" in inspect.getsource(anchors.verify_anchors)
    assert "brief(got)" in inspect.getsource(intoto._intoto_verify_result)
