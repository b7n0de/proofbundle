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

HOW THE POPULATION IS CHOSEN — and why that used to be the bug. This rule first selected its own scope by
matching function NAMES (``verify_``/``load_``/``check_``/…). That is a blocklist of the spellings known on
the day it was written: it must be COMPLETE to work. It was not. The entire ``evaluate_`` family sat outside
it, exported ``evaluate_renewal_policy`` included, and a blind rule emits nothing, so nothing looked wrong.
The population is now DERIVED — see ``test_surface_family_selector`` — from every public surface the package
ships, with the EXCLUSIONS enumerated instead of the inclusions. A surface nobody has decided about is
covered, so an unfamiliar naming convention lands on the checked side by itself.

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
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from test_surface_family_selector import (  # noqa: E402 — path shim above must run first
    REASON_CODES,
    SURFACE_DECISIONS,
    covered_surfaces,
    discover_public_surfaces,
)

SRC = pathlib.Path(__file__).resolve().parents[1] / "src" / "proofbundle"

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
    """Every covered public surface of the package, plus the private helpers those surfaces call inside the
    same module (a message built in a helper is still a message on the path).

    Yields ``(module, qualname, function, parameters_in_scope, predicates, is_surface)``. For a covered
    surface every parameter is in scope: it is what a relying party calls. For a helper only the parameters
    an outside value can actually reach are (see :func:`_reachable_params`).

    The helper closure is taken from ALL public surfaces, not only the covered ones. An exclusion is a
    statement about ONE surface's own messages; letting it also drop the helpers that only that surface
    reaches would quietly shrink the swept area a second time, invisibly — which is the failure mode this
    whole file exists to prevent.
    """
    covered = covered_surfaces(SRC)
    by_module: dict[str, list] = {}
    for surface in discover_public_surfaces(SRC).values():
        by_module.setdefault(surface.module, []).append(surface)
    for module, surfaces in sorted(by_module.items()):
        funcs = surfaces[0].module_functions
        predicates = frozenset(_type_predicates(funcs))
        public_names = {s.node.name for s in surfaces}
        helpers = set()
        # one step of call closure: a private helper called by a public surface is on the path too
        for surface in surfaces:
            for node in ast.walk(surface.node):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                        and node.func.id.startswith("_") and node.func.id in funcs \
                        and node.func.id not in public_names:
                    helpers.add(node.func.id)
        for surface in sorted(surfaces, key=lambda s: s.qualname):
            if surface.key not in covered:
                continue
            yield module, surface.qualname, surface.node, _parameters(surface.node), predicates, True
        for name in sorted(helpers):
            yield module, name, funcs[name], _reachable_params(funcs, name), predicates, False


def _parameters(fn) -> set[str]:
    a = fn.args
    names = {p.arg for p in (a.posonlyargs + a.args + a.kwonlyargs)}
    if a.vararg:
        names.add(a.vararg.arg)
    if a.kwarg:
        names.add(a.kwarg.arg)
    # `self` / `cls` are the receiver, never a relying-party value
    return names - {"self", "cls"}


def _type_predicates(funcs: dict) -> set[str]:
    """Module-local predicates that narrow their own first argument with ``isinstance``.

    A type narrowing does not have to be spelled ``isinstance(x, T)`` at the point of use.
    ``statuslist._is_plain_int(value)`` is ``isinstance(value, int) and not isinstance(value, bool)``
    behind a name, and a rule that knows only the inline spelling flags the perfectly narrowed rendering
    underneath it. Recognising a guard by ONE syntactic form is the same enumeration mistake this file
    exists to prevent, one level down — so a predicate qualifies when its own code proves it is one: a
    local function whose FIRST parameter is ``isinstance``-checked inside its body AND which returns only
    boolean expressions.

    That second condition is what keeps this from becoming a hole. ``decision.validate_decision_predicate``
    also ``isinstance``-checks its first argument, but it returns a LIST OF ERRORS: it tells you the shape
    was wrong, it does not narrow the value, and the fields it accepts can still be arbitrarily large. Only
    a function that answers yes-or-no about a type is treated as a guard.
    """
    out = set()
    for name, fn in funcs.items():
        args = fn.args.posonlyargs + fn.args.args
        if not args:
            continue
        first = args[0].arg
        returns = [n for n in ast.walk(fn) if isinstance(n, ast.Return)]
        if not returns:
            continue
        if not all(_is_boolean_expression(r.value) for r in returns):
            continue
        for node in ast.walk(fn):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                    and node.func.id == "isinstance" and node.args \
                    and isinstance(node.args[0], ast.Name) and node.args[0].id == first:
                out.add(name)
                break
    return out


def _is_boolean_expression(node) -> bool:
    """A yes/no answer: ``True``/``False``, a comparison, ``and``/``or``/``not`` over those, or a direct
    ``isinstance(...)`` call. Anything else — a list, a dict, a formatted string — is not a type answer."""
    if isinstance(node, ast.Constant):
        return isinstance(node.value, bool)
    if isinstance(node, ast.Compare):
        return True
    if isinstance(node, ast.BoolOp):
        return all(_is_boolean_expression(v) for v in node.values)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "isinstance":
        return True
    return False


def _isinstance_guarded(fn, param: str, predicates: frozenset[str] = frozenset()) -> set[int]:
    """Line numbers of type tests on `param` inside `fn` — inline ``isinstance(param, ...)``, or a call to
    a module-local type predicate (see :func:`_type_predicates`) with `param` as its first argument.

    A message below such a test renders a value whose type has been narrowed. This checks PRESENCE, not
    dominance — a guard on a branch that does not actually reach the message would satisfy it. That is the
    documented weak point of this rule; it is deliberately permissive here so the rule stays mechanical
    rather than approximate in the unsafe direction.
    """
    lines = set()
    for node in ast.walk(fn):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
            continue
        if node.func.id != "isinstance" and node.func.id not in predicates:
            continue
        if node.args and isinstance(node.args[0], ast.Name) and node.args[0].id == param:
            lines.add(node.lineno)
    return lines


def _unbounded_renderings(fn, params: set[str],
                          predicates: frozenset[str] = frozenset()) -> list[tuple[int, str]]:
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
                guards = _isinstance_guarded(fn, param, predicates)
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


class _HostileRepr:
    """Hashable, compares equal to a hash-algorithm name, and refuses to be rendered.

    It is the shape a message-rendering defect needs in order to show itself: the check can reach a verdict
    about it, only the EXPLANATION cannot. `__eq__`/`__hash__` let it satisfy a set-membership test, so
    every guard except the rendering one is happy.
    """

    def __init__(self, like: str = "sha1") -> None:
        self._like = like

    def __hash__(self) -> int:
        return hash(self._like)

    def __eq__(self, other: object) -> bool:
        return other == self._like

    def __repr__(self) -> str:
        raise RecursionError("this value refuses to be rendered")

    __str__ = __repr__


# `evaluate_renewal_policy` is exported, documents a VerificationResult, and was outside the swept family
# purely because its name begins with `evaluate_`. These are the shapes that left it as a raw exception.
# Each one is a relying-party-supplied argument or a field of a caller-built ArchiveTimeStamp — the
# dataclass validates nothing — so none of them needs a malicious document to arrive.
_HOSTILE_POLICY_VECTORS = [
    ("ats time is a string", {"time": "1000"}, {"max_ats_age": 10}, 2000),
    ("ats time is None", {"time": None}, {"max_ats_age": 10}, 2000),
    ("ats hash_alg is unhashable", {"hash_alg": ["sha256"]}, {"deprecated_algs": frozenset({"x"})}, 2000),
    ("now is a string", {}, {"max_ats_age": 10}, "2000"),
    ("max_ats_age is a string", {}, {"max_ats_age": "x"}, 2000),
    ("deprecated_algs is not a container", {}, {"deprecated_algs": 7}, 2000),
    ("max_ats_age is a deep structure", {}, {"max_ats_age": _deep()}, 2000),
    ("ats hash_alg refuses rendering", {"hash_alg": _HostileRepr()},
     {"deprecated_algs": frozenset({"sha1"})}, 2000),
]


@pytest.mark.parametrize("label,ats_kw,policy_kw,now",
                         _HOSTILE_POLICY_VECTORS,
                         ids=[v[0] for v in _HOSTILE_POLICY_VECTORS])
def test_evaluate_renewal_policy_returns_a_verdict_for_hostile_scalars(label, ats_kw, policy_kw, now):
    """The never-raise contract on the surface the name-keyed rule could not see."""
    from proofbundle.renewal import ArchiveTimeStamp, RenewalPolicy, evaluate_renewal_policy
    from proofbundle.errors import VerificationResult

    fields = {"hash_alg": "sha256", "covered_digest": "ab" * 32, "time": 1000}
    fields.update(ats_kw)
    sequence = [[ArchiveTimeStamp(**fields)]]
    policy = RenewalPolicy(**policy_kw)
    try:
        outcome = evaluate_renewal_policy(sequence, policy=policy, now=now)
    except BaseException as exc:  # noqa: BLE001 — that is the whole point of the test
        pytest.fail(f"{label}: undeclared {type(exc).__name__} escaped a verdict-returning surface: {exc}")
    assert isinstance(outcome, VerificationResult)
    assert all(isinstance(c.detail, str) and len(c.detail) <= 4096 for c in outcome.checks), (
        "the explanation must stay bounded, not grow with the input")


@pytest.mark.parametrize("label,ats_kw,policy_kw,now",
                         _HOSTILE_POLICY_VECTORS,
                         ids=[v[0] for v in _HOSTILE_POLICY_VECTORS])
def test_an_unevaluable_renewal_policy_is_never_reported_as_within_policy(label, ats_kw, policy_kw, now):
    """Fail-closed direction. Returning a verdict is only half the contract: 'I could not evaluate this'
    must not come back as 'no renewal due', and it must not be softened to a WARN either — `strictness` is
    read off the very object that turned out to be unusable."""
    from proofbundle.renewal import ArchiveTimeStamp, RenewalPolicy, evaluate_renewal_policy

    fields = {"hash_alg": "sha256", "covered_digest": "ab" * 32, "time": 1000}
    fields.update(ats_kw)
    policy = RenewalPolicy(strictness="warn", **policy_kw)
    outcome = evaluate_renewal_policy([[ArchiveTimeStamp(**fields)]], policy=policy, now=now)
    detail = " ".join(c.detail for c in outcome.checks)
    assert "no renewal due" not in detail, f"{label}: an unusable policy reported as within policy"
    assert not outcome.ok, f"{label}: an unevaluable policy was softened into a passing WARN"


def test_a_well_formed_renewal_policy_says_exactly_what_it_said_before():
    """Backward compatibility, stated as bytes rather than as an intention. The bounded renderer must not
    change a single character of the messages a legitimate producer sees."""
    from proofbundle.renewal import ArchiveTimeStamp, RenewalPolicy, evaluate_renewal_policy

    seq = [[ArchiveTimeStamp("sha256", "ab" * 32, 1000)]]
    within = evaluate_renewal_policy(seq, policy=RenewalPolicy(max_ats_age=1000), now=1500)
    assert within.ok
    assert within.checks[0].detail == "newest ATS (sha256, age 500) is within policy — no renewal due"

    overdue = evaluate_renewal_policy(seq, policy=RenewalPolicy(max_ats_age=10, strictness="fail"),
                                      now=1500)
    assert not overdue.ok
    assert overdue.checks[0].detail == "renewal overdue (FAIL): newest ATS age 500 exceeds max 10"

    deprecated = evaluate_renewal_policy(
        seq, policy=RenewalPolicy(deprecated_algs=frozenset({"sha256"}), strictness="warn"), now=1200)
    assert deprecated.checks[0].detail == (
        "renewal overdue (WARN): newest ATS uses policy-deprecated hash 'sha256'")


def test_renewal_rejection_message_does_not_outweigh_the_rejection():
    """The same class on the two renewal entry points, which raise by contract: the DECLARED
    ``RenewalError`` is fine, a ``RecursionError`` out of building its text is not."""
    from proofbundle.renewal import ArchiveTimeStamp, RenewalError, renew_timestamp

    class _RefusesToRender:
        def __le__(self, other: object) -> bool:
            return True          # "not strictly after" — the check reaches its verdict

        def __format__(self, spec: str) -> str:
            raise RecursionError("this value refuses to be rendered")

        __repr__ = __str__ = __format__  # type: ignore[assignment]

    seq = [[ArchiveTimeStamp("sha256", "ab" * 32, 1000)]]
    with pytest.raises(RenewalError):
        renew_timestamp(seq, time=_RefusesToRender())


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
    "adapters/lm_eval.py::_find_metric::metric",
    "anchors_chia.py::_hexatom::field",
    "anchors_chia.py::_hexbytes::field",
    "bundle.py::_require::field",
    "checkpoint.py::_cosigned_message::timestamp",
    "intoto.py::_declare_content_root_alg::content_root_alg",
    "intoto.py::_serialize_statement::content_root_alg",
    "policy.py::_reject_unknown::where",
    "policy.py::_require_bool::key",
    "policy.py::_require_dict::where",
    "policy.py::_require_list_of_str::key",
    "policy.py::_validate_checkpoint_entry::idx",
    "policy.py::_validate_pinned_ed25519_pubkey::ctx",
    "policy.py::_validate_root_b64::where",
    "policy_profiles.py::_warn_deprecated_alias::canonical",
    "policy_profiles.py::_warn_deprecated_alias::old_short",
    "pqsig.py::_mldsa_classes::level",
    "relation.py::_validate_edge_digest::path",
    "relation.py::_walk_chain::max_depth",
    "trust_pack.py::_parse_rfc3339_z::s",
}


def _split_violations():
    """(surface violations, helper violations) — the enforcing population and the enumerated one."""
    surface, helper = set(), set()
    for module, qualname, fn, params, predicates, is_surface in _family_functions():
        target = surface if is_surface else helper
        for _lineno, param in _unbounded_renderings(fn, params, predicates):
            target.add(f"{module}::{qualname}::{param}")
    return surface, helper


def test_no_family_member_renders_a_parameter_unbounded():
    """The class-level rule over the surface a relying party actually calls. A public surface added
    tomorrow is covered by this without anyone remembering to edit this file — the population is derived,
    and an undecided surface defaults to covered."""
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
    assert len(family) >= 300, (
        f"the never-raise family collapsed to {len(family)} members — rule is vacuous")


def test_no_pinned_open_surface_is_already_fixed():
    """The other direction of the surface-level ratchet, and the reason an exclusion is an admission rather
    than an exemption.

    Every surface excluded as ``OPEN_UNBOUNDED_RENDERING`` claims to still be violating. If one is repaired
    and its line is left behind, the exclusion list stops describing the real gap and starts hiding a
    surface that is once again unwatched. So a repair has to unpin.
    """
    open_keys = {k for k, reason in SURFACE_DECISIONS.items()
                 if reason == "OPEN_UNBOUNDED_RENDERING"}
    assert open_keys, "no pinned open surfaces — this ratchet has nothing to hold"
    assert "OPEN_UNBOUNDED_RENDERING" in REASON_CODES

    still_violating = set()
    for module, qualname, fn, params, predicates in _all_public_surface_functions():
        if _unbounded_renderings(fn, params, predicates):
            still_violating.add(f"{module}::{qualname}")
    fixed_but_pinned = sorted(open_keys - still_violating)
    assert not fixed_but_pinned, (
        "these surfaces no longer render a parameter unbounded — delete them from SURFACE_DECISIONS so "
        "they rejoin the enforced population:\n  " + "\n  ".join(fixed_but_pinned))


def _all_public_surface_functions():
    """Like :func:`_family_functions` but over the population BEFORE exclusions, so a pinned entry can be
    re-measured. Helpers are not needed here and are not produced."""
    for surface in discover_public_surfaces(SRC).values():
        predicates = frozenset(_type_predicates(surface.module_functions))
        yield surface.module, surface.qualname, surface.node, _parameters(surface.node), predicates


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


_PLANTED_EVALUATE_MODULE = '''
def evaluate_thing_policy(sequence, *, policy, now):
    """A verdict-returning surface whose name no pattern in the old rule anticipated."""
    if not sequence:
        return {"ok": False, "detail": f"nothing to evaluate under {policy} at {now}"}
    return {"ok": True, "detail": "fine"}
'''


def test_a_name_keyed_population_goes_blind_on_the_evaluate_family(tmp_path):
    """The anti-tautology twin for THIS fix, varied on the axis the fix actually decides: which surfaces
    are in the population at all.

    Blinding the RENDERING rule (below) proves the renderer check works. It proves nothing about the leak
    that was found, because the rendering rule was never asked about ``evaluate_renewal_policy``. So plant
    an ``evaluate_``-named surface and show both directions: the derived population sees it, and selecting
    by the old name pattern does not — the exact blindness that let four live sites through.
    """
    from test_surface_family_selector import _LEGACY_NAME_PATTERN

    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "planted.py").write_text(_PLANTED_EVALUATE_MODULE, encoding="utf-8")

    derived = covered_surfaces(pkg)
    assert "planted.py::evaluate_thing_policy" in derived, "the derived population did not see it"
    surface = derived["planted.py::evaluate_thing_policy"]
    found = {p for _line, p in _unbounded_renderings(surface.node, _parameters(surface.node))}
    assert found == {"policy", "now"}, f"the seeing rule found {found}"

    name_keyed = {k for k in derived if _LEGACY_NAME_PATTERN.match(k.split("::")[1])}
    assert not name_keyed, (
        "the legacy name pattern now selects this surface, so it no longer demonstrates the blindness — "
        "re-derive the finding before trusting this test")


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
    from proofbundle import anchors, intoto, renewal
    assert "brief(require_target)" in inspect.getsource(anchors.verify_anchors)
    assert "brief(got)" in inspect.getsource(intoto._intoto_verify_result)

    # the sites the derived population added, checked the same way
    policy_src = inspect.getsource(renewal.evaluate_renewal_policy)
    assert "brief(max_ats_age)" in policy_src and "brief(now)" in policy_src
    assert "brief(time, quote=False)" in inspect.getsource(renewal.renew_timestamp)
    assert "brief(time, quote=False)" in inspect.getsource(renewal.renew_hashtree)
    assert "brief(prior.anchor_status)" in inspect.getsource(renewal._require_prior_anchor)
    # and the floor that stops the arithmetic before the message is ever needed
    assert "_plain_int(newest.time) and _plain_int(now)" in policy_src
