"""One safe membership test for attacker-controlled values (deep gate iteration 8, L3-01..L3-05).

THE DEFECT CLASS, stated as the violated assumption rather than as a code shape: *a value taken from
parsed JSON is hashable.* It is not. `set` and `dict` membership HASHES the left-hand operand, so

    if predicate.get("status") not in _OUTCOME_STATUS:   # _OUTCOME_STATUS is a set

raises a bare ``TypeError: unhashable type: 'list'`` the moment the attacker sends
``{"status": []}`` — before any signature is checked, and out of a function whose entire contract is
that it returns a verdict or raises ``ProofBundleError``. Iteration 8 confirmed it on four surfaces at
once, including the flagship ``verify_bundle`` and a correctly SIGNED outcome receipt.

WHY THIS IS A MODULE AND NOT FOUR ``isinstance`` GUARDS. This repository has already paid for the
instance fix three times (statuslist.py:122, kbjwt.py:151, kbjwt.py:230): each time the OUTER argument
was hardened and the INNER field kept crashing. Four guards would close four lines and leave the
assumption intact everywhere else, including in code not yet written. What is fixed here is the
assumption, in one place, with a scanner (tests/test_membership_hashable_guard.py) that fails on any
new unguarded site.

WHY ``try/except TypeError`` AND NOT ONLY ``isinstance(value, Hashable)``. The first version of this
module used the isinstance check alone and argued against the try/except as "too broad". That argument
was wrong, and the mandatory review lane refuted it on 2026-08-26 (verdict REJECT, one finding held):
``collections.abc.Hashable`` tests whether ``__hash__`` EXISTS, not whether calling it succeeds.
Measured: ``isinstance(("a", []), Hashable)`` is ``True`` and ``hash(("a", []))`` raises anyway — a
tuple inherits ``__hash__`` and only fails once it hashes its elements. So the guard whose entire
contract is "never raises" could raise. That is the very class it exists to remove, one level down;
this is the third time in one day that a fix reproduced its own defect inside itself.

HONEST NOTE ON REACH, because the finding was half right and half wrong. The reviewer's example was
``{"a": []}``, and that one does NOT get through: ``dict.__hash__`` is ``None``, so the isinstance
check already rejects it. Only the TUPLE case gets through — and ``json.loads`` never produces a
tuple, so no attacker-controlled JSON reaches it today. It is fixed anyway: a guard that is only
correct because of what its callers happen to pass is not a guard, and "not reachable today" is a
property of the callers, not of this function.

The isinstance check stays as the fast path (it is the common case and needs no exception machinery).
Swallowing a TypeError from a genuinely broken ``__hash__`` is fine here rather than regrettable: such
an object cannot be an element of a hash-based container either, so ``False`` remains the true answer
to the only question this function asks.
"""
from __future__ import annotations

from collections.abc import Hashable
from typing import Any, Container, TypeGuard

__all__ = ["is_member", "as_dict", "is_bool", "same_json_value", "_MISSING"]

# A pair budget for `same_json_value`, and the NUMBER IS DERIVED, not chosen. What it exists for is the
# one input the walk cannot finish: a self-referential container, which `json.loads` never produces but
# a direct caller can build. It must therefore sit ABOVE anything a legal document can reach.
#
# THE FIRST VALUE WAS 100_000 AND THAT WAS WRONG, recorded because the correction is the lesson. The
# house's own parser admits `VerificationBudget.json_nodes = 200_000` nodes per document (`budget.py`),
# so a bound of 100_000 pairs refused input the house considers legal — and it refused it wearing the
# WRONG LABEL: a lens built an honest claim whose `suite` held 110_000 items, both sides bit-identical,
# and `verify_bundle` reported "cross-receipt substitution; suite differ from the signed claim". There
# was no substitution. A fail-closed stop that reports itself as a specific different finding is worse
# than no stop, because the reader acts on the diagnosis.
#
# Twice the node budget clears every legal pair with room to spare, and the room is larger than the
# first wording claimed. That wording said two documents contribute their own nodes EACH; a lens
# measured the actual bound and it is ONE side's node count, because a container contributes
# `len(container)` pairs here and `len(container)` nodes to `_strict_json`, so a comparison of two
# same-shaped documents costs at most what ONE of them is allowed to be. 400_000 against a real edge
# of ~200_000 is therefore conservative rather than tight — the safe direction, and now the measured
# one. Confirmed at the edge: 199_992 items still bind; one more makes the document itself illegal
# and it is refused as malformed, never as a mismatch. The relationship is pinned in
# `tests/test_bindung_vergleicht_typen.py`, not asserted here, because a number explained in a
# comment is exactly what goes stale in silence.
#
# IT COUNTS PAIRS PUSHED, NOT PAIRS POPPED, and that is the difference between a bound and a
# decoration. The first version counted pops, so a self-referential node of width W pushed W new
# pairs on EVERY pop while the counter rose by one: a lens measured a 200_000-wide self-referential
# dict growing from 235 MB to 2988 MB in twelve seconds, monotone, with no end reachable. Raising
# the bound made that WORSE. Counting what goes ON the stack stops it at the first pop.
# The width needed is far smaller than that first measurement suggested: a second lens reproduced
# non-termination at width 1000 (5.75 GB and growing when it was killed) and for a MUTUAL reference
# a<->b at width 1000 as well. With the push count, every one of those returns False in under 0.2 s
# and under 75 MB. A number that names the worst case somebody happened to try is not the bound.
_COMPARE_PAIR_BUDGET = 400_000

# Only these carry a JSON scalar. Anything else reaching the value branch is not a decoded JSON value,
# and `==` cannot be trusted to answer for it: a lens passed an object whose `__eq__` returns True
# unconditionally and got `same_json_value(obj, "an unrelated string") -> True` (measured 2026-09-24).
# `bool` is absent on purpose — it is decided one branch earlier, and listing it here would re-admit
# the int conflation this function exists to remove.
_JSON_SCALAR = (str, int, float, type(None))

# Read-once sentinel. `field in claim` followed by `claim.get(field)` are TWO reads of one object; see
# `same_json_value`'s dict branch for the measured version of that mistake.
_MISSING = object()


def is_member(value: Any, container: Container) -> bool:
    """``value in container``, but ``False`` instead of ``TypeError`` for an unhashable value.

    An unhashable value cannot be an element of a hash-based container, so ``False`` is not a
    convenient lie — it is the correct answer, and it lets the caller's existing "not one of the
    allowed values" branch produce the typed rejection it was always meant to produce.

    Containers that do not hash (``tuple``, ``list``) are handled by the same call unchanged; routing
    them through here too is what makes a later ``tuple`` -> ``set`` refactor safe instead of silently
    arming this defect again.
    """
    if not isinstance(value, Hashable):
        return False
    try:
        return value in container
    except TypeError:
        # `__hash__` exists but failed — a tuple whose elements are unhashable is the reachable
        # shape. See the module docstring: the isinstance check alone was measurably not enough.
        return False

def is_bool(value: Any) -> TypeGuard[bool]:
    """True only for a genuine ``bool``. The verdict-bearing fields of a claim go through here.

    THE DEFECT CLASS, as the violated assumption: *a field that carries a verdict holds a boolean.* It
    does not have to. ``bool("false")`` is ``True``, and ``"false"`` is a non-empty string, so it also
    survives every presence check of the shape ``claim.get(k) in (None, "")``. CWE-1287, improper
    validation of the specified TYPE of an input: the field is recognised, its type is not.

    WHAT THIS RESTORES IS MONOTONICITY, which is the stronger statement and the reason this is not
    merely tidiness. The in-toto attestation spec calls a policy monotonic when ignoring an attestation
    or a field within it can never turn a DENY into an ALLOW. Measured on 2026-09-24 on ``d8c9c61`` by
    calling the exporters DIRECTLY, the opposite held there:

        to_test_result_statement   False -> 'FAILED'   'false' -> 'PASSED'
        to_eval_result_predicate   False -> False      'false' -> True
        svr_properties             False -> []         'false' -> ['PROOFBUNDLE_THRESHOLD_MET']
        to_intoto_statement        False -> False      'false' -> the string, passed through raw

    WHERE IT DID **NOT** HOLD, stated because an earlier version of this docstring claimed it did. The
    signed SVR path was never exposed: ``export_svr_dsse`` decodes first, and A-15 typed ``passed`` at
    that boundary on 2026-09-19, so a string verdict is refused there and on every CLI path. The draft
    that described a signed SVR carrying PROOFBUNDLE_THRESHOLD_MET for ``"false"`` had measured
    ``/home/konrad/proofbundle``, a checkout 47 commits behind main and 9 ahead of it, where A-15 is
    absent. The exposure is the DIRECT library caller, exactly as the register scoped it.

    WHY A SHARED PREDICATE AND NOT SIX ``isinstance`` LINES. The register entry that scheduled the work
    names three sites; reading the file finds five in the same reach, and counting them is how this
    class keeps coming back: ``intoto.py:99`` passes the raw value through, ``:246`` maps it through
    ``_RESULT_ENUM[bool(...)]``, ``:251`` picks ``passedTests`` versus ``failedTests``, ``:424`` emits
    ``bool(...)``, and ``:551`` tests truthiness. The module docstring above already argued this once
    for the hashable class, after this repository paid for the instance fix three times. Same argument,
    third class.

    AND THEN A SIXTH, found only after the first five were already fixed and pushed: ``sdjwt_issue.py``
    copies ``passed`` into the always-open claims of an SD-JWT and SIGNS it. That one was missed because
    the scanner beside this module looked for truthiness CONTEXTS -- ``if claim["passed"]``, ``bool(...)``,
    a ternary -- and an unexamined pass-through into a signed artefact is none of those while being the
    same violated assumption and a worse outcome. The count in this paragraph is therefore not decoration:
    each number here was once the number someone believed was final. ``policy.py:269`` has carried
    ``_require_bool`` with this reasoning in its docstring since before any of them, which is the sharper
    embarrassment -- the knowledge existed in this package at one surface and never travelled to the
    others.

    THE VERIFY BOUNDARY ROUTES THROUGH HERE TOO, and not because it was missing a check. A-15's inline
    ``isinstance(claim.get("passed"), bool)`` was right and is why the signed paths held. It calls this
    predicate now so the boundary and the exporters answer one question with one function; a second
    check beside it would have been two promises for one invariant.

    ``isinstance(value, bool)`` is the whole test and it is the right one: ``bool`` subclasses ``int``,
    so an ``int``-typed check would accept ``True`` while this rejects ``1`` and ``0``, which is what a
    JSON document that meant a number must not be allowed to mean.

    A ``TypeGuard`` AND NOT A PLAIN ``bool``, because mypy said so and was right: a caller that has
    just established the type should not have to assert it again. ``TypeGuard`` narrows the positive
    branch, which is the one every caller here uses (``if not is_bool(x): refuse``), so the value is a
    ``bool`` to the type checker from that line on. ``typing.TypeGuard`` exists from 3.10, which is this
    package's floor.

    STATED LIMIT, not an assurance. A ``numpy.bool_`` is NOT a ``bool`` subclass and is rejected here.
    That is the safe direction for a signed attestation, and it is a real edge rather than a theoretical
    one, because ``adapters/eee.py`` imports numpy: a harness that hands a numpy scalar straight into a
    claim gets a refusal naming the type. The fix for that is a conversion at the harness boundary,
    where the value is known, not a wider test here.
    """
    return isinstance(value, bool)


def as_dict(value: Any) -> dict:
    """``value`` if it is a dict, else ``{}`` — the safe form of the ``(x or {}).get(...)`` idiom.

    THE DEFECT CLASS: ``(x or {})`` only replaces a FALSY ``x``. A TRUTHY non-dict — a ``str``/``list``/
    ``int``/``True`` from attacker-controlled JSON — slips straight through and the downstream ``.get``
    raises a bare ``AttributeError`` out of a never-raise verify surface (deep gate: ``verify_bundle`` via
    ``sdjwt_issue.check_binds_bundle`` on a truthy non-dict ``receipt``). ``anchors_chia_add.py`` already
    closed the exact class with an ``_as_dict``; routing container access through ONE shared helper closes
    it as an assumption, not one line, and the scanner (tests/test_membership_hashable_guard.py) fails on a
    new unguarded ``(x or {}).get`` site."""
    return value if isinstance(value, dict) else {}


def same_json_value(a: Any, b: Any, *, pair_budget: int = _COMPARE_PAIR_BUDGET) -> bool:
    """``a == b`` for two decoded JSON values, without conflating a JSON boolean with a JSON number.

    THE DEFECT CLASS, as the violated assumption: *two values that compare equal carry the same JSON
    type.* They need not. ``bool`` subclasses ``int``, so ``True == 1`` and ``False == 0`` — the same
    language fact ``is_bool`` above already names in its own docstring, four paragraphs about why an
    ``int``-typed check would wrongly accept ``True``. The knowledge was in this module and did not
    travel to the one place that COMPARES such a field: ``sdjwt_issue.check_binds_bundle``, whose
    docstring promises the SD-JWT's always-open claims match the signed bundle payload *bit-exact* and
    which, measured on 2026-09-24 against ``058ed6fc``, delivered loose equality instead:

        SD-JWT ``passed: true``      vs bundle ``passed: 1``       -> bound
        SD-JWT ``passed: true``      vs bundle ``passed: 1.0``     -> bound
        SD-JWT ``threshold: 0``      vs bundle ``threshold: false`` -> bound
        SD-JWT ``passed: true``      vs bundle ``passed: false``   -> not bound  (the control)

    The first three pairs are two claims that ``require_bool_verdict`` declares incompatible, reported
    as one and the same. It is the R-B4 class on the one path the establisher never runs.

    WHAT THIS IS **NOT**, stated because overstating it was the first reading. No verdict flips: ``1``
    and ``True`` are the same verdict, so nothing false-passes in the pass/fail sense. What breaks is
    the binding attestation — a signed derived view is certified as this bundle's view when it is a
    view of a differently-typed claim.

    THE RULE IS DERIVED FROM RFC 8785 AND NOT INVENTED, which is what keeps it from over-refusing.
    Measured with the ``rfc8785`` canonicalizer, JCS serialises ``true`` and ``1`` and ``1.0`` as
    ``true``, ``1``, ``1`` — so ``true``/``1`` differ and MUST refuse, while ``1``/``1.0`` are the
    SAME canonical bytes and must keep binding. Distinguishing int from float here would refuse pairs
    the canonical form calls identical: a new defect in the other direction. Only the boolean/number
    distinction is restored, because that is the only one JCS itself makes.

    WHY NOT CALL THE CANONICALIZER, which would be the semantically exact answer. ``canonicalize_statement``
    lives behind the optional ``[eval]`` extra and fail-closes with ``CanonicalizerUnavailable`` without
    it. The caller sits inside the flagship ``verify_bundle`` path, which works on the base install
    today; routing it through an extra would shrink that reach to buy exactness this comparison can
    reach with stdlib alone.

    ITERATIVE AND NOT RECURSIVE, with an explicit stack. The ``!=`` this replaces recurses in C, where
    CPython guards the depth; a hand-written recursion would hit Python's much shallower limit and turn
    a nested payload into a ``RecursionError`` out of a never-raise verify surface — the same class this
    module exists for, one level down. Nesting is handled because a scalar rule alone would close the
    instance and leave ``[true]`` against ``[1]`` open.
    """
    stack = [(a, b)]
    gesehen = 1
    return _walk(stack, gesehen, pair_budget)


def _walk(stack: list, gesehen: int, pair_budget: int) -> bool:
    """The walk itself, with a guard around EVERY protocol call and around nothing else.

    WHY NOT ONE GUARD AROUND THE WHOLE WALK, which is what this was for one iteration of the gate.
    A lens injected four separate typos into this function — one per branch, plus one in
    `check_binds_bundle`'s own field loop — and every one of them left as a clean `False` on honest,
    bit-identical input. Of the 137 tests that touch these functions, two to nineteen failed
    depending on the branch, and not one of them is written for that class; they are over-refusal
    guards that happened to notice. A `MemoryError` came back as "the documents differ".

    The justification for the broad form said: a value whose protocol methods raise cannot be SHOWN
    equal. That covers exceptions from the VALUE. It does not cover exceptions from THIS code, and
    the broad form could not tell them apart. `is_member` above is the house precedent and it is
    narrow for exactly this reason: it guards the one call its own docstring names.

    So each `try` below contains protocol calls and nothing else. Bookkeeping sits outside, where a
    defect of mine raises and is seen. That is not a breach of the never-raise contract: the contract
    protects a caller from hostile INPUT, and a silent wrong verdict is worse than a visible crash.
    """
    while stack:
        x, y = stack.pop()
        if isinstance(x, bool) or isinstance(y, bool):
            # `x is y` and not `x == y`: this branch exists precisely because == is too forgiving here.
            if not (isinstance(x, bool) and isinstance(y, bool)) or x is not y:
                return False
        elif isinstance(x, dict) or isinstance(y, dict):
            if not (isinstance(x, dict) and isinstance(y, dict)):
                return False
            # THE KEYS ARE READ ONCE AND THE SAME LIST IS WALKED. The first version decided with
            # `x.keys() != y.keys()` and then walked `for k in x` — two different accessors on one
            # object. A lens built a dict subclass whose `keys()` is truthful while `__iter__` hides a
            # key; it passed the decision and the hidden key was never compared, so two dicts differing
            # at that key came back equal (measured 2026-09-24). This is the SAME class `_verdict`
            # states in its own docstring — "the accessor is read once and the value is returned" —
            # written a day earlier and not carried into the function that compares.
            try:                    # protocol only: keys(), and the hashing the sets do
                schluessel = list(x.keys())
                meine = set(schluessel)
                andere = set(y.keys())
            except Exception:       # noqa: BLE001 — a mapping that raises when read cannot be shown equal
                return False
            if len(schluessel) != len(andere) or meine != andere:
                return False
            # THE BUDGET IS CHECKED BEFORE THE PAIRS ARE BUILT. A lens set the budget to 100, handed
            # in two million keys and measured 744 MB allocated before the refusal fired. The count
            # is known from the key list, so nothing needs building to know it is too much.
            if gesehen + len(schluessel) > pair_budget:
                return False
            gesehen += len(schluessel)
            try:                    # protocol only: __getitem__ on both sides
                paare = [(x[k], y[k]) for k in schluessel]
            except Exception:       # noqa: BLE001 — a key `keys()` reports and `[]` refuses cannot bind
                return False
            stack.extend(paare)
        elif isinstance(x, list) or isinstance(y, list):
            if not (isinstance(x, list) and isinstance(y, list)):
                return False
            try:                    # protocol only: __len__ on both sides
                laenge = len(x)
                gleich_lang = laenge == len(y)
            except Exception:       # noqa: BLE001 — a sequence that raises when measured cannot bind
                return False
            if not gleich_lang:
                return False
            if gesehen + laenge > pair_budget:      # before building, as in the dict branch
                return False
            gesehen += laenge
            try:                    # protocol only: iteration of both sides
                paare = list(zip(x, y))
            except Exception:       # noqa: BLE001
                return False
            stack.extend(paare)
        elif not (isinstance(x, _JSON_SCALAR) and isinstance(y, _JSON_SCALAR)):
            # Not a decoded JSON value, so it cannot be SHOWN equal. Refusing beats asking its `__eq__`,
            # which is the attacker's code when the value is the attacker's object.
            return False
        else:
            try:                    # protocol only: the comparison itself
                ungleich = x != y
            except Exception:       # noqa: BLE001 — a value whose __eq__ raises cannot be shown equal
                return False
            if ungleich:
                return False
    return True
