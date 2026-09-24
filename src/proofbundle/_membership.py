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

__all__ = ["is_member", "as_dict", "is_bool"]


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

    WHY A SHARED PREDICATE AND NOT FIVE ``isinstance`` LINES. The register entry that scheduled the work
    names three sites; reading the file finds five in the same reach, and counting them is how this
    class keeps coming back: ``intoto.py:99`` passes the raw value through, ``:246`` maps it through
    ``_RESULT_ENUM[bool(...)]``, ``:251`` picks ``passedTests`` versus ``failedTests``, ``:424`` emits
    ``bool(...)``, and ``:551`` tests truthiness. The module docstring above already argued this once
    for the hashable class, after this repository paid for the instance fix three times. Same argument,
    third class.

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
