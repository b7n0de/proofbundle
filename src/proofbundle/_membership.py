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
from typing import Any, Container

__all__ = ["is_member"]


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
