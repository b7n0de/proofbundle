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

DELIBERATELY NOT A ``try/except TypeError``: that would also swallow a TypeError raised by a broken
container or a __hash__ with a bug, i.e. it would convert unrelated real defects into a quiet False.
The test here is exactly the property the call site needs — "can this value be a member at all".
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
    return value in container
