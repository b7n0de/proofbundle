"""One establisher for the verdict type. There were two, and that is why there was a sixth site.

WHAT THIS MODULE IS. ``require_bool_verdict`` answers one question — *is the value in a claim's
``passed`` field a genuine boolean* — and raises a typed refusal naming the field and the type when it
is not. It is the only implementation of that answer in this package.

WHY IT IS A MODULE AND NOT TWO PRIVATE FUNCTIONS, which is the part worth reading. R-B4 (CWE-1287,
``bool("false") is True``) was fixed on 2026-09-24 in five sites inside ``intoto.py``. A SIXTH site was
found afterwards, in ``sdjwt_issue.py``, and it was the one that SIGNS. The reason it was missed is
recorded in ``_membership.is_bool``: five of six lived in one file, and sweeping a file is not sweeping
a class. The fix then created its own second-order instance — ``intoto._require_bool_verdict`` and
``sdjwt_issue._require_bool_verdict`` became two independent implementations with no shared import and
the same intent. An independent lens of the house deep-gate reported exactly that on the same day:

    "two independent, unconnected implementations with identical intent — risk: a future change at one
     site forgets the other."

That is the class this package has now paid for four times: the hashable-membership class
(``_membership`` module docstring, instance-fixed three times before it became a module), the
``(x or {})`` class, R-B4 itself, and R-B4's own fix. ``policy.py`` has carried a ``_require_bool``
with this reasoning since before any of them — the knowledge existed at one surface and never
travelled. A shared module is how it travels.

WHY NOT IN ``_membership.py``, where ``is_bool`` lives. That module has NO package imports: it is pure
stdlib and is imported by nine others precisely because it depends on nothing. This function must raise
``BundleFormatError``, so it needs ``errors``. Putting it there would give the primitive module a
package dependency to buy one less file, and the primitive module's independence is worth more.

WHAT THE MESSAGE NO LONGER SAYS, stated because it is a real loss and not a cleanup. The former
``sdjwt_issue`` copy added "in the always-open claims of a validly signed SD-JWT" — site-specific, and
the sharpest half of that refusal. One shared message cannot carry four sites' consequences, so ``wo``
names the site and the consequence stays in each caller's docstring, where a reader who needs it is
already standing.
"""
from __future__ import annotations

from typing import Any

from ._membership import is_bool
from .errors import BundleFormatError

__all__ = ["require_bool_verdict"]


def require_bool_verdict(claim: Any, *, wo: str) -> bool:
    """The claim's ``passed`` as a real bool, or a fail-closed refusal naming what arrived.

    ``wo`` is the site, and it appears first in the message, because a refusal that does not say where
    it came from sends the reader looking through four exporters.

    A REFUSAL, NOT A COERCION. Guessing what ``"false"`` was meant to mean is how the string got a
    verdict in the first place; the caller who produced it is the only one who knows, and they are told
    which field and which type. See ``_membership.is_bool`` for the measurement and for why this
    restores monotonicity rather than merely validating a type.

    THE ACCESSOR IS READ ONCE AND THE VALUE IS RETURNED, which is the other half of the guard. A caller
    that re-reads ``claim["passed"]`` after this returns can be handed a different value than the one
    that was checked: for a ``dict`` subclass whose ``get`` and ``__getitem__`` disagree those are two
    values, measured on 2026-09-24 with an object whose ``get("passed")`` returns ``True`` while the
    stored item is the string ``"false"``. Use the return value; do not read the field again.

    ``BundleFormatError`` and NOT ``ValueError``: it is what all sites raised before, and
    ``issubclass(BundleFormatError, ValueError)`` is False — a caller guarding this family writes
    ``except BundleFormatError`` (or ``ProofBundleError``). The refusal forms of the surrounding
    modules are NOT one family; ``tests/test_abweisungsformen_sind_drei.py`` measures the three.
    """
    if not isinstance(claim, dict):
        raise BundleFormatError(f"{wo}: needs a claim object, got {type(claim).__name__}")
    wert = claim.get("passed")
    if not is_bool(wert):
        raise BundleFormatError(
            f"{wo}: `passed` is {type(wert).__name__} {wert!r}, expected a boolean — refusing rather "
            f"than coercing or passing it on, because bool({wert!r}) would read a non-passing verdict "
            "as a PASS (R-B4, CWE-1287)")
    return wert
