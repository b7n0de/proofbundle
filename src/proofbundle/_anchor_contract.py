"""The registered-anchor-verifier contract, enforced at the verifier rather than at its caller.

THE RULE THE PROJECT PUBLISHES. :func:`proofbundle.anchors.register_anchor_type` tells third-party
extension authors, in its own docstring, that an anchor verifier "MUST be fail-closed: return
``{'ok': False, ...}`` on any doubt, never raise for an ordinary bad proof". That is a contract this
package asks outsiders to honour.

THE FINDING. The FIRST-PARTY verifiers did not honour it. ``verify_rfc3161`` called ``rp.get(...)`` and
``frozen.get(...)`` on values that need not be mappings, so a non-mapping ``frozen`` or ``rp_trust``
terminated the verifier with a raw ``AttributeError``. The same shape sits in ``verify_opentimestamps``
(reached once a proof deserializes far enough to consult the frozen/RP material) and, through delegation,
in ``verify_markovian``. Nothing leaks to a relying party today, because ``anchors.verify_anchor`` wraps
every dispatch in ``except Exception`` — but "our caller happens to catch it" is not the contract we
published, and an extension author reading our code learns the wrong lesson from it.

WHY A MECHANISM AND NOT FIVE EDITS. The violated invariant is not "``frozen`` is unchecked in one
function". It is: *a registered anchor verifier terminates inside its own verdict contract, for every
argument*. Enumerating the argument shapes that are known to break would be a blocklist — it has to be
COMPLETE to work, and the next verifier, the next optional library, or the next nested field extends it.
So the guard is inverted: the two arguments the anchor layer documents as MAPPINGS are normalised to a
mapping before the verifier body runs, and anything else that goes wrong — an unknown shape, a hostile
``__repr__``, a library raising from deep inside — lands on the REJECTED side by default. Unknown forms
fail closed without anyone having predicted them.

WHAT IT DOES NOT DO. It is not a substitute for the checks inside a verifier: normalising ``rp_trust``
to ``{}`` REMOVES trust material, so it can only ever make a verdict more conservative, never turn a
failure into a pass. It does not sanitise proofs, and it does not swallow ``KeyboardInterrupt`` or
``SystemExit`` (those are not verdicts about a proof and must stay fatal).
"""
from __future__ import annotations

import functools
from typing import Callable, Optional

#: The verifier keyword arguments the anchor layer specifies as JSON objects: ``frozen`` (the bundle's
#: own evidence block) and ``rp_trust`` (relying-party trust material). Both are read with ``.get`` by
#: every verifier that consults them, so both are normalised to a mapping before the body runs. This is
#: a contract statement about ARGUMENTS, not a list of bad values: a shape not named here still lands on
#: the rejected side through the fail-closed backstop below.
MAPPING_ARGUMENTS = ("frozen", "rp_trust")

#: Marker attribute set on a wrapped verifier. A structural gate can ask a registered verifier whether it
#: carries the contract without calling it.
CONTRACT_ATTRIBUTE = "__proofbundle_failclosed_anchor_verifier__"

_DEFAULT_REJECTION = {"ok": False, "warn": False, "status": "verifier_error"}


def _rejection(template: dict, exc: BaseException) -> dict:
    """The verdict a verifier returns when its body could not produce one.

    Only the EXCEPTION TYPE NAME is reported. The offending value is never rendered here: this runs on a
    never-raise path, and a message that interpolates a caller-supplied value can fail harder than the
    check it explains (see :mod:`proofbundle._brief`).
    """
    out = dict(template)
    out["detail"] = ("anchor verifier refused the input fail-closed "
                     f"({type(exc).__name__}); an anchor that cannot be checked never passes")
    return out


def failclosed_anchor_verifier(fn: Optional[Callable] = None, *,
                               rejection: Optional[dict] = None) -> Callable:
    """Hold a registered anchor verifier to the contract ``register_anchor_type`` publishes.

    Usable bare (``@failclosed_anchor_verifier``) or with a verdict template
    (``@failclosed_anchor_verifier(rejection={...})``) for a verifier whose verdict dict has a different
    key set, so the rejected verdict keeps that surface's own shape instead of inventing a second one.

    Three things happen, in order:

    1. every argument in :data:`MAPPING_ARGUMENTS` that is not a mapping becomes ``{}`` — strictly less
       material for the verifier to trust, so this can never manufacture a pass;
    2. the verifier runs; any ``Exception`` it lets escape becomes the rejected verdict;
    3. a verdict that is not a mapping is itself a broken verifier, and is replaced by the rejected one —
       otherwise ``verify_anchor``'s ``res.get(...)`` would be the thing that crashes.

    ``functools.wraps`` keeps ``__wrapped__``, so ``inspect.signature`` still reports the ORIGINAL
    signature. That matters: ``anchors._call_verifier`` decides whether to pass ``rp_trust`` by
    introspecting the verifier, and a wrapper advertising ``**kwargs`` would break a pre-WP-A1 verifier.
    """
    template = dict(rejection) if rejection is not None else dict(_DEFAULT_REJECTION)

    def _decorate(target: Callable) -> Callable:
        @functools.wraps(target)
        def _guarded(*args, **kwargs):
            for name in MAPPING_ARGUMENTS:
                if name in kwargs and not isinstance(kwargs[name], dict):
                    kwargs[name] = {}
            try:
                verdict = target(*args, **kwargs)
            except Exception as exc:  # noqa: BLE001 — the whole point: a verifier returns, it does not raise
                return _rejection(template, exc)
            if not isinstance(verdict, dict):
                return _rejection(template, TypeError("verifier returned a non-mapping verdict"))
            return verdict

        setattr(_guarded, CONTRACT_ATTRIBUTE, True)
        return _guarded

    return _decorate if fn is None else _decorate(fn)


def is_failclosed_anchor_verifier(fn: object) -> bool:
    """Whether ``fn`` carries the fail-closed anchor-verifier contract wrapper."""
    return bool(getattr(fn, CONTRACT_ATTRIBUTE, False))
