"""EvidenceLevel — a uniform, orderable strength ladder over the digest-presence-only 'proven'/'bound'
verify-time checks (2026-07 verify-layer hardening, Finding 03, additive/non-breaking).

WURZEL: ``action_outcome_proven`` (decision.py), ``outcome_execution_proven`` (outcome.py), and the
``evidence_bound`` shape check in decision.py all stop at "does a syntactically valid sha256 digest
OBJECT exist at this field" (``_is_digest``) — a 64-hex string of AN ATTACKER'S CHOOSING satisfies it as
readily as the digest of the real referenced artifact; none of them checks the digest against actual
resolved bytes. ``decision.resolve_evidence_ref`` already exists to go further (it checks a digest against
ACTUAL bytes an offline caller supplies), but no ``verify_*`` path ever calls it — the deeper evidence
primitive is built, never wired.

This module makes the STRENGTH of a 'proven'/'bound' claim explicit and orderable, WITHOUT changing the
existing boolean ``*_proven``/``evidence_bound`` fields (they stay, unchanged, for backward compatibility)
— each ``verify_*`` function gains ADDITIVE, more precise field(s) that classify a claim onto this ladder.
"""
from __future__ import annotations

import enum
import re
from typing import Any, Callable, Optional

__all__ = [
    "EvidenceLevel", "EVIDENCE_LEVEL_NAMES", "classify_digest_evidence",
    "evidence_ladder_summary", "EFFECT_OBSERVED_NOT_IMPLEMENTED",
]

_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


class EvidenceLevel(enum.IntEnum):
    """Ordered ladder from a bare claim to full effect observation (No-Overclaim, Finding 03). Higher is
    strictly stronger; compare/sort with the plain ``int``/``IntEnum`` ordering."""

    CLAIMED = 0                  # a value is asserted but not even shaped as a digest
    REFERENCE_WELL_FORMED = 1    # a syntactically valid sha256 digest OBJECT is present (the old
                                  # *_proven==True / evidence_bound==True bar — attacker-choosable content)
    CONTENT_RESOLVED = 2         # the digest was checked against ACTUALLY RESOLVED bytes
                                  # (mirrors decision.resolve_evidence_ref's content_root_ok)
    RECEIPT_CRYPTO_VERIFIED = 3  # the resolved content is ITSELF a cryptographically verified receipt
    POLICY_AUTHORIZED = 4        # a trust policy additionally authorizes the claim (signer/role pinned)
    INDEPENDENTLY_ATTESTED = 5   # a THIRD PARTY (not the original claimant) attests the same content
    EFFECT_OBSERVED = 6          # the real-world EFFECT itself was observed, not merely a receipt about it


EVIDENCE_LEVEL_NAMES: tuple[str, ...] = tuple(level.name for level in EvidenceLevel)

# EFFECT_OBSERVED is structurally UNREACHABLE from this module alone (Finding 16 — real-world effect
# observation, e.g. a monitored side channel confirming the outcome actually happened in the world, not
# merely that a receipt about it was signed/resolved). No verify_* path in this repo can compute it today.
# Making that explicit here — rather than silently never emitting it — is itself the honest No-Fake point;
# a caller grepping for "EFFECT_OBSERVED" finds this marker, not silence.
EFFECT_OBSERVED_NOT_IMPLEMENTED = (
    "EvidenceLevel.EFFECT_OBSERVED is not reachable by any verify_* path in this repo (depends on "
    "Finding 16 / a real-world effect-observation channel, not yet built) — TODO, tracked, not silently "
    "absent."
)


def _is_digest(obj: Any) -> bool:
    return isinstance(obj, dict) and isinstance(obj.get("sha256"), str) and bool(_SHA256_HEX.match(obj["sha256"]))


def classify_digest_evidence(digest_obj: Any, *, applicable: bool = True,
                             evidence_resolver: Optional[Callable[[Any], bool]] = None) -> dict:
    """Classify ONE digest-bound field (e.g. an ``effectDigest``, a ``decisionRef``, one
    ``evidenceRefs[]`` entry) onto the :class:`EvidenceLevel` ladder. Never raises; a malformed input
    classifies as ``CLAIMED``, it never crashes the caller.

    ``applicable=False`` (e.g. ``status != 'executed'``) -> ``level=None`` (not applicable, mirrors the
    existing ``*_proven=None`` convention: a non-applicable claim is not a WEAK claim, it is not a claim
    at all).

    ``evidence_resolver``, when supplied, is called with ``digest_obj`` and must return True iff the
    digest was checked against the ACTUAL resolved bytes (mirrors ``resolve_evidence_ref``'s
    ``content_root_ok``); on True the level reaches ``CONTENT_RESOLVED``, never higher —
    ``RECEIPT_CRYPTO_VERIFIED``/``POLICY_AUTHORIZED``/``INDEPENDENTLY_ATTESTED`` are each a STRONGER claim
    this classifier does not itself verify (conflating "checked against real bytes" with "the real bytes'
    OWN signature was checked" would be exactly the kind of unearned strength bump No-Overclaim forbids).
    A raising/exception-throwing ``evidence_resolver`` is treated as False (fail-closed: an exception is
    not evidence, never silently promoted).
    """
    if not applicable:
        return {"level": None, "level_name": None, "detail": "not applicable"}
    if not _is_digest(digest_obj):
        return {"level": EvidenceLevel.CLAIMED, "level_name": EvidenceLevel.CLAIMED.name,
                "detail": "no well-formed sha256 digest object present"}
    level = EvidenceLevel.REFERENCE_WELL_FORMED
    detail = "a well-formed sha256 digest object is present (attacker-choosable content, not content-checked)"
    if evidence_resolver is not None:
        try:
            resolved = bool(evidence_resolver(digest_obj))
        except Exception:  # noqa: BLE001 - fail-closed: a raising resolver proves nothing
            resolved = False
        if resolved:
            level = EvidenceLevel.CONTENT_RESOLVED
            detail = "digest checked against actually-resolved content bytes"
    return {"level": level, "level_name": level.name, "detail": detail}


def evidence_ladder_summary(*fields: dict) -> dict:
    """Roll several :func:`classify_digest_evidence` results into ONE summary using AND semantics: a chain
    of evidence is only as strong as its WEAKEST applicable link (e.g. ``decision.py``'s
    ``evidenceRefs[]`` — ``evidence_bound`` is only meaningful when EVERY ref is bound). Non-applicable
    (``level=None``) fields are ignored, never silently counted as CLAIMED. When no field is applicable,
    returns ``level=None`` (mirrors the existing ``evidence_bound=None`` "nothing to bind" convention —
    never a vacuous strong verdict over an empty set)."""
    applicable = [f for f in fields if f.get("level") is not None]
    if not applicable:
        return {"level": None, "level_name": None, "fields": list(fields)}
    weakest = min(applicable, key=lambda f: f["level"])
    return {"level": weakest["level"], "level_name": weakest["level_name"], "fields": list(fields)}


def evidence_ladder_best(*fields: dict) -> dict:
    """Roll several :func:`classify_digest_evidence` results into ONE summary using OR semantics: only ONE
    of several alternative digest fields needs to hold for the claim to be satisfied (e.g.
    ``outcome.py``'s ``effectDigest`` OR ``actualActionDigest`` — the existing boolean
    ``outcome_execution_proven`` is exactly this OR). Picks the STRONGEST applicable field. When no field
    is applicable, returns ``level=None``."""
    applicable = [f for f in fields if f.get("level") is not None]
    if not applicable:
        return {"level": None, "level_name": None, "fields": list(fields)}
    strongest = max(applicable, key=lambda f: f["level"])
    return {"level": strongest["level"], "level_name": strongest["level_name"], "fields": list(fields)}
