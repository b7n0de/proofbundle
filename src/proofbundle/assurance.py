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
    "classify_receiver_corroboration",
    "evidence_ladder_summary", "evidence_ladder_best", "EFFECT_OBSERVED_NOT_IMPLEMENTED",
]

_SHA256_HEX = re.compile(r"\A[0-9a-f]{64}\Z")  # \A..\Z (not ^..$): $ matches before a trailing newline


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
#
# Finding 16 UPDATE (receiver/observer corroboration, self-fixable part): the SELF-FIXABLE portion of
# Finding 16 IS now built — outcome.py's optional `receiverRefs` + `classify_receiver_corroboration` below
# make INDEPENDENTLY_ATTESTED (level 5, "a THIRD PARTY attests the same content") reachable when a
# receiver/observer's own signed acknowledgement is resolved and verified as coming from a party distinct
# from the executor. EFFECT_OBSERVED (level 6) stays UNREACHABLE even then — a signed receiver receipt is
# still a RECEIPT ABOUT the effect, never a live-monitored observation of the real-world effect itself; that
# is Finding 16's honestly-documented INHERENT limit (proofbundle cannot itself make a third-party system
# sign anything — real-world side-channel monitoring is ecosystem adoption outside this repo).
EFFECT_OBSERVED_NOT_IMPLEMENTED = (
    "EvidenceLevel.EFFECT_OBSERVED is not reachable by any verify_* path in this repo (Finding 16's "
    "self-fixable receiver-corroboration part now reaches INDEPENDENTLY_ATTESTED; EFFECT_OBSERVED itself "
    "still needs a real-world effect-observation channel, which is an inherent, not-yet-built limit outside "
    "proofbundle's own control) — TODO, tracked, not silently absent."
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


def classify_receiver_corroboration(digest_obj: Any, *, applicable: bool = True,
                                    evidence_resolver: Optional[Callable[[Any], bool]] = None,
                                    independent_attestation_resolver: Optional[Callable[[Any], bool]] = None,
                                    executor_key_id: Optional[str] = None,
                                    receiver_key_id: Optional[str] = None,
                                    ) -> dict:
    """Classify a receiver/observer corroboration ref (Finding 16, additive) ONE STEP BEYOND
    :func:`classify_digest_evidence` — reaches ``EvidenceLevel.INDEPENDENTLY_ATTESTED`` when
    ``independent_attestation_resolver`` confirms the referenced content is ITSELF a validly-signed
    statement from a party DISTINCT from the original claimant (e.g. a receiver's or observer's own
    DSSE-signed acknowledgement of an Action Outcome) — never merely a resolved digest, which is
    :func:`classify_digest_evidence`'s own documented ceiling (its docstring: "RECEIPT_CRYPTO_VERIFIED /
    POLICY_AUTHORIZED / INDEPENDENTLY_ATTESTED are each a STRONGER claim this classifier does not itself
    verify").

    The three-tier informal ladder a caller might reach for here — SELF_ASSERTED / DIGEST_REFERENCED /
    RECEIVER_CORROBORATED — maps onto this module's EXISTING orderable :class:`EvidenceLevel` rather than
    a new competing enum (CLAIMED/REFERENCE_WELL_FORMED ≈ SELF_ASSERTED/DIGEST_REFERENCED,
    INDEPENDENTLY_ATTESTED ≈ RECEIVER_CORROBORATED — "a THIRD PARTY attests the same content" is exactly
    what a receiver/observer corroboration IS).

    Never raises: a raising ``independent_attestation_resolver`` is fail-closed (treated as False, the base
    ``classify_digest_evidence`` level is kept — never silently promoted, mirrors the existing
    ``evidence_resolver`` contract). The resolver is only ever consulted once the digest has ALREADY reached
    at least ``CONTENT_RESOLVED`` — an attacker-choosable digest that was never resolved cannot be promoted
    straight to INDEPENDENTLY_ATTESTED by a permissive attestation resolver alone.

    STRUCTURAL independence (crypto-review, 2026-07-15): "INDEPENDENTLY_ATTESTED" means the corroborating
    statement is from a party DISTINCT from the executor/claimant. proofbundle asserts this only when it can
    PROVE it: a receiver reaches INDEPENDENTLY_ATTESTED ONLY IF BOTH ``executor_key_id`` AND
    ``receiver_key_id`` are present AND they differ. An ABSENT ``executor_key_id`` blocks promotion just as
    an absent/equal receiver key id does — the executor authors and signs its own outcome predicate and
    ``executor.keyId`` is schema-optional, so a one-sided check (fire only when executor_key_id is supplied)
    would be trivially evaded by simply omitting one's own keyId. Without knowing BOTH parties' key ids
    proofbundle cannot show they differ, so it does not claim independence (fail-closed to the base level).

    INHERENT limit (honestly not closed here): two DISTINCT key ids can still belong to the SAME real-world
    principal (an executor using a second key it also controls). proofbundle cannot bind a key id to a
    real-world identity on its own — that is exactly what the ``outcomeReceivers`` Trust Pack role provides
    (``outcome.receiver_trusted_by_role``: a curated list of trusted, genuinely-independent receiver keys).
    So key-id distinctness here is the STRUCTURAL floor; principal-level independence needs that out-of-band
    trust binding."""
    base = classify_digest_evidence(digest_obj, applicable=applicable, evidence_resolver=evidence_resolver)
    if base["level"] is None or base["level"] < EvidenceLevel.CONTENT_RESOLVED or independent_attestation_resolver is None:
        return base
    # Provable distinctness: to ASSERT independence, BOTH key ids must be present, be STRINGS, AND differ.
    # The isinstance(str) guards close a type-confusion evasion (crypto-review 2026-07-15): a non-str
    # receiver_key_id (e.g. ["kid-exec"]) is `!= "kid-exec"` in Python, so a bare `==` distinctness check
    # would read a wrapped copy of the executor's OWN id as "distinct". An absent/non-str/equal key id is
    # self-corroboration that cannot be shown independent -> fail-closed, no promotion.
    if not isinstance(executor_key_id, str) or not isinstance(receiver_key_id, str) or receiver_key_id == executor_key_id:
        return {**base, "detail": base["detail"] + " (independence not provable: executor and receiver key "
                "ids must both be present and differ; an absent/equal key id is self-corroboration — "
                "principal-level independence for two distinct keys needs the outcomeReceivers trust role)"}
    try:
        attested = bool(independent_attestation_resolver(digest_obj))
    except Exception:  # noqa: BLE001 - fail-closed: a raising resolver proves nothing
        attested = False
    if not attested:
        return base
    return {"level": EvidenceLevel.INDEPENDENTLY_ATTESTED,
            "level_name": EvidenceLevel.INDEPENDENTLY_ATTESTED.name,
            "detail": "the referenced content is itself a validly-signed statement from a party distinct "
                      "from the original claimant (receiver/observer corroboration)"}


def evidence_ladder_summary(*fields: dict) -> dict:
    """Roll several :func:`classify_digest_evidence` results into ONE summary using AND semantics: a chain
    of evidence is only as strong as its WEAKEST applicable link (e.g. ``decision.py``'s
    ``evidenceRefs[]`` — ``evidence_bound`` is only meaningful when EVERY ref is bound). Non-applicable
    (``level=None``) fields are ignored, never silently counted as CLAIMED. When no field is applicable,
    returns ``level=None`` (mirrors the existing ``evidence_bound=None`` "nothing to bind" convention —
    never a vacuous strong verdict over an empty set)."""
    # Berkeley re-gate: a non-dict ``*fields`` entry (int) crashed ``f.get('level')`` with a raw AttributeError
    # out of these package-top-level surfaces; a non-Mapping field is simply not-applicable (skipped), never a raise.
    applicable = [f for f in fields if isinstance(f, dict) and f.get("level") is not None]
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
    # Berkeley re-gate: a non-dict ``*fields`` entry (int) crashed ``f.get('level')`` with a raw AttributeError
    # out of these package-top-level surfaces; a non-Mapping field is simply not-applicable (skipped), never a raise.
    applicable = [f for f in fields if isinstance(f, dict) and f.get("level") is not None]
    if not applicable:
        return {"level": None, "level_name": None, "fields": list(fields)}
    strongest = max(applicable, key=lambda f: f["level"])
    return {"level": strongest["level"], "level_name": strongest["level_name"], "fields": list(fields)}
