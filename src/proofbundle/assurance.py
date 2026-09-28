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
from typing import Any, Callable, Optional, TypeGuard, Union

from ._membership import require_switch, stored_str_items

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
    # The digest object is the caller's. Its type is asked with issubclass(type(obj), dict), an identity walk
    # of the real type's MRO: isinstance believes an object's own __class__, so one whose __class__ raised
    # escaped classify_digest_evidence, which never raises (measured), and one that only claimed to be a dict
    # decided the level with its own get(). The value is read from what the dict stores (dict.get of the base
    # type, then str.__str__), so a dict or str subclass (an OrderedDict, say) is read as the dict and the str
    # it is, and none of its own methods (get, __getitem__, __eq__) runs. 3a8074fc asked type(obj) is dict and
    # classified an OrderedDict digest as CLAIMED where main 31816e08 said REFERENCE_WELL_FORMED (measured).
    #
    # Round 5: dict.get of the base type still compared a stored key whose hash equals hash("sha256") through
    # that key's own __eq__, so {K("sha256"): ...} with a raising __eq__ made this never-raise function raise
    # (measured on 3d5b992a), and one whose __eq__ answered True stood in for "sha256". The key is now found by
    # iterating what the dict stores, and only an exact str key counts (_membership.stored_str_items).
    if not issubclass(type(obj), dict):
        return False
    value = stored_str_items(obj).get("sha256")
    if not issubclass(type(value), str):
        return False
    return bool(_SHA256_HEX.match(str.__str__(value)))


def _is_key_material(value: Any) -> TypeGuard[Union[bytes, bytearray]]:
    """True only for a plain ``bytes`` or ``bytearray`` object: the one form of key material a resolver or
    a caller hands in that this package reads.

    ``type()``, never ``isinstance()``: ``isinstance`` also believes an object's own ``__class__``, so an
    object whose ``__class__`` property says ``bytes`` passed, and was then read with its own ``__len__``
    and ``__bytes__`` (32 and ``b""`` reached INDEPENDENTLY_ATTESTED with zero bytes of key material; a
    raising ``__class__`` or ``__len__`` escaped the never-raise verifiers). A real ``bytes`` subclass is
    refused as well, for the same reason: its ``__len__`` and ``__bytes__`` are the caller's code. Plain
    ``bytes`` and ``bytearray`` are read with ``len()`` and ``bytes()`` without running any caller code.
    Shared by :func:`classify_receiver_corroboration` and ``outcome.verify_outcome_receipt``, so the
    ladder and ``receiver_role_trusted`` judge one answer by one rule."""
    return type(value) is bytes or type(value) is bytearray


def classify_digest_evidence(digest_obj: Any, *, applicable: bool = True,
                             evidence_resolver: Optional[Callable[[Any], bool]] = None) -> dict:
    """Classify ONE digest-bound field (e.g. an ``effectDigest``, a ``decisionRef``, one
    ``evidenceRefs[]`` entry) onto the :class:`EvidenceLevel` ladder. Never raises; a malformed input
    classifies as ``CLAIMED``, it never crashes the caller.

    ``applicable=False`` (e.g. ``status != 'executed'``) -> ``level=None`` (not applicable, mirrors the
    existing ``*_proven=None`` convention: a non-applicable claim is not a WEAK claim, it is not a claim
    at all). ``applicable`` must be a bool: anything else raises
    :class:`~proofbundle.errors.SwitchTypeError` (a ``TypeError``) before anything is classified. It was
    read by its truth, so ``applicable=None``, ``0``, ``""`` or ``[]`` made a field not applicable, and
    :func:`evidence_ladder_summary`, which ignores such a field, rose above the weakest real link
    (measured at 3a8074fc: CLAIMED and CONTENT_RESOLVED summarised to CONTENT_RESOLVED). The digest
    object and the resolver still never make this function raise; the switch is the caller's own
    argument, not the evidence under classification.

    ``evidence_resolver``, when supplied, is called with ``digest_obj`` and must return True iff the
    digest was checked against the ACTUAL resolved bytes (mirrors ``resolve_evidence_ref``'s
    ``content_root_ok``). Only the exact ``True`` promotes: any other answer, a truthy one included
    (``1``, ``"true"``, ``"false"``, a non-empty list, an object whose ``__bool__`` says True), keeps
    ``REFERENCE_WELL_FORMED``, the answer's own ``__bool__`` is never called, and when the answer is
    not a bool at all the detail says so. On True the level reaches ``CONTENT_RESOLVED``, never higher —
    ``RECEIPT_CRYPTO_VERIFIED``/``POLICY_AUTHORIZED``/``INDEPENDENTLY_ATTESTED`` are each a STRONGER claim
    this classifier does not itself verify (conflating "checked against real bytes" with "the real bytes'
    OWN signature was checked" would be exactly the kind of unearned strength bump No-Overclaim forbids).
    A raising/exception-throwing ``evidence_resolver`` is treated as False (fail-closed: an exception is
    not evidence, never silently promoted).
    """
    if not require_switch(applicable, "applicable"):
        return {"level": None, "level_name": None, "detail": "not applicable"}
    if not _is_digest(digest_obj):
        return {"level": EvidenceLevel.CLAIMED, "level_name": EvidenceLevel.CLAIMED.name,
                "detail": "no well-formed sha256 digest object present"}
    level = EvidenceLevel.REFERENCE_WELL_FORMED
    detail = "a well-formed sha256 digest object is present (attacker-choosable content, not content-checked)"
    if evidence_resolver is not None:
        try:
            answer = evidence_resolver(digest_obj)
        except Exception:  # noqa: BLE001 - fail-closed: a raising resolver proves nothing
            answer = False
        # The contract is a bool, so only the exact True promotes. bool(answer) would promote on 1, "true",
        # "false", [0] or any object whose __bool__ says True, and would run the caller's __bool__. The
        # answer is never rendered into the detail either (rendering could run caller code as well).
        if answer is True:
            level = EvidenceLevel.CONTENT_RESOLVED
            detail = "digest checked against actually-resolved content bytes"
        elif type(answer) is not bool:
            detail += (" (the evidence resolver answered something other than True; only the exact True "
                       "promotes)")
    return {"level": level, "level_name": level.name, "detail": detail}


def classify_receiver_corroboration(digest_obj: Any, *, applicable: bool = True,
                                    evidence_resolver: Optional[Callable[[Any], bool]] = None,
                                    independent_attestation_resolver: Optional[Callable[[Any], bool]] = None,
                                    executor_key_id: Optional[str] = None,
                                    receiver_key_id: Optional[str] = None,
                                    expected_receiver_public_key: Optional[bytes] = None,
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

    Never raises on the digest, the resolvers or the key material: a raising
    ``independent_attestation_resolver`` is fail-closed (treated as False, the base
    ``classify_digest_evidence`` level is kept — never silently promoted, mirrors the existing
    ``evidence_resolver`` contract). ``applicable`` is a switch and must be a bool; anything else raises
    :class:`~proofbundle.errors.SwitchTypeError` from :func:`classify_digest_evidence`, before anything is
    classified or any resolver is called. The resolver's answer attests only when it is the exact ``True`` or
    32 bytes of key material in a plain ``bytes`` or ``bytearray`` object (see KEY BINDING below): any
    other answer, a truthy one included (``1``, ``"true"``, ``"false"``, a non-empty list, an object
    whose ``__bool__`` says True, an object whose ``__class__`` says ``bytes``, a ``bytes`` subclass),
    keeps the base level, none of the answer's own methods (``__bool__``, ``__class__``, ``__len__``,
    ``__bytes__``) is called, and when the answer is not a bool the detail says so. The key ids are
    judged the same way: each must be a plain ``str``, so a key id's own ``__class__`` or ``__eq__`` never
    decides independence. The resolver is only ever consulted once the digest has ALREADY reached
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
    # type() and not isinstance(): isinstance believes an object's own __class__, and the == below would then
    # run that object's __eq__, so a key id that only claims to be a str decided independence (measured:
    # INDEPENDENTLY_ATTESTED for a receiver key id whose __class__ says str and whose __eq__ says False).
    if type(executor_key_id) is not str or type(receiver_key_id) is not str or receiver_key_id == executor_key_id:
        return {**base, "detail": base["detail"] + " (independence not provable: executor and receiver key "
                "ids must both be present and differ; an absent/equal key id is self-corroboration — "
                "principal-level independence for two distinct keys needs the outcomeReceivers trust role)"}
    # KEY BINDING (deep gate 2026-09-05, L1-600-02, receiver half): a `receiverKeyId` is a LABEL the
    # executor wrote into its own predicate. When the caller can name the key the pack holds for that
    # label (``expected_receiver_public_key``, from a Trust Pack's ``keys[receiverKeyId].publicKey``),
    # independence is asserted only if the resolver returns THE SIGNING KEY of the referenced statement
    # (32 raw Ed25519 bytes) and it equals the expectation. A resolver that answers a bare ``True``
    # cannot bind a label to a key, so with an expectation in hand it earns no promotion — the base level
    # is kept and the detail says why. Without an expectation the contract is unchanged (additive).
    try:
        res = independent_attestation_resolver(digest_obj)
    except Exception:  # noqa: BLE001 - fail-closed: a raising resolver proves nothing
        res = False
    # Key material only as a plain bytes/bytearray object (_is_key_material): an object whose __class__ says
    # bytes, or a bytes subclass, is not read with its own __len__/__bytes__, and so neither promotes on zero
    # bytes nor raises out of this never-raise function; it falls to the branches below like any other
    # answer that is neither True nor key material.
    if _is_key_material(res):
        signer_key = bytes(res) if len(res) == 32 else None
        if signer_key is None:
            return {**base, "detail": base["detail"] + " (attestation resolver returned key material that is "
                    "not a 32-byte Ed25519 key — not attested)"}
        if expected_receiver_public_key is not None and not _is_key_material(expected_receiver_public_key):
            # The expectation is the caller's too: bytes() on it ran its __bytes__ and raised a raw TypeError
            # for a str (measured), out of a function that never raises.
            return {**base, "detail": base["detail"] + " (expected_receiver_public_key is not a bytes or "
                    "bytearray object, so the signer key cannot be compared with it — not attested)"}
        if expected_receiver_public_key is not None and signer_key != bytes(expected_receiver_public_key):
            return {**base, "detail": base["detail"] + " (KEY_ID_NOT_BOUND_TO_SIGNER: the referenced statement "
                    "is signed by a key that is not the trust pack's key for receiverKeyId — the label names "
                    "a party that did not sign)"}
        attested = True
    elif expected_receiver_public_key is not None:
        return {**base, "detail": base["detail"] + " (receiverKeyId has key material in the trust pack, but "
                "the attestation resolver did not return the signing key, so the label cannot be bound to "
                "the signer — no promotion; return the 32-byte signer key from the resolver to bind it)"}
    else:
        # Only the exact True attests (the contract is a bool); bool(res) would attest on 1, "true", "false",
        # [0] or any object whose __bool__ says True, and would run the caller's __bool__.
        attested = res is True
        if not attested and type(res) is not bool:
            return {**base, "detail": base["detail"] + " (the attestation resolver answered neither True nor "
                    "32 bytes of key material in a plain bytes or bytearray object, and the answer is not a "
                    "bool; only the exact True promotes)"}
    if not attested:
        return base
    return {"level": EvidenceLevel.INDEPENDENTLY_ATTESTED,
            "level_name": EvidenceLevel.INDEPENDENTLY_ATTESTED.name,
            "detail": "the referenced content is itself a validly-signed statement from a party distinct "
                      "from the original claimant (receiver/observer corroboration)"}


def _has_level(field: Any) -> bool:
    """A rollup input counts only as a ``dict`` whose stored ``level`` is an ``int`` (an
    :class:`EvidenceLevel` is one); a bool is not a level. The types are asked with ``issubclass`` on the
    real type (an identity walk of its MRO), never with ``isinstance``: a level whose own ``__class__`` said
    ``int`` passed and then decided the rollup with its own ``__lt__``/``__gt__``, and a raising
    ``__class__`` escaped :func:`evidence_ladder_summary` and :func:`evidence_ladder_best`, which never
    raise (measured on both). The level is read from what the dict stores (``dict.get`` of the base type)
    and compared by its value (:func:`_level_value`), so a dict or int subclass (an OrderedDict field, an
    IntEnum level of the caller's) counts as the dict and the int it is and none of its own methods runs.

    3a8074fc asked ``type(field) is dict`` and ``type(level) in (int, EvidenceLevel)``, so an OrderedDict
    field and a level from the caller's own IntEnum were skipped as not applicable, and
    :func:`evidence_ladder_summary`, the AND rollup, rose past them: a CLAIMED OrderedDict field beside a
    CONTENT_RESOLVED one summarised to CONTENT_RESOLVED, where main 31816e08 said CLAIMED (measured).

    Round 5: ``dict.get`` of the base type still compared a stored key whose hash equals ``hash("level")``
    through that key's own ``__eq__``: ``{K("level"): 0}`` with a raising ``__eq__`` made both rollups, which
    never raise, raise (measured on 3d5b992a), and one answering True stood in for ``"level"``. The fields
    are read with :func:`_membership.stored_str_items`, where only an exact str key counts."""
    return _level_value(field) is not None


def _level_value(field: Any) -> Optional[int]:
    """The level a rollup input stores, as a plain int (``int.__int__`` of the base type reads the value an
    int subclass stores and runs none of its methods), or None when it stores none (see :func:`_has_level`)."""
    level: Any = stored_str_items(field).get("level")
    level_type = type(level)
    if level_type is bool or not issubclass(level_type, int):
        return None
    return int.__int__(level)


def _level_key(field: Any) -> int:
    """The sort key of a field that passed :func:`_has_level`: its stored level, read by :func:`_level_value`."""
    level = _level_value(field)
    return level if level is not None else -1


def _pick(field: dict) -> dict:
    """``level`` and ``level_name`` of the chosen field, read the way :func:`_level_value` reads them."""
    stored = stored_str_items(field)
    return {"level": stored.get("level"), "level_name": stored.get("level_name")}


def evidence_ladder_summary(*fields: dict) -> dict:
    """Roll several :func:`classify_digest_evidence` results into ONE summary using AND semantics: a chain
    of evidence is only as strong as its WEAKEST applicable link (e.g. ``decision.py``'s
    ``evidenceRefs[]`` — ``evidence_bound`` is only meaningful when EVERY ref is bound). Non-applicable
    (``level=None``) fields are ignored, never silently counted as CLAIMED. When no field is applicable,
    returns ``level=None`` (mirrors the existing ``evidence_bound=None`` "nothing to bind" convention —
    never a vacuous strong verdict over an empty set)."""
    # adversarial re-audit: a non-dict ``*fields`` entry (int) crashed ``f.get('level')`` with a raw AttributeError
    # out of these package-top-level surfaces; a non-Mapping field is simply not-applicable (skipped), never a raise.
    applicable = [f for f in fields if _has_level(f)]
    if not applicable:
        return {"level": None, "level_name": None, "fields": list(fields)}
    weakest = min(applicable, key=_level_key)
    return {**_pick(weakest), "fields": list(fields)}


def evidence_ladder_best(*fields: dict) -> dict:
    """Roll several :func:`classify_digest_evidence` results into ONE summary using OR semantics: only ONE
    of several alternative digest fields needs to hold for the claim to be satisfied (e.g.
    ``outcome.py``'s ``effectDigest`` OR ``actualActionDigest`` — the existing boolean
    ``outcome_execution_proven`` is exactly this OR). Picks the STRONGEST applicable field. When no field
    is applicable, returns ``level=None``."""
    # adversarial re-audit: a non-dict ``*fields`` entry (int) crashed ``f.get('level')`` with a raw AttributeError
    # out of these package-top-level surfaces; a non-Mapping field is simply not-applicable (skipped), never a raise.
    applicable = [f for f in fields if _has_level(f)]
    if not applicable:
        return {"level": None, "level_name": None, "fields": list(fields)}
    strongest = max(applicable, key=_level_key)
    return {**_pick(strongest), "fields": list(fields)}
