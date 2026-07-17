"""B6 evidence-pack hardening for offline long-term verification (EXPERIMENTAL; ADR 0006).

Goal: a pack built from a receipt verifies OFFLINE on a second machine from bundled data — no calendar,
no network. The OTS anchor already verifies offline from a relying-party Bitcoin block header
(``anchors_ots.verify_opentimestamps``); this module adds the PACK layer around it:

* ``ots_upgraded_proof_is_self_contained`` — a proof with a Bitcoin block-header attestation is upgraded
  and self-contained (the calendar is no longer needed to verify existence-in-Bitcoin). A pending-only or
  malformed proof is not.
* ``build_evidence_pack`` — assemble the self-contained proof + the canonical root + the calendars the
  PROOF proves it carries (``provenCalendars``, the only redundancy that is evidence) kept separate from
  any producer-DECLARED calendars (``declaredCalendars``, ``verified: false``) and, optionally, a COPY of
  the Bitcoin block headers as EVIDENCE.
* ``verify_evidence_pack`` — verify the pack with NO network I/O, delegating to the OTS verifier.

WP-A1 boundary (never crossed). The header a pack bundles is producer-controlled EVIDENCE, never trust —
a producer could bundle a self-committed, backdated header. Confirmation therefore still needs a
RELYING-PARTY header (``rp_trust.bitcoin_block_headers``). That header can be an OFFLINE trusted Bitcoin
checkpoint the relying party ships, so "needs a relying-party header" does NOT mean "needs the network".
A pack with a bundled header but no relying-party trust is honestly ``needs_rp_trust``, not a pass.

Honesty on scope. The MECHANISM here is complete and tested. Producing a pack from a REAL confirmed
receipt (submitting to public calendars, waiting for Bitcoin confirmation, ``ots upgrade``) is an
Owner-gated external anchor submission and is tracked as the OPEN end-to-end step in ADR 0006 — not
claimed here.
"""
from __future__ import annotations

import base64
from typing import Optional

from .anchors_ots import _classify, calendar_operators, calendar_uris, verify_opentimestamps

__all__ = [
    "ots_upgraded_proof_is_self_contained",
    "build_evidence_pack",
    "verify_evidence_pack",
    "describe_proof",
]


def ots_upgraded_proof_is_self_contained(proof: bytes) -> bool:
    """True iff ``proof`` is an UPGRADED OTS proof (a Bitcoin block-header attestation) — self-contained,
    so verifying existence-in-Bitcoin no longer needs a calendar. A pending-only or malformed proof is
    False (fail-closed; never over-claim a pending proof as self-contained)."""
    try:
        from opentimestamps.core.serialize import BytesDeserializationContext  # noqa: PLC0415
        from opentimestamps.core.timestamp import DetachedTimestampFile  # noqa: PLC0415
    except ImportError:
        return False
    try:
        dtf = DetachedTimestampFile.deserialize(BytesDeserializationContext(proof))
    except Exception:
        return False
    has_bitcoin, _heights, _has_pending = _classify(dtf.timestamp)
    return has_bitcoin


def build_evidence_pack(canonical_root: bytes, proof: bytes, *,
                        declared_calendars: Optional[list[str]] = None,
                        bundled_headers: Optional[dict[str, str]] = None) -> dict:
    """Assemble an offline-verifiable evidence pack around an OTS proof.

    Calendar redundancy is split into two clearly-separated, No-Fake honest classes (Berkeley audit,
    2026-07-16 — previously the two were conflated and a producer's unverified ``--calendar`` list was
    surfaced as if it were audit evidence):

    * ``provenCalendars`` — the calendar URIs the PROOF ITSELF carries (its retained PendingAttestations,
      read from ``proof``, never trusted-but-cryptographically-present). ``operatorRedundancy`` is the count
      of distinct INDEPENDENT operators behind the PROVEN calendars and is the ONLY redundancy number that
      is audit evidence. An UPGRADED proof that no longer retains any pending attestation honestly yields
      ``provenCalendars == []`` and ``operatorRedundancy == 0``: after upgrade the calendar dependency is
      discharged and which calendars carried the stamp is no longer recoverable FROM THE PROOF.
    * ``declaredCalendars`` — producer testimony (``declared_calendars``, the CLI ``--calendar-declared``
      flag), recorded verbatim for documentation with ``declaredCalendarsVerified: false``. It NEVER feeds
      ``operatorRedundancy`` and is NOT audit evidence — a producer could list any calendars it never used.

    ``bundled_headers`` (a ``height -> block merkle-root hex`` map) is copied into the pack as EVIDENCE only
    (``frozen`` block, WP-A1: never trusted by the verifier). The pack never contains a secret."""
    proven = calendar_uris(proof)                       # proof-derived: cryptographically present, real
    proven_operators = calendar_operators(proven)
    pack: dict = {
        "type": "opentimestamps-evidence-pack",
        "packVersion": "v0.2",
        "canonicalRoot": base64.b64encode(canonical_root).decode(),
        "proof": base64.b64encode(proof).decode(),
        "selfContained": ots_upgraded_proof_is_self_contained(proof),
        "provenCalendars": proven,
        "provenCalendarOperators": proven_operators,
        # WP-B1: OPERATOR redundancy = distinct INDEPENDENT operators the PROOF proves (never a raw URL
        # count, never a producer claim). This is the only redundancy figure a reviewer may treat as
        # evidence; it is 0 for an upgraded proof that retains no pending attestation, which is honest.
        "operatorRedundancy": len(proven_operators),
        "bundledHeaderEvidence": bool(bundled_headers),
    }
    declared = sorted(set(declared_calendars or []))
    if declared:
        # producer testimony only — recorded for documentation, flagged unverified, NEVER counted as
        # redundancy evidence (No-Fake: a producer could list calendars it never submitted to).
        pack["declaredCalendars"] = declared
        pack["declaredCalendarOperators"] = calendar_operators(declared)
        pack["declaredCalendarsVerified"] = False
    if bundled_headers:
        # producer-controlled EVIDENCE, surfaced in the frozen block; verify_opentimestamps treats it as
        # frozenEvidence and never as trust (WP-A1).
        pack["frozen"] = {"bitcoinBlockHeaderMerkleRootsByHeight": dict(bundled_headers)}
    return pack


def verify_evidence_pack(pack: dict, *, rp_trust: Optional[dict] = None,
                         now: Optional[int] = None) -> dict:
    """Verify an evidence pack OFFLINE (no network I/O). Delegates to the OTS verifier with the pack's
    proof + canonical root; the pack's bundled header is passed as ``frozen`` EVIDENCE, and confirmation
    happens only against a relying-party header (``rp_trust``), which may be an offline checkpoint.

    Returns the OTS verifier's result dict ({ok, detail, warn, status, …}). Fail-closed on a malformed
    pack (missing/!b64 proof or root)."""
    try:
        proof = base64.b64decode(pack["proof"], validate=True)
        canonical_root = base64.b64decode(pack["canonicalRoot"], validate=True)
    except (KeyError, ValueError, TypeError) as exc:
        return {"ok": False, "warn": False, "status": "malformed_pack",
                "detail": f"evidence pack is missing or has a non-base64 proof/canonicalRoot: {exc}"}
    frozen = pack.get("frozen") or {}
    return verify_opentimestamps(proof, canonical_root, frozen=frozen, now=now, rp_trust=rp_trust)


def describe_proof(proof: bytes) -> dict:
    """Lifecycle transparency for a raw OTS proof (WP-B1) — for ``proofbundle anchor inspect`` and the
    upgrade report. Returns ``{state, selfContained, bitcoinHeights, provenCalendars,
    provenCalendarOperators, operatorRedundancy}`` where ``state`` is one of ``pending`` | ``upgraded`` |
    ``empty`` | ``malformed`` | ``no_lib``. Every calendar figure here is PROOF-DERIVED (proven): it reads
    the proof's own retained attestations, never a producer claim, so ``operatorRedundancy`` is real
    evidence. Read-only and fail-closed: it reports state, it never trusts the proof (confirmation is still
    the relying party's job via ``verify``/``verify_evidence_pack``)."""
    base = {"state": "malformed", "selfContained": False, "bitcoinHeights": [],
            "provenCalendars": [], "provenCalendarOperators": [], "operatorRedundancy": 0}
    try:
        from opentimestamps.core.serialize import BytesDeserializationContext  # noqa: PLC0415
        from opentimestamps.core.timestamp import DetachedTimestampFile  # noqa: PLC0415
    except ImportError:
        return {**base, "state": "no_lib"}
    try:
        dtf = DetachedTimestampFile.deserialize(BytesDeserializationContext(proof))
    except Exception:
        return base
    has_bitcoin, heights, has_pending = _classify(dtf.timestamp)
    cals = calendar_uris(proof)
    ops = calendar_operators(cals)
    state = "upgraded" if has_bitcoin else ("pending" if has_pending else "empty")
    return {"state": state, "selfContained": has_bitcoin, "bitcoinHeights": sorted(heights),
            "provenCalendars": cals, "provenCalendarOperators": ops, "operatorRedundancy": len(ops)}
