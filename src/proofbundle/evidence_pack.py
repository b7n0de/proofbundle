"""B6 evidence-pack hardening for offline long-term verification (EXPERIMENTAL; ADR 0006).

Goal: a pack built from a receipt verifies OFFLINE on a second machine from bundled data — no calendar,
no network. The OTS anchor already verifies offline from a relying-party Bitcoin block header
(``anchors_ots.verify_opentimestamps``); this module adds the PACK layer around it:

* ``ots_upgraded_proof_is_self_contained`` — a proof with a Bitcoin block-header attestation is upgraded
  and self-contained (the calendar is no longer needed to verify existence-in-Bitcoin). A pending-only or
  malformed proof is not.
* ``build_evidence_pack`` — assemble the self-contained proof + the canonical root + the set of calendars
  it was submitted to (multi-calendar redundancy metadata) and, optionally, a COPY of the Bitcoin block
  headers as EVIDENCE.
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


def build_evidence_pack(canonical_root: bytes, proof: bytes, *, calendars: list[str],
                        bundled_headers: Optional[dict[str, str]] = None) -> dict:
    """Assemble an offline-verifiable evidence pack around an OTS proof.

    ``calendars`` is the set of calendar servers the stamp was submitted to; recording two or more is the
    multi-calendar redundancy metadata (``calendarRedundancy`` = distinct count). ``bundled_headers`` (a
    ``height -> block merkle-root hex`` map) is copied into the pack as EVIDENCE only (``frozen`` block,
    WP-A1: never trusted by the verifier). The pack never contains a secret."""
    distinct = sorted(set(calendars))
    operators = calendar_operators(distinct)
    pack: dict = {
        "type": "opentimestamps-evidence-pack",
        "packVersion": "v0.1",
        "canonicalRoot": base64.b64encode(canonical_root).decode(),
        "proof": base64.b64encode(proof).decode(),
        "selfContained": ots_upgraded_proof_is_self_contained(proof),
        "calendars": distinct,
        "calendarRedundancy": len(distinct),
        # WP-B1: OPERATOR redundancy (distinct independent operators) is what tolerates an outage or a
        # defunding — a raw URL count does not, since several URLs may be one operator. Surfaced so a
        # reviewer sees the >=2-operator redundancy (or its absence) at a glance.
        "calendarOperators": operators,
        "operatorRedundancy": len(operators),
        "bundledHeaderEvidence": bool(bundled_headers),
    }
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
    upgrade report. Returns ``{state, selfContained, bitcoinHeights, calendars, calendarOperators,
    operatorRedundancy}`` where ``state`` is one of ``pending`` | ``upgraded`` | ``empty`` |
    ``malformed`` | ``no_lib``. Read-only and fail-closed: it reports state, it never trusts the proof
    (confirmation is still the relying party's job via ``verify``/``verify_evidence_pack``)."""
    base = {"state": "malformed", "selfContained": False, "bitcoinHeights": [],
            "calendars": [], "calendarOperators": [], "operatorRedundancy": 0}
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
            "calendars": cals, "calendarOperators": ops, "operatorRedundancy": len(ops)}
