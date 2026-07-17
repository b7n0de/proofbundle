"""OpenTimestamps anchor (EXPERIMENTAL; the `[anchors]` extra).

Honest lifecycle (this is where OTS is easy to over-claim):

* A fresh stamp is submitted to public calendars and is **PENDING** — it commits your root but is not
  yet anchored in Bitcoin. A pending proof is a WARN, never a full-strength anchor.
* ``ots upgrade`` embeds the Bitcoin block-header path; only then is the proof **upgraded** and
  self-contained (no calendar needed to verify).
* Verifying an upgraded proof still needs the Bitcoin **block header** for the attested height — per the
  documented client path, a local (pruned) Bitcoin node. There is no documented "header file instead of
  a node" mode, and we do not claim one. If the caller supplies the block header (its Merkle root) in the
  anchor's ``frozen`` block, we verify against it offline; otherwise we report, honestly, that the proof
  is upgraded but Bitcoin verification needs a node/header — we never silently PASS it.

``proof`` is the serialized detached OTS proof; ``canonicalRoot`` is the exact bytes that were stamped.
"""
from __future__ import annotations

from typing import Optional


def _classify(timestamp):
    """Return (has_bitcoin, bitcoin_heights, has_pending) over all attestations in the proof."""
    from opentimestamps.core.notary import (  # noqa: PLC0415
        BitcoinBlockHeaderAttestation, PendingAttestation,
    )
    heights, has_pending = [], False
    for _msg, att in timestamp.all_attestations():
        if isinstance(att, BitcoinBlockHeaderAttestation):
            heights.append(att.height)
        elif isinstance(att, PendingAttestation):
            has_pending = True
    return (bool(heights), heights, has_pending)


def verify_opentimestamps(proof: bytes, canonical_root: bytes, *, frozen: dict,
                          now: Optional[int] = None, rp_trust: Optional[dict] = None) -> dict:
    """Fail-closed OTS verify. Returns {ok, detail, warn, status}. A pending proof is warn (status
    'pending'); an upgraded proof with no RELYING-PARTY block header is not-ok-but-not-warn honest report
    (status 'needs_rp_trust'); an upgraded proof verified against an RP-supplied header is ok (status
    'confirmed').

    WP-A1 (Owner-GO, trust from the relying party): the Bitcoin block header that turns an upgraded proof
    into a CONFIRMED anchor is trust material and MUST come from the relying party (``rp_trust`` — CLI
    ``--bitcoin-header`` / policy ``anchors.bitcoin_block_headers``), NEVER from the bundle's own ``frozen``
    block (which the producer controls and could backdate with a self-committed header). A frozen header is
    reported as EVIDENCE (``frozenEvidence``) but is never trusted. Without RP trust material an upgraded
    proof is honestly ``needs_rp_trust`` (ok=False), so ``--require-anchor`` is unmet → exit 3."""
    try:
        from opentimestamps.core.serialize import BytesDeserializationContext  # noqa: PLC0415
        from opentimestamps.core.timestamp import DetachedTimestampFile  # noqa: PLC0415
    except ImportError:
        return {"ok": False, "warn": False, "status": "no_lib",
                "detail": "opentimestamps anchor needs proofbundle[anchors] (opentimestamps)"}
    try:
        dtf = DetachedTimestampFile.deserialize(BytesDeserializationContext(proof))
    except Exception as exc:   # any malformed proof → FAIL (fail-closed)
        return {"ok": False, "warn": False, "status": "malformed",
                "detail": f"OTS proof did not deserialize: {exc}"}
    # structural binding: the proof must commit to EXACTLY the canonical root
    if dtf.file_digest != canonical_root:
        return {"ok": False, "warn": False, "status": "unbound",
                "detail": "OTS proof does not commit to the target canonical root"}
    has_bitcoin, heights, has_pending = _classify(dtf.timestamp)
    if not has_bitcoin:
        if has_pending:
            return {"ok": False, "warn": True, "status": "pending",
                    "detail": "OTS proof is PENDING (submitted to calendars, not yet on Bitcoin) — "
                              "run `ots upgrade`; not a full anchor yet"}
        return {"ok": False, "warn": False, "status": "empty",
                "detail": "OTS proof has no Bitcoin or pending attestation"}
    # upgraded: to verify offline we need the block's Merkle root for the attested height. WP-A1: that root
    # is TRUST material — it must come from the RELYING PARTY (rp_trust.bitcoin_block_headers, i.e. their
    # own trusted/pruned Bitcoin node), NEVER from the producer-controlled `frozen` block. A frozen header
    # is surfaced as evidence only. BitcoinBlockHeaderAttestation's own check is exactly
    # `attestation_message == block_header.hashMerkleRoot`; we do that comparison directly against the
    # RP-supplied root (equivalent, and avoids reconstructing a full CBlockHeader).
    rp_headers = (rp_trust or {}).get("bitcoin_block_headers") or {}
    frozen_headers = frozen.get("bitcoinBlockHeaderMerkleRootsByHeight") or {}
    if not rp_headers:
        # no RP trust material → cannot confirm. Frozen alone is NOT trust (it could be a self-committed
        # backdated header). Honest not-ok report; --require-anchor stays unmet (exit 3).
        return {"ok": False, "warn": False, "status": "needs_rp_trust", "needs_rp_trust": True,
                "frozenEvidence": bool(frozen_headers),
                "detail": f"OTS proof is upgraded (Bitcoin height {heights}) but confirming it needs a "
                          "relying-party-supplied Bitcoin block header (--bitcoin-header / policy "
                          "anchors.bitcoin_block_headers). The bundle's own frozen header is producer-"
                          "controlled evidence, not trust; not claiming a pass"}
    # WP-A1.b (Berkeley audit, 2026-07-16): a proof can carry SEVERAL Bitcoin attestations (independent
    # calendar branches, a reorg-era re-anchor, a bad/tampered branch alongside a good one). Because the
    # structural binding above pins EVERY attestation's message to the same canonical root (all_attestations
    # walks the tree from `file_digest`, which must equal `canonical_root`), confirming on ANY branch whose
    # attested block matches the relying-party header is sound — the branch cannot commit an unrelated root.
    # So we scan ALL RP-covered heights and confirm as soon as one matches; a single wrong/tampered branch
    # must NEVER short-circuit and mask a genuinely confirmable one (that would be a False-REJECT / DoS).
    # Per-branch diagnostics are retained: if no branch confirms we surface whether the covered heights were
    # present-and-wrong (block_mismatch, a tamper signal), carried bad relying-party hex (bad_header), or
    # were simply uncovered (upgraded_unverified).
    mismatch_heights: list = []
    bad_header_heights: list = []
    for msg, att in dtf.timestamp.all_attestations():
        height = getattr(att, "height", None)
        if height is None:
            continue
        merkle_root_hex = rp_headers.get(str(height))
        if not merkle_root_hex:
            continue
        try:
            expected = bytes.fromhex(merkle_root_hex)
        except ValueError:
            # a malformed RP header for THIS height must not short-circuit — another branch may confirm.
            bad_header_heights.append(height)
            continue
        if msg == expected:
            return {"ok": True, "warn": False, "status": "confirmed", "rp_trusted": True,
                    # WP-A2: a Bitcoin HEIGHT is the proof's native trusted-time unit — reported
                    # structured, never converted to a wall-clock guess (the header time is not
                    # part of the supplied material).
                    "trustedTime": {"source": "bitcoin_block", "height": height},
                    "detail": f"OTS proof confirmed: committed in the Bitcoin block at height {height} "
                              "(merkle root supplied by the relying party)"}
        mismatch_heights.append(height)
    # No RP-covered branch matched. Fall through with an honest, tamper-visible diagnostic.
    if mismatch_heights:
        return {"ok": False, "warn": False, "status": "block_mismatch", "rp_trusted": True,
                "mismatchHeights": sorted(mismatch_heights),
                "badHeaderHeights": sorted(bad_header_heights),
                "detail": f"no OTS Bitcoin attestation matched the relying-party block merkle root: "
                          f"present-and-wrong at height(s) {sorted(mismatch_heights)}"
                          + (f", invalid relying-party hex at height(s) {sorted(bad_header_heights)}"
                             if bad_header_heights else "")}
    if bad_header_heights:
        return {"ok": False, "warn": False, "status": "bad_header", "rp_trusted": True,
                "badHeaderHeights": sorted(bad_header_heights),
                "detail": f"relying-party Bitcoin block merkle root is not valid hex for height(s) "
                          f"{sorted(bad_header_heights)}, and no other covered branch confirmed"}
    return {"ok": False, "warn": False, "status": "upgraded_unverified", "needs_rp_trust": True,
            "frozenEvidence": bool(frozen_headers),
            "detail": f"OTS proof is upgraded (Bitcoin height {heights}) but the relying party supplied no "
                      "block header for any attested height; not claiming a pass"}


# ── Calendar transparency (WP-B1) ──────────────────────────────────────────────────────────────────
# A stamp is created with the aid of MULTIPLE remote calendars — the OpenTimestamps client submits to
# three default endpoints across at least two independent operators (a/b.pool.opentimestamps.org run by
# OpenTimestamps, a.pool.eternitywall.com run by Eternity Wall), and requires at least two to reply.
# Surfacing WHICH calendars carry a proof is the redundancy evidence: an outage or defunding of any one
# calendar removes none of the others' PendingAttestations, and verifying an UPGRADED proof needs no
# calendar at all. These helpers are pure transparency: they read a proof, never trust it, never raise.

_KNOWN_CALENDAR_OPERATORS = (
    ("opentimestamps.org", "opentimestamps"),
    ("eternitywall.com", "eternitywall"),
    ("catallaxy.com", "catallaxy"),
)


def calendar_operator(uri: str) -> str:
    """Best-effort operator label for a calendar URI. Operator redundancy (distinct OPERATORS), not URL
    count, is what tolerates an outage or a defunding — two URLs on one operator are one point of
    failure. Maps a known calendar host to its operator; an unknown host falls back to its last two
    host labels so a distinct third-party or self-hosted calendar still counts as a distinct operator.
    Never raises (a transparency helper must not break a verify path).

    BLIND SPOT (documented, not hidden — Berkeley audit 2026-07-16): this is a bare-hostname heuristic,
    NOT a verified-independent-entity claim. The last-two-labels fallback does not know the public-suffix
    boundary, so a ccSLD host like ``cal.example.co.uk`` collapses to ``co.uk`` (and ``example.com.au`` to
    ``com.au``): two genuinely independent operators under the same ccSLD would be counted as one, and the
    label itself is a registrable-domain guess, not an attestation of who runs the calendar. It is a
    transparency hint only; for a real independence claim, pin the operators you trust. An optional
    ``tldextract`` dependency would resolve the public-suffix boundary; it is deliberately not added here,
    so this stays a heuristic."""
    if not isinstance(uri, str) or not uri:
        return "unknown"
    from urllib.parse import urlparse  # noqa: PLC0415
    host = (urlparse(uri if "://" in uri else "https://" + uri).hostname or "").lower()
    if not host:
        return "unknown"
    for needle, label in _KNOWN_CALENDAR_OPERATORS:
        if host == needle or host.endswith("." + needle):
            return label
    parts = [p for p in host.split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def calendar_uris(proof: bytes) -> list[str]:
    """The distinct calendar URIs whose PendingAttestations carry ``proof`` (WP-B1 transparency).
    Fail-closed: without the ``[anchors]`` extra, or on a malformed proof, returns ``[]`` (never raises).
    An UPGRADED proof that no longer retains pending attestations honestly returns ``[]`` — its calendar
    dependency is already discharged, which is precisely the calendar-independence being surfaced."""
    try:
        from opentimestamps.core.notary import PendingAttestation  # noqa: PLC0415
        from opentimestamps.core.serialize import BytesDeserializationContext  # noqa: PLC0415
        from opentimestamps.core.timestamp import DetachedTimestampFile  # noqa: PLC0415
    except ImportError:
        return []
    try:
        dtf = DetachedTimestampFile.deserialize(BytesDeserializationContext(proof))
    except Exception:   # malformed → no calendars, never raise (fail-closed transparency)
        return []
    uris: set[str] = set()
    for _msg, att in dtf.timestamp.all_attestations():
        if isinstance(att, PendingAttestation):
            uri = getattr(att, "uri", None)
            if isinstance(uri, bytes):
                try:
                    uri = uri.decode("utf-8")
                except Exception:
                    continue
            if isinstance(uri, str) and uri:
                uris.add(uri)
    return sorted(uris)


def calendar_operators(uris) -> list[str]:
    """The distinct, sorted operator labels behind a list of calendar URIs (WP-B1). ``len(...)`` is the
    OPERATOR redundancy — the number that survives an outage, unlike a raw URL count."""
    return sorted({calendar_operator(u) for u in (uris or [])})
