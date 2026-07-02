"""Public-randomness audit challenges (v1.9) — non-interactive, publicly re-derivable.

The per-sample audit (SPEC §7g) has three challenge modes. Two shipped in v1.5: an *auditor
nonce* (interactive, grinding-impossible) and *self-challenge* (a documented-grindable sanity
check). This module formalizes the third — a **public randomness beacon** — so an audit needs no
live auditor and anyone can re-derive the same challenged indices from published data.

Why a beacon RESISTS grinding without a live auditor, AND WHAT IT ASSUMES: the producer signs the receipt (with its
``samples_root``) at time T. A beacon pulse from a round whose emission time is *after* T did not
exist when the producer committed, so the producer cannot have chosen the samples to fit the
challenge. This is the RFC 3797 pattern ("derive selections from pre-specified future public
randomness") applied to sample auditing. Established beacons: the drand League of Entropy
(``randomness`` = 32 bytes per round) and the NIST Interoperable Randomness Beacon
(``outputValue`` = 64 bytes per pulse).

Offline-first: proofbundle never fetches. The relying party obtains the pulse out of band (or it
is bundled) and passes its raw bytes here. The returned ``AuditRequest`` records the beacon id
and round so a third party can fetch the *same* pulse and re-run ``audit_challenge`` to the
identical indices — the audit is reproducible without trusting the auditor.

Soundness caveats, stated honestly (the beacon mode is grinding-resistant ONLY under these, otherwise it
is no stronger than the documented-grindable self-challenge, so a relying party MUST check them):
  1. Beacon signature: this module does NOT verify the beacon's own signature (drand pulses are BLS-signed;
     NIST pulses are RSA-signed) — that is a separate trust anchor the relying party validates with the
     beacon's public key out of band, like every anchor in docs/TRUST_ANCHORS.md.
  2. Ordering depends on a SELF-DECLARED, UNVERIFIED timestamp. The "the round emitted after time T" argument
     uses the receipt's own ``timestamp`` field, which the producer writes and signs but which nothing here
     proves is the true commit time. A dishonest producer can BACKDATE ``timestamp``, wait for a round R whose
     randomness is already public, grind sample trees against R, and sign a receipt claiming a timestamp before
     R's emission. Ed25519 only proves the false timestamp was signed, not that it is true. So the relying party
     must corroborate the ordering from an INDEPENDENT source (a transparency-log inclusion time for the receipt,
     a witnessed/notarized timestamp, or a pre-registered round id chosen before the run) — not from the receipt's
     own timestamp alone. Without independent corroboration the beacon mode does NOT close producer-side grinding.
  3. Round independence: the round id must be fixed BEFORE the samples are committed (a future round), not chosen
     by the producer after seeing published randomness; this module records the round but cannot enforce that it
     was pre-committed.
"""

from __future__ import annotations

import hashlib
from typing import List

from .errors import BundleFormatError
from .persample import audit_challenge

__all__ = ["AuditRequest", "beacon_nonce", "beacon_audit_challenge"]

# Beacon randomness lengths we accept (raw bytes). drand = 32, NIST = 64. Other lengths are
# allowed too (any >=16 bytes of published randomness), but these are the named, verified ones.
_MIN_PULSE_BYTES = 16
_BEACON_DOMAIN = b"proofbundle/v1.9/beacon-nonce\x00"


class AuditRequest:
    """A reproducible audit challenge derived from a public beacon pulse.

    Everything a third party needs to RE-derive the same indices: the beacon id, the round, and
    the resulting indices. ``as_dict`` is JSON-serializable for publishing alongside the receipt.
    """

    __slots__ = ("beacon", "round", "n", "k", "indices")

    def __init__(self, beacon: str, round_: int, n: int, k: int, indices: List[int]):
        self.beacon = beacon
        self.round = round_
        self.n = n
        self.k = k
        self.indices = indices

    def as_dict(self) -> dict:
        return {"beacon": self.beacon, "round": self.round, "n": self.n, "k": self.k,
                "indices": list(self.indices)}

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"AuditRequest(beacon={self.beacon!r}, round={self.round}, k={self.k}, n={self.n})"


def beacon_nonce(pulse_randomness: bytes, beacon: str, round_: int) -> bytes:
    """Derive the ``audit_challenge`` nonce from a beacon pulse, binding the beacon id + round.

    The nonce is ``SHA-256(domain ‖ beacon ‖ 0x00 ‖ u64(round) ‖ pulse_randomness)`` — so two
    different beacons or rounds never collide to the same challenge, and the nonce is a fixed
    32 bytes regardless of the beacon's own randomness length.
    """
    if not isinstance(pulse_randomness, (bytes, bytearray)) or len(pulse_randomness) < _MIN_PULSE_BYTES:
        raise BundleFormatError(
            f"beacon pulse randomness must be at least {_MIN_PULSE_BYTES} bytes")
    if not beacon or "\x00" in beacon:
        raise BundleFormatError("beacon id must be a non-empty string without NUL")
    if isinstance(round_, bool) or not isinstance(round_, int) or round_ < 0 or round_ >= 2**64:
        raise BundleFormatError("beacon round must be a u64 (0 <= round < 2**64)")
    return hashlib.sha256(_BEACON_DOMAIN + beacon.encode("utf-8") + b"\x00"
                          + round_.to_bytes(8, "big") + bytes(pulse_randomness)).digest()


def beacon_audit_challenge(root, n: int, k: int, *, pulse_randomness: bytes, beacon: str,
                           round_: int) -> AuditRequest:
    """Derive a reproducible per-sample audit challenge from a public beacon pulse.

    ``root``/``n``/``k`` are the receipt's signed samples root, committed count, and the number
    of samples to challenge. ``pulse_randomness`` is the raw randomness of a beacon pulse whose
    round emits AFTER the receipt's signed timestamp (the relying party checks that). Returns an
    :class:`AuditRequest` recording the beacon id + round + indices, so the challenge is
    publicly re-derivable — no live auditor, no trust in who ran it.
    """
    nonce = beacon_nonce(pulse_randomness, beacon, round_)
    indices = audit_challenge(root, n, k, nonce)
    return AuditRequest(beacon=beacon, round_=round_, n=n, k=k, indices=indices)
