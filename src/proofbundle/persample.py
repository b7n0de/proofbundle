"""Per-sample receipts — a Merkle tree over individual eval samples, with salted selective
opening and an auditor spot-check protocol (v1.5).

This closes the THREAT_MODEL's named structural gap: an aggregate receipt cannot detect
per-sample sub-sampling or cherry-picking. Now the signed claim can carry a **samples root** —
an RFC 6962 SHA-256 Merkle tree head over one leaf per sample — so an auditor can challenge k
random indices and demand **openings** (disclosure + inclusion proof) that re-derive to the
committed root. Catching an m-fraction of manipulated samples with k challenges succeeds with
probability 1−(1−m)^k, independent of n (proof-of-retrievability bound, Ateniese/Juels–Kaliski
2007): k=300 → 95% at m=1%, k=459 → 99%.

Construction (deliberately assembled from shipped standards, nothing invented but the record
schema — design verified against TRUCE arXiv:2403.00393, RFC 9901, RFC 6962/9162, RFC 3797):
  - **Leaf** = RFC 6962 leaf hash (0x00 domain separation, via :mod:`proofbundle.merkle`) over
    the US-ASCII bytes of a base64url-encoded **disclosure** — RFC 9901's digest mechanic, so
    the verify path never canonicalizes JSON. A disclosure decodes to ``[salt_b64, record]``;
    the record MUST embed its own ``idx`` (replay guard: an opening cannot be presented at a
    different position) and records are committed in canonical order sorted by (id, epoch).
  - **Salts** are per-leaf and fresh (RFC 9901: one shared salt is burned by the first opening —
    eval verdicts have tiny answer spaces and fall to dictionary attack). They derive from ONE
    holder-kept 32-byte ``tree_secret`` via HMAC-SHA-256 as a PRF (RFC 2104/FIPS 198):
    ``salt_i = HMAC(tree_secret, "proofbundle/v2/leaf-salt" ‖ id ‖ 0x00 ‖ epoch)[:16]``.
    Disclosing one salt reveals nothing about siblings; full escrow = disclosing the secret.
    The secret NEVER appears in the receipt.
  - **Challenge** = ``SHA-256("proofbundle/v2/audit-challenge" ‖ root ‖ u64(n) ‖ u64(k) ‖
    nonce)``, expanded via HMAC-SHA-256 counter mode into u64 draws, mapped to [0, n) by
    **rejection sampling** (no modulo bias), duplicates skipped until k distinct indices.
    Modes: (a) *auditor nonce* (default for real audits) — fresh ≥128-bit nonce supplied AFTER
    the receipt is signed, grinding impossible; (b) *beacon* — a public-randomness pulse
    (drand/NIST) from after the signed timestamp, RFC 3797-style, publicly re-verifiable;
    (c) *self-challenge* (empty nonce) — sanity check ONLY: a producer unhappy with the
    deterministic indices can re-salt and re-root (grinding), escaping with ≈ g·(1−m/n)^k over
    g attempts. Stated here and in THREAT_MODEL, never papered over.

Contamination economics (stated honestly): every opened sample is burned for future evals.
Openings are auditor-directed and never enter the public receipt; k ≪ n keeps leakage bounded;
benchmark owners may include canary/watermarked items so leakage of opened samples into
training data is later detectable (DyePack arXiv:2505.23001).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import List, Optional, Sequence

from . import merkle
from .errors import BundleFormatError

__all__ = ["LEAF_ALG", "derive_leaf_salt", "make_disclosure", "build_sample_tree",
           "sample_opening", "verify_sample_opening", "audit_challenge"]

LEAF_ALG = "sha256-rfc6962-sdjwt-v1"     # named in the claim so verifiers know the leaf mechanic
_SALT_DOMAIN = b"proofbundle/v2/leaf-salt"
_CHALLENGE_DOMAIN = b"proofbundle/v2/audit-challenge"
_SALT_BYTES = 16                          # 128 bit, RFC 9901 recommendation


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    raw = s.encode("ascii")
    return base64.urlsafe_b64decode(raw + b"=" * (-len(raw) % 4))


def derive_leaf_salt(tree_secret: bytes, sample_id, epoch: int = 1) -> bytes:
    """Per-leaf salt = HMAC-SHA-256(tree_secret, domain ‖ id ‖ 0x00 ‖ epoch)[:16].

    HMAC as a PRF: revealing one derived salt reveals nothing about any other. The 0x00
    separator prevents id/epoch ambiguity (id "1" epoch 12 vs id "11" epoch 2)."""
    if not isinstance(tree_secret, bytes) or len(tree_secret) < 16:
        raise BundleFormatError("tree_secret must be at least 16 random bytes (32 recommended)")
    if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 0:
        raise BundleFormatError("epoch must be a non-negative integer")
    msg = _SALT_DOMAIN + str(sample_id).encode("utf-8") + b"\x00" + str(epoch).encode("ascii")
    return hmac.new(tree_secret, msg, hashlib.sha256).digest()[:_SALT_BYTES]


def make_disclosure(record: dict, salt: bytes) -> str:
    """Encode one sample record as a disclosure: base64url(JSON [salt_b64, record]).

    The LEAF commits to the encoded ASCII string (RFC 9901 mechanic) — verification re-hashes
    the transported string and never needs JSON canonicalization. ``record`` must carry ``idx``
    (its committed position) — enforced here so no leaf can ever lack the replay guard."""
    if not isinstance(record, dict):
        raise BundleFormatError("sample record must be a JSON object")
    idx = record.get("idx")
    if isinstance(idx, bool) or not isinstance(idx, int) or idx < 0:
        raise BundleFormatError("sample record must embed its committed index as 'idx' (int >= 0)")
    if len(salt) < _SALT_BYTES:
        raise BundleFormatError("per-leaf salt must be at least 16 bytes")
    disclosure_json = json.dumps([_b64url(salt), record], sort_keys=True,
                                 separators=(",", ":"))
    return _b64url(disclosure_json.encode("utf-8"))


def _leaf_hash_of(disclosure_b64: str) -> bytes:
    """RFC 6962 leaf hash (0x00 domain separation) over the encoded disclosure's ASCII bytes."""
    return merkle.leaf_hash(disclosure_b64.encode("ascii"))


def build_sample_tree(records: Sequence[dict], tree_secret: bytes) -> dict:
    """Commit a full eval run's samples. Returns ``{root, root_b64, n, leaf_alg, disclosures}``.

    ``records`` must already be in canonical order (sort by (id, epoch) before calling — the
    producer has NO ordering freedom; the committed ``idx`` is assigned here, 0-based, and
    embedded into each record). Salts derive per leaf from ``tree_secret``. The caller keeps
    ``disclosures`` (holder-side material for openings) and the secret; the receipt only ever
    carries root + n + leaf_alg.
    """
    if not records:
        raise BundleFormatError("cannot commit an empty sample set")
    disclosures: List[str] = []
    leaves: List[bytes] = []
    prev_key = None
    for i, rec in enumerate(records):
        if not isinstance(rec, dict):
            raise BundleFormatError(f"record {i} is not a JSON object")
        rec = dict(rec)
        if "idx" in rec and rec["idx"] != i:
            raise BundleFormatError(
                f"record {i} carries idx={rec['idx']!r} — indices are assigned by the tree "
                "builder from canonical order, never by the caller")
        rec["idx"] = i
        # Enforce the documented canonical (id, epoch) order (release-review #7/#10): the producer has NO ordering
        # freedom, so reject records that are not already sorted — otherwise the invariant is only a comment. id is
        # compared as a string (stable across int/str ids), epoch as int; a non-integer epoch is rejected.
        try:
            key = (str(rec.get("id", i)), int(rec.get("epoch", 1)))
        except (TypeError, ValueError) as exc:
            raise BundleFormatError(f"record {i} has a non-integer epoch") from exc
        if prev_key is not None and key < prev_key:
            raise BundleFormatError(
                f"record {i} breaks canonical (id, epoch) order — sort records before commitment")
        prev_key = key
        salt = derive_leaf_salt(tree_secret, rec.get("id", i), int(rec.get("epoch", 1)))
        d = make_disclosure(rec, salt)
        disclosures.append(d)
        leaves.append(d.encode("ascii"))
    root = merkle.merkle_tree_hash(leaves)
    return {"root": root, "root_b64": base64.b64encode(root).decode("ascii"),
            "n": len(leaves), "leaf_alg": LEAF_ALG, "disclosures": disclosures}


def sample_opening(disclosures: Sequence[str], index: int) -> dict:
    """Produce the opening for one committed sample: disclosure + RFC 6962 inclusion proof."""
    n = len(disclosures)
    if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < n:
        raise BundleFormatError(f"index must be an integer in [0, {n})")
    leaves = [d.encode("ascii") for d in disclosures]
    proof = merkle.inclusion_proof(leaves, index)
    return {"index": index, "n": n, "disclosure": disclosures[index],
            "proof_b64": [base64.b64encode(p).decode("ascii") for p in proof]}


def verify_sample_opening(opening: dict, root_b64: str, n: int) -> dict:
    """Verify one opening against the receipt's committed samples root — offline, fail-closed.

    Checks: the disclosure's leaf hash is included at ``opening.index`` in the tree of size
    ``n`` under ``root_b64`` (recomputed, never trusted), the disclosure decodes to
    ``[salt, record]``, and the record's embedded ``idx`` equals the proven index (replay
    guard). Returns ``{ok, record, salt_b64, detail}`` — the record is only meaningful when
    ``ok`` is True; plaintext that does not re-derive the committed leaf is never returned.
    """
    result = {"ok": False, "record": None, "salt_b64": None, "detail": ""}
    if not isinstance(opening, dict):
        raise BundleFormatError("opening must be a JSON object")
    index = opening.get("index")
    disclosure = opening.get("disclosure")
    proof_list = opening.get("proof_b64")
    if isinstance(index, bool) or not isinstance(index, int) \
            or not isinstance(disclosure, str) or not isinstance(proof_list, list):
        raise BundleFormatError("opening needs integer 'index', string 'disclosure', list 'proof_b64'")
    if isinstance(n, bool) or not isinstance(n, int) or not 0 <= index < n:
        result["detail"] = "index out of range for the committed tree size"
        return result
    try:
        proof = [base64.b64decode(p, validate=True) for p in proof_list]
        root = base64.b64decode(root_b64, validate=True)
    except (ValueError, TypeError) as exc:
        raise BundleFormatError("opening proof/root is not valid base64") from exc

    if not merkle.verify_inclusion(disclosure.encode("ascii"), index, n, proof, root):
        result["detail"] = "inclusion proof does not bind this disclosure to the samples root"
        return result

    try:
        parsed = json.loads(_b64url_decode(disclosure))
    except (ValueError, TypeError):
        result["detail"] = "disclosure is not valid base64url(JSON)"
        return result
    if not (isinstance(parsed, list) and len(parsed) == 2 and isinstance(parsed[0], str)
            and isinstance(parsed[1], dict)):
        result["detail"] = "disclosure must decode to [salt_b64, record]"
        return result
    salt_b64, record = parsed
    if record.get("idx") != index:
        result["detail"] = (f"replay guard: record idx {record.get('idx')!r} does not match the "
                            f"proven position {index}")
        return result

    result.update(ok=True, record=record, salt_b64=salt_b64,
                  detail=f"sample {index} of {n} opens against the committed root")
    return result


def audit_challenge(root, n: int, k: int, nonce: bytes = b"") -> List[int]:
    """Derive k distinct audit indices in [0, n) from the committed root — deterministic,
    re-verifiable by anyone with the same inputs.

    ``nonce`` modes (see module docstring): auditor-supplied (default for audits — arrives
    after signing, no grinding), a public beacon pulse, or empty (self-challenge sanity mode
    ONLY — grinding by re-salting is possible and documented). Index mapping uses rejection
    sampling over u64 draws — zero modulo bias by construction.
    """
    if isinstance(root, str):
        root = base64.b64decode(root, validate=True)
    if not isinstance(root, bytes) or len(root) != 32:
        raise BundleFormatError("root must be the 32-byte samples root (or its base64)")
    if isinstance(n, bool) or not isinstance(n, int) or n <= 0:
        raise BundleFormatError("n must be a positive integer")
    if isinstance(k, bool) or not isinstance(k, int) or not 0 < k <= n:
        raise BundleFormatError("k must be an integer in [1, n]")
    seed = hashlib.sha256(_CHALLENGE_DOMAIN + root + n.to_bytes(8, "big")
                          + k.to_bytes(8, "big") + nonce).digest()
    chosen: List[int] = []
    seen = set()
    counter = 0
    while len(chosen) < k:
        block = hmac.new(seed, counter.to_bytes(8, "big"), hashlib.sha256).digest()
        counter += 1
        for off in range(0, 32, 8):
            idx = _map_draw(int.from_bytes(block[off:off + 8], "big"), n)
            if idx is None or idx in seen:
                continue
            seen.add(idx)
            chosen.append(idx)
            if len(chosen) == k:
                break
    return chosen


def _map_draw(v: int, n: int) -> Optional[int]:
    """Map one u64 draw to [0, n) by rejection sampling — or None if rejected.

    Accept iff ``v < ⌊2^64/n⌋·n`` (the largest multiple of n below 2^64), else redraw: zero
    modulo bias by construction (Romailler; same 'simple discard' method as FIPS 186-5).
    Isolated as a pure function because the rejection branch fires with probability
    (2^64 mod n)/2^64 (~1e-19 for small n) — it can only be TESTED in isolation, never
    observed through the full challenge path."""
    limit = (2**64 // n) * n
    if v >= limit:
        return None
    return v % n


def catch_probability(m_fraction: float, k: int) -> float:
    """PoR bound: probability that k challenges catch an m-fraction of bad samples,
    1 − (1 − m)^k — independent of n. (k=300 → ~0.95 at m=0.01; k=459 → ~0.99.)"""
    if not 0 <= m_fraction <= 1 or k < 0:
        raise BundleFormatError("m_fraction in [0,1], k >= 0")
    return 1.0 - (1.0 - m_fraction) ** k
