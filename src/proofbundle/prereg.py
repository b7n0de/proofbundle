"""Pre-registration helper (v1.8) — commit to an eval protocol BEFORE the run.

The single mitigation for best-of-many / cherry-picking that a receipt can carry: hash the
protocol document (the plan — suite, seeds, decision rule, sampling policy) *before* running the
eval, put that hash in the claim's ``prereg_sha256``, and sign the receipt. A verifier who is
later handed the protocol file re-hashes it and checks it matches — so the plan could not have
been written to fit the result. The signed receipt's own timestamp binds "this hash existed at
receipt time" without any network dependency.

Construction (verified against standards, 2026-07): commit = **sha256 over the RAW file bytes**.
Document commitments hash raw bytes (git blob addressing, RFC 6962 leaf hashing, in-toto
``gitBlob``/``sha256`` DigestSet all hash the artifact's own bytes) — NOT a re-normalized form.
Canonicalization would only add a lossy transform the verifier must reproduce byte-for-byte; a
trailing-newline or CRLF change breaking the match is tamper-evidence, not a bug. The claim field
is a bare 64-hex ``prereg_sha256`` (matching the eval-claim schema).

Out of scope, stated honestly: this proves the protocol was fixed relative to the receipt's
signing time; it does NOT prove the run actually followed the protocol, nor timestamp the
commitment against a third party's clock. An optional RFC 3161 TSA countersignature over the
hash (e.g. FreeTSA) is the upgrade when the verifier does not trust the issuer's clock — that is
a deployment choice, not built in here.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

__all__ = ["prereg_hash", "verify_prereg"]


def prereg_hash(protocol_path) -> str:
    """Return the lowercase-hex sha256 over the RAW bytes of the protocol file — the value to
    place in a claim's ``prereg_sha256`` BEFORE running the eval."""
    data = Path(protocol_path).read_bytes()
    return hashlib.sha256(data).hexdigest()


def verify_prereg(protocol_path, claim: dict) -> dict:
    """Check that ``claim['prereg_sha256']`` matches the sha256 of the protocol file.

    Returns ``{ok, present, expected, actual, detail}``. ``present`` is False when the claim
    carries no ``prereg_sha256`` (not pre-registered) — the caller decides whether that is
    acceptable; ``ok`` is only True on a present-and-matching hash (fail-closed)."""
    expected = claim.get("prereg_sha256") if isinstance(claim, dict) else None
    result = {"ok": False, "present": expected is not None, "expected": expected,
              "actual": None, "detail": ""}
    if expected is None:
        result["detail"] = "claim carries no prereg_sha256 (not pre-registered)"
        return result
    actual = prereg_hash(protocol_path)
    result["actual"] = actual
    if actual == expected:
        result["ok"] = True
        result["detail"] = "protocol file matches the pre-registered hash"
    else:
        result["detail"] = "protocol file does NOT match the pre-registered hash (plan changed?)"
    return result
