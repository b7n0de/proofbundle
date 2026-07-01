"""SD-JWT issuance per RFC 9901 — the differentiation feature (v0.5).

Issue an eval receipt so a holder can disclose `passed` + `threshold` while WITHHOLDING the exact score
and the identifier openings. The existing verifier (proofbundle.sdjwt) stays; this adds issuance.

Source of truth: the signed canonical bundle payload (evalclaim) is the ONLY truth. This SD-JWT is a
derived view — its always-open claims are copied bit-exact from that payload, and it binds the bundle
anchor via `receipt.root_b64`. Sign the SD-JWT with the SAME Ed25519 key that signed the bundle (matching
the `issuer` field). A holder cannot lift a claim under a different key.

Always-open (plaintext JWT claims, NEVER a disclosure): passed, threshold, comparator, suite, issuer,
receipt.root_b64. Selectively-disclosable (via `_sd` + disclosures): the exact metric value, ci95, and
the identifier-commitment openings (identifier + salt).

RFC 9901 §4.2.4.1 digest byte-chain (the subtle, load-bearing detail): for each disclosable field, a
CSPRNG salt of ≥128 bit (base64url); the disclosure is base64url(UTF-8(JSON array [salt, name, value]));
the digest placed in `_sd` is **base64url(SHA-256(ASCII bytes of the base64url-ENCODED disclosure
string)))** — hashed over the ENCODED string, NOT over the JSON bytes. `_sd_alg` = "sha-256" at the top
level. The JWT is signed with EdDSA. Compact form is tilde-separated: JWT~disclosure1~...~ (trailing ~).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import Optional, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

SD_ALG = "sha-256"
_SALT_BYTES = 16  # 128 bit


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _make_disclosure(name: str, value, salt_b64: str) -> tuple[str, str]:
    """Return (disclosure_b64url, digest_b64url) per RFC 9901 §4.2.4.1.

    The digest hashes the ASCII bytes of the base64url-ENCODED disclosure string (not the JSON bytes)."""
    disclosure_json = json.dumps([salt_b64, name, value])            # array [salt, name, value]
    disclosure_b64 = _b64url(disclosure_json.encode("utf-8"))
    digest = _b64url(hashlib.sha256(disclosure_b64.encode("ascii")).digest())
    return disclosure_b64, digest


def issue_sd_jwt(claim: dict, signer: Ed25519PrivateKey, *, root_b64: str,
                 exact_score: Optional[str] = None, ci95: Optional[Sequence[str]] = None,
                 model_id_opening: Optional[Sequence] = None,
                 dataset_id_opening: Optional[Sequence] = None) -> str:
    """Issue a compact SD-JWT for the eval claim, signed with `signer` (must match claim['issuer']).

    Openings are (identifier, salt_hex) pairs the issuer may later reveal; `exact_score`/`ci95` are the
    withheld numeric detail. All extras are selectively-disclosable; the pass/threshold facts are open.
    """
    always_open = {
        "passed": claim["passed"], "threshold": claim["threshold"],
        "comparator": claim["comparator"], "suite": claim["suite"],
        "issuer": claim["issuer"], "receipt": {"root_b64": root_b64},
    }
    disclosures: list[str] = []
    sd_digests: list[str] = []

    def _add(name: str, value):
        d, dig = _make_disclosure(name, value, _b64url(os.urandom(_SALT_BYTES)))
        disclosures.append(d)
        sd_digests.append(dig)

    if exact_score is not None:
        _add("exact_score", exact_score)
    if ci95 is not None:
        _add("ci95", list(ci95))
    if model_id_opening is not None:
        _add("model_id_opening", list(model_id_opening))
    if dataset_id_opening is not None:
        _add("dataset_id_opening", list(dataset_id_opening))

    payload = dict(always_open)
    if sd_digests:
        payload["_sd"] = sd_digests
        payload["_sd_alg"] = SD_ALG

    header = {"alg": "EdDSA", "typ": "sd-jwt"}
    signing_input = _b64url(json.dumps(header).encode("utf-8")) + "." + _b64url(json.dumps(payload).encode("utf-8"))
    signature = signer.sign(signing_input.encode("ascii"))
    jwt = signing_input + "." + _b64url(signature)

    # compact: JWT ~ disclosure1 ~ ... ~ (trailing tilde, no key-binding JWT in v0.5)
    return "~".join([jwt, *disclosures]) + "~"


def issuer_matches(claim: dict, signer: Ed25519PrivateKey) -> bool:
    """True iff the claim's issuer fingerprint equals the signer's public key (bundle↔SD-JWT same key)."""
    raw = signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return claim.get("issuer") == "ed25519:" + base64.b64encode(raw).decode("ascii")


def _jwt_payload(compact: str) -> dict:
    """Decode the always-open JWT payload of a compact SD-JWT (the part before the first '~')."""
    jwt = compact.split("~", 1)[0]
    payload_b64 = jwt.split(".")[1]
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))


def check_binds_bundle(compact: str, claim: dict, root_b64: str) -> bool:
    """No-Fake binding: the SD-JWT's always-open claims MUST match the signed bundle payload bit-exact and
    bind its merkle root. A derived SD-JWT that diverges from its bundle source of truth is rejected."""
    try:
        p = _jwt_payload(compact)
    except (ValueError, KeyError, IndexError):
        return False
    return (p.get("passed") == claim["passed"] and p.get("threshold") == claim["threshold"]
            and p.get("comparator") == claim["comparator"] and p.get("suite") == claim["suite"]
            and p.get("issuer") == claim["issuer"]
            and (p.get("receipt") or {}).get("root_b64") == root_b64)
