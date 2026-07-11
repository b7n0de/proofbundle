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
# sd_hash / disclosure digests use the SD-JWT's declared _sd_alg — the kbjwt verifier reads _sd_alg from the
# issuer payload, so the presenter MUST hash with the same algorithm (not a hardcoded sha256). Release-review fix.
_HASH_BY_SD_ALG = {"sha-256": hashlib.sha256, "sha-384": hashlib.sha384, "sha-512": hashlib.sha512}
_SALT_BYTES = 16  # 128 bit

# SD-JWT VC syntactic markers (v1.3). draft-ietf-oauth-sd-jwt-vc-17 (2026-07) is at the IESG
# ("Publication Requested"), not yet an RFC — we adopt ONLY its four stable interop markers:
# header `typ: dc+sd-jwt` (media type application/dc+sd-jwt; stable since the vc+sd-jwt rename,
# though NOT yet IANA-registered — registration lands with RFC publication), a `vct` type URI,
# the optional `status` claim (Token Status List), and `cnf` (already present since v1.2). The
# type-metadata resolution machinery is deliberately NOT implemented (network-bound, still churning).
SD_JWT_TYP = "dc+sd-jwt"
DEFAULT_VCT = "https://b7n0de.com/proofbundle/vct/eval-receipt/v1"


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
                 dataset_id_opening: Optional[Sequence] = None,
                 holder_public_key: Optional[bytes] = None,
                 vct: str = DEFAULT_VCT,
                 status: Optional[dict] = None) -> str:
    """Issue a compact SD-JWT for the eval claim, signed with `signer` (must match claim['issuer']).

    Openings are (identifier, salt_hex) pairs the issuer may later reveal; `exact_score`/`ci95` are the
    withheld numeric detail. All extras are selectively-disclosable; the pass/threshold facts are open.

    `holder_public_key` (raw 32-byte Ed25519, v1.2) binds a holder key via the `cnf.jwk` claim
    (RFC 7800), enabling Key Binding JWT presentations verified by :mod:`proofbundle.kbjwt`.

    v1.3 (SD-JWT VC markers): the header `typ` is ``dc+sd-jwt`` and the payload carries a `vct`
    type URI (override per profile). `status` (build via
    :func:`proofbundle.statuslist.status_claim`) points the receipt into a Token Status List;
    verifying a bundled list snapshot lives in :mod:`proofbundle.statuslist`.
    """
    always_open = {
        "passed": claim["passed"], "threshold": claim["threshold"],
        "comparator": claim["comparator"], "suite": claim["suite"],
        "issuer": claim["issuer"], "receipt": {"root_b64": root_b64},
        "vct": vct,
    }
    if status is not None:
        if not isinstance(status, dict) or "status_list" not in status:
            raise ValueError("status must be a dict with a status_list member "
                             "(use proofbundle.statuslist.status_claim)")
        always_open["status"] = status
    if holder_public_key is not None:
        if len(holder_public_key) != 32:
            raise ValueError("holder_public_key must be a raw 32-byte Ed25519 public key")
        always_open["cnf"] = {"jwk": {"kty": "OKP", "crv": "Ed25519",
                                      "x": _b64url(holder_public_key)}}
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

    header = {"alg": "EdDSA", "typ": SD_JWT_TYP}
    signing_input = _b64url(json.dumps(header).encode("utf-8")) + "." + _b64url(json.dumps(payload).encode("utf-8"))
    signature = signer.sign(signing_input.encode("ascii"))
    jwt = signing_input + "." + _b64url(signature)

    # compact: JWT ~ disclosure1 ~ ... ~ (trailing tilde, no key-binding JWT in v0.5)
    return "~".join([jwt, *disclosures]) + "~"


def present_with_key_binding(compact: str, holder_signer: Ed25519PrivateKey, *,
                             aud: str, nonce: str, iat: int) -> str:
    """Append a Key Binding JWT to a compact SD-JWT presentation (RFC 9901 §4.3, v1.2).

    ``compact`` must end with ``~`` (no KB yet); the holder signs over its own header/payload,
    where ``sd_hash`` commits to the exact presented ``JWT~disclosures...~`` ASCII bytes with the
    SD-JWT's ``_sd_alg`` hash — so dropping or swapping a disclosure after signing is detectable.
    ``iat`` is the POSIX issuance time chosen by the holder (explicit, not sampled here, so
    presentations are reproducible in tests).
    """
    if not compact.endswith("~"):
        raise ValueError("compact SD-JWT already carries a key binding JWT (or is malformed)")
    if isinstance(iat, bool) or not isinstance(iat, int):
        raise ValueError("iat must be a POSIX timestamp integer")
    # sd_hash MUST use the SD-JWT's OWN declared _sd_alg (read from the presented compact's issuer payload),
    # matching the kbjwt verifier — not a hardcoded module constant (release-review fix #9/#10).
    sd_alg = _jwt_payload(compact).get("_sd_alg", SD_ALG)
    if sd_alg not in _HASH_BY_SD_ALG:
        raise ValueError(f"unsupported _sd_alg {sd_alg!r} in the presented SD-JWT")
    sd_hash = _b64url(_HASH_BY_SD_ALG[sd_alg](compact.encode("ascii")).digest())
    header = {"alg": "EdDSA", "typ": "kb+jwt"}
    payload = {"iat": iat, "aud": aud, "nonce": nonce, "sd_hash": sd_hash}
    signing_input = _b64url(json.dumps(header).encode("utf-8")) + "." + _b64url(json.dumps(payload).encode("utf-8"))
    signature = holder_signer.sign(signing_input.encode("ascii"))
    return compact + signing_input + "." + _b64url(signature)


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
    # `claim` is an attacker-controllable, only-schema-checked bundle payload — read every field with
    # .get() (WP-C1 6-lens review): a missing field must yield a mismatch (unbound → False), never a
    # raw KeyError traceback out of the verify path. Guarding against `None == None` matching a genuinely
    # absent SD-JWT field would be a false bind, so a claim missing a required field can never bind.
    for field in ("passed", "threshold", "comparator", "suite", "issuer"):
        if field not in claim or p.get(field) != claim.get(field):
            return False
    return (p.get("receipt") or {}).get("root_b64") == root_b64
