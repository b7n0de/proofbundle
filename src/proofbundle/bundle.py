"""Evidence bundle model and offline verification.

An evidence bundle is a single self-contained JSON document. ``verify_bundle``
checks, fully offline and without any running log server:

  1. ed25519-signature   the payload is signed by the stated public key
  2. merkle-inclusion    the payload is anchored under the stated tree root
                         (RFC 6962 / RFC 9162 inclusion proof)
  3. sd-jwt (optional)   any embedded SD-JWT selective-disclosure credential is
                         well formed and, if a key is given, issuer-signed

The verifier treats ``payload`` as opaque bytes: it proves *that these exact
bytes were signed and anchored*, not what they mean. That keeps v0.1 small and
correct. Turning a reproducible eval run into such a payload is the job of the
eval-receipt emitter (see :mod:`proofbundle.evalclaim`, since v0.4).

Malformed input (wrong types, missing or unknown fields) is rejected with a
``BundleFormatError`` — never a raw traceback — so a caller gets the documented
malformed exit code, not a crash.
"""

from __future__ import annotations

import base64
import json
from typing import Union

from . import merkle
from .errors import BundleFormatError, UnsupportedError, VerificationResult
from .signature import verify_ed25519
from .sdjwt import verify_sd_jwt

__all__ = ["SCHEMA", "verify_bundle", "load_bundle"]

SCHEMA = "proofbundle/v0.1"

# Allowed keys per object — SPEC.md §3: a verifier MUST reject unknown fields (schema is
# additionalProperties: false). Enforced here so the code matches its own normative spec.
_TOP_KEYS = {"schema", "payload_b64", "signature", "merkle", "sd_jwt_vc"}
_SIG_KEYS = {"alg", "public_key_b64", "sig_b64"}
_MERKLE_KEYS = {"hash_alg", "leaf_index", "tree_size", "inclusion_proof_b64", "root_b64"}
_SD_KEYS = {"compact", "issuer_public_key_b64"}


def _b64d(value: str, field: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise BundleFormatError(f"field {field} is not valid base64") from exc


def _require(obj: dict, key: str, field: str):
    if key not in obj:
        raise BundleFormatError(f"missing field {field}")
    return obj[key]


def _require_dict(obj, field: str) -> dict:
    """The value must be a JSON object — a string/list/number is malformed, not a crash."""
    if not isinstance(obj, dict):
        raise BundleFormatError(f"field {field} must be a JSON object")
    return obj


def _require_int(obj: dict, key: str, field: str) -> int:
    """The value must be a JSON integer — reject floats (SPEC §2) and non-numeric strings/None."""
    val = _require(obj, key, field)
    if isinstance(val, bool) or not isinstance(val, int):   # bool is an int subclass; a float/str/None is not
        raise BundleFormatError(f"field {field} must be an integer, got {type(val).__name__}")
    return val


def _reject_unknown(obj: dict, allowed: set, field: str) -> None:
    extra = set(obj) - allowed
    if extra:
        raise BundleFormatError(f"unknown field(s) in {field}: {sorted(extra)}")


def load_bundle(path: str) -> dict:
    """Read and JSON-parse a bundle file."""
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def verify_bundle(bundle: Union[dict, str]) -> VerificationResult:
    """Verify an evidence bundle (a dict or a path to a JSON file)."""
    if isinstance(bundle, str):
        bundle = load_bundle(bundle)
    if not isinstance(bundle, dict):
        raise BundleFormatError("bundle must be a JSON object")

    schema = bundle.get("schema")
    if schema != SCHEMA:
        raise UnsupportedError(f"unsupported schema {schema!r}, expected {SCHEMA!r}")
    _reject_unknown(bundle, _TOP_KEYS, "bundle")

    result = VerificationResult()
    payload = _b64d(_require(bundle, "payload_b64", "payload_b64"), "payload_b64")

    # 1. signature over the payload
    sig = _require_dict(_require(bundle, "signature", "signature"), "signature")
    _reject_unknown(sig, _SIG_KEYS, "signature")
    alg = sig.get("alg")
    if alg != "ed25519":
        raise UnsupportedError(f"signature alg {alg!r} not supported in v0.1")
    pub = _b64d(_require(sig, "public_key_b64", "signature.public_key_b64"), "signature.public_key_b64")
    raw_sig = _b64d(_require(sig, "sig_b64", "signature.sig_b64"), "signature.sig_b64")
    sig_ok = verify_ed25519(pub, raw_sig, payload)
    result.add("ed25519-signature", sig_ok, "payload signed by stated key" if sig_ok else "invalid signature")

    # 2. merkle inclusion of the payload
    mk = _require_dict(_require(bundle, "merkle", "merkle"), "merkle")
    _reject_unknown(mk, _MERKLE_KEYS, "merkle")
    hash_alg = mk.get("hash_alg", "sha256-rfc6962")
    if hash_alg != "sha256-rfc6962":
        raise UnsupportedError(f"merkle hash_alg {hash_alg!r} not supported in v0.1")
    leaf_index = _require_int(mk, "leaf_index", "merkle.leaf_index")
    tree_size = _require_int(mk, "tree_size", "merkle.tree_size")
    proof_list = _require(mk, "inclusion_proof_b64", "merkle.inclusion_proof_b64")   # required per SPEC §5
    if not isinstance(proof_list, list):
        raise BundleFormatError("field merkle.inclusion_proof_b64 must be a list")
    proof = [_b64d(p, "merkle.inclusion_proof_b64[]") for p in proof_list]
    root = _b64d(_require(mk, "root_b64", "merkle.root_b64"), "merkle.root_b64")
    incl_ok = merkle.verify_inclusion(payload, leaf_index, tree_size, proof, root)
    result.add(
        "merkle-inclusion",
        incl_ok,
        f"anchored at index {leaf_index} of {tree_size}" if incl_ok else "inclusion proof failed",
    )

    # 3. optional SD-JWT selective disclosure credential
    sd = bundle.get("sd_jwt_vc")
    if sd is not None:
        sd = _require_dict(sd, "sd_jwt_vc")
        _reject_unknown(sd, _SD_KEYS, "sd_jwt_vc")
        compact = _require(sd, "compact", "sd_jwt_vc.compact")
        issuer_pub = None
        if sd.get("issuer_public_key_b64"):
            issuer_pub = _b64d(sd["issuer_public_key_b64"], "sd_jwt_vc.issuer_public_key_b64")
        sd_res = verify_sd_jwt(compact, issuer_pub)
        result.add("sd-jwt-disclosures", sd_res["structure_ok"], sd_res["detail"])
        if sd_res["sig_checked"]:
            result.add(
                "sd-jwt-issuer-signature",
                sd_res["sig_ok"],
                "issuer signature valid" if sd_res["sig_ok"] else "issuer signature invalid",
            )

    return result
