"""EXPERIMENTAL: does a reference match a candidate Signed Statement under a named identification scheme?

The reader of draft-gruszka-scitt-statement-identification-03, Section 6, behind ``proofbundle scitt match``. It
takes a reference, the CBOR array ``[alg, scheme, digest]``, and a candidate COSE_Sign1, and reports the axes of
Section 6 for one scheme the caller names. Nothing in it is a verify path of this package: no verifier imports this
module, and the result is a statement about bytes, not a trust decision.

THE SCHEMES. The caller names the scheme and its hash algorithm; the reference never chooses it, and there is no
fallback to another scheme (Appendix A.3.14 of the draft, case C14).

* ``ToBeSigned``, Section 5.1 of the draft: the digest of the deterministic encoding of
  ``["Signature1", body_protected, external_aad, payload]``, where ``body_protected`` is the protected header byte
  string as received and a nil payload is replaced by the supplied detached payload. An embedded payload is used
  even when a detached one is supplied (case C1). An ``external_aad`` that is not supplied, and a detached payload
  that is needed and not supplied, give no ToBeSigned, so the match is INDETERMINATE and never a success.
* ``WholeBytes``, named by case C14 of the draft and defined here, by this reader, as a local experimental scheme:
  the digest of the candidate bytes exactly as given, tag and signature included, nothing removed or re-encoded. It
  needs neither ``external_aad`` nor a detached payload. A candidate that fails the read check below is not a
  statement under this scheme either.

THE AXES. ``ref_usable``: the reference is one CBOR data item, an array of exactly an integer alg that names a hash
function of :data:`HASHES`, a text scheme name and a byte string of that function's output length, and its alg and
name equal those of the named scheme. ``match``: MATCH or NO_MATCH when the comparison can be made, INDETERMINATE when
the reference is not usable or a required input is absent. ``is_scitt``: the candidate passes the read check of
Section 6 and carries tag 18; it is a structural check, not conformance to the SCITT envelope profile. A candidate
that fails the read check gives ``is_scitt`` False and NO_MATCH under a usable reference, INDETERMINATE under one
that is not.

THE READ CHECK, Section 6: the candidate, bare or with tag 18, is an array of exactly four elements, a protected header
byte string that is empty or encodes one map, an unprotected header map, a payload byte string or nil, and a signature
byte string. The candidate and its protected header are each one valid CBOR data item under RFC 8949 Section 5.3.1.
Both are read by :func:`proofbundle._strict_cbor.loads_strict_cbor`, which accepts what the section accepts (heads
that are not the shortest, indefinite lengths, tags not interpreted) and refuses duplicate keys and invalid UTF-8.

NO VERDICT. The strict reader does not represent some valid input: a map key that is an array, a map, a tag or a NaN,
and two distinct data items that are one Python dict key (1 and true, 0 and 0.0, 1 and 1.0). It also stops at its
budget (8 MiB of input, 64 levels of nesting, 200,000 array elements, map pairs and string chunks, where a chunk of an
indefinite string counts one level below its string). For such input this reader gives no verdict at all and raises
:class:`NoVerdict`: it does not report a candidate it could not read as "not a statement".

THE SIGNATURE. Section 6 defines ``sig_valid`` by four rules, and rule 2 asks that A and R have order L. This reader
does not apply rule 2: proofbundle checks Ed25519 through ``cryptography`` under the profile of SPEC.md section 4a,
which accepts small-order and mixed-order components and performs no order check. ``sig_valid`` is therefore
reported as not evaluated, with the reason, and the result carries a separate axis, ``signature``: the outcome of
:func:`proofbundle.signature.verify_ed25519_pinned` over the ToBeSigned of Section 5.1, under the key the caller
supplies, which also refuses a malformed, non-canonical or small-order key (SPEC.md section 4b). On the 14 cases of
the draft ``signature`` equals the draft's ``sig_valid``; a signature whose R is the neutral point, and a key of mixed
order, are inputs where they differ, and the tests keep both.
"""
from __future__ import annotations

import hashlib
from typing import Any

from ._cbor_prescan import encode_head
from ._strict_cbor import CborBeyondLimits, CborInvalid, CborUnrepresentable, Tag, loads_strict_cbor
from .errors import BundleFormatError

__all__ = ["HASHES", "SCHEMES", "NoVerdict", "match_statement", "to_be_signed"]

#: The schemes this reader knows. ``ToBeSigned`` is Section 5.1 of the draft; ``WholeBytes`` is defined above.
SCHEMES = ("ToBeSigned", "WholeBytes")

#: COSE algorithm number -> (hash name, output length in bytes): the hash functions of RFC 9054 with a fixed
#: output length, as registered in the IANA COSE Algorithms registry.
HASHES = {
    -14: ("SHA-1", 20),
    -15: ("SHA-256/64", 8),
    -16: ("SHA-256", 32),
    -17: ("SHA-512/256", 32),
    -18: ("SHAKE128", 32),
    -43: ("SHA-384", 48),
    -44: ("SHA-512", 64),
    -45: ("SHAKE256", 64),
}

#: What this reader says about Section 6 ``sig_valid``, on every result.
SIG_VALID_NOT_EVALUATED = ("rule 2 of Section 6 (A and R of order L) is not applied by this reader; see "
                           "signature, which follows the Ed25519 profile of SPEC.md section 4a")

_INDETERMINATE, _MATCH, _NO_MATCH = "INDETERMINATE", "MATCH", "NO_MATCH"


class NoVerdict(BundleFormatError):
    """The input is beyond what this reader reads, so it gives no verdict. ``reason`` says why."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(f"no verdict: {reason}")


def _digest(alg: int, data: bytes) -> bytes:
    if alg == -14:
        return hashlib.sha1(data, usedforsecurity=False).digest()
    if alg == -15:
        return hashlib.sha256(data).digest()[:8]
    if alg == -16:
        return hashlib.sha256(data).digest()
    if alg == -17:
        return hashlib.new("sha512_256", data).digest()
    if alg == -18:
        return hashlib.shake_128(data).digest(32)
    if alg == -43:
        return hashlib.sha384(data).digest()
    if alg == -44:
        return hashlib.sha512(data).digest()
    if alg == -45:
        return hashlib.shake_256(data).digest(64)
    raise ValueError(f"no hash function for COSE algorithm {alg}")


def _read(data: bytes, what: str) -> Any:
    """One valid CBOR data item, or None when ``data`` is not one; NoVerdict when this reader does not read it."""
    try:
        return loads_strict_cbor(data)
    except (CborUnrepresentable, CborBeyondLimits) as exc:
        raise NoVerdict(f"the {what} is not read by this reader: {exc.reason}") from exc
    except CborInvalid:
        return None


def _bstr(data: bytes) -> bytes:
    return encode_head(2, len(data)) + data


def to_be_signed(body_protected: bytes, external_aad: bytes, payload: bytes) -> bytes:
    """The Sig_structure of RFC 9052 Section 4.4 for COSE_Sign1 in the deterministic encoding of its Section 9."""
    return encode_head(4, 4) + encode_head(3, 10) + b"Signature1" + _bstr(body_protected) + _bstr(external_aad) + \
        _bstr(payload)


def _reference_usable(reference: bytes, scheme: str, alg: int) -> tuple:
    """(usable, digest or None, reason)."""
    ref = _read(reference, "reference")
    if not (type(ref) is list and len(ref) == 3):
        return False, None, "the reference is not one CBOR array of three elements"
    r_alg, r_name, r_digest = ref
    if type(r_alg) is not int or r_alg not in HASHES:
        return False, None, "the reference alg is not an integer naming a hash function this reader knows"
    if type(r_name) is not str or type(r_digest) is not bytes:
        return False, None, "the reference scheme is not a text string or its digest is not a byte string"
    if len(r_digest) != HASHES[r_alg][1]:
        return False, None, f"the reference digest is {len(r_digest)} bytes, {HASHES[r_alg][0]} gives {HASHES[r_alg][1]}"
    if r_alg != alg or r_name != scheme:
        return False, None, f"the reference names {r_name!r} with alg {r_alg}, not the scheme {scheme!r} with alg {alg}"
    return True, r_digest, None


def _read_candidate(candidate: bytes):
    """(tagged with 18, body_protected, payload or None for nil, signature), or None when it is not a statement."""
    top = _read(candidate, "candidate")
    tagged = type(top) is Tag
    if tagged:
        if top.number != 18:
            return None
        top = top.value
    if not (type(top) is list and len(top) == 4):
        return None
    protected, unprotected, payload, signature = top
    if type(protected) is not bytes or type(unprotected) is not dict or type(signature) is not bytes:
        return None
    if not (type(payload) is bytes or payload is None):
        return None
    if protected and type(_read(protected, "protected header")) is not dict:
        return None
    return tagged, protected, payload, signature


def match_statement(reference: bytes, candidate: bytes, *, scheme: str, alg: int,
                    external_aad: bytes | None = None, detached_payload: bytes | None = None,
                    public_key: bytes | None = None) -> dict:
    """The axes of Section 6 for ``reference`` and ``candidate`` under the named scheme.

    ``external_aad`` and ``detached_payload`` are None when not supplied; an empty byte string is a supplied empty
    value. ``public_key`` is the 32-byte raw Ed25519 key for the ``signature`` axis, or None. Raises ValueError for a
    scheme or algorithm this reader does not know, and :class:`NoVerdict` for input it does not read."""
    if scheme not in SCHEMES:
        raise ValueError(f"unknown scheme {scheme!r}; this reader knows {', '.join(SCHEMES)}")
    if type(alg) is not int or alg not in HASHES:
        raise ValueError(f"alg {alg!r} names no hash function this reader knows")
    for name, value in (("reference", reference), ("candidate", candidate), ("external_aad", external_aad),
                        ("detached_payload", detached_payload), ("public_key", public_key)):
        if value is not None and type(value) is not bytes:
            raise ValueError(f"{name} must be bytes")
    reasons: list = []
    usable, ref_digest, why = _reference_usable(reference, scheme, alg)
    if why:
        reasons.append(why)
    result = {"scheme": scheme, "alg": alg, "ref_usable": usable, "match": _INDETERMINATE, "is_scitt": False,
              "sig_valid": None, "sig_valid_reason": SIG_VALID_NOT_EVALUATED, "signature": None,
              "digest": None, "reasons": reasons}
    read = _read_candidate(candidate)
    if read is None:
        reasons.append("the candidate is not a statement under the read check of Section 6")
        result["match"] = _NO_MATCH if usable else _INDETERMINATE
        return result
    tagged, protected, payload, signature = read
    result["is_scitt"] = tagged
    if not tagged:
        reasons.append("the candidate carries no tag 18")
    if payload is None:
        payload = detached_payload
    tbs = None if payload is None or external_aad is None else to_be_signed(protected, external_aad, payload)
    if tbs is None:
        reasons.append("no ToBeSigned: " + ("external_aad is not supplied" if external_aad is None
                                            else "the payload is nil and no detached payload is supplied"))
    covered = tbs if scheme == "ToBeSigned" else candidate
    if covered is not None:
        result["digest"] = _digest(alg, covered).hex()
    if usable and covered is not None:
        result["match"] = _MATCH if bytes.fromhex(result["digest"]) == ref_digest else _NO_MATCH
    if public_key is None:
        reasons.append("signature is not evaluated: no public key is supplied")
    elif len(signature) != 64:
        result["signature"] = False
    elif tbs is not None:
        from .signature import ed25519_trust_anchor_weakness, verify_ed25519_pinned  # noqa: PLC0415
        weakness = ed25519_trust_anchor_weakness(public_key)
        if weakness is not None:
            reasons.append(f"the public key is refused as a {weakness} Ed25519 key (SPEC.md section 4b)")
        result["signature"] = verify_ed25519_pinned(public_key, signature, tbs)
    return result
