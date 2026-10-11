#!/usr/bin/env python3
"""Illustrative test cases for identifying SCITT Signed Statements.

Builds three synthetic signed statements and a set of transformed candidates,
then runs one reference-matching rule (SHA-256 over ToBeSigned, RFC 9052
Sections 4.4 and 9) and reports each check on separate axes:

  ref_usable : whether the reference is well-formed and compatible with the
               named scheme;
  match      : MATCH or NO_MATCH when the comparison can be completed, and
               INDETERMINATE when the reference is unusable or a required input
               is absent;
  sig_valid  : whether the candidate's signature verifies under the stated key,
               by the four rules of Section 6 of the draft (canonical A and R
               per RFC 8032 Section 5.1.3, both of order L, S below L, and the
               cofactorless equation over ToBeSigned);
  is_scitt   : whether the candidate is a tagged COSE_Sign1 (RFC 9943 Section
               6.1 requires CBOR tag 18).

A candidate is read as one well-formed CBOR data item, valid under RFC 8949
Section 5.3.1, that is a COSE_Sign1, bare or with tag 18, whose protected
header is empty or one such map; the content of a tag is not checked. Anything
else is no statement: NO_MATCH under a usable reference (INDETERMINATE under an
unusable one), is_scitt False, sig_valid None (not evaluated).

A successful match establishes none of: signature validity, issuer trust,
payload truth, or registration. The fixtures are synthetic; nothing is
registered and no Receipt is verified.

Deterministic: keys and timestamps are fixed, so two runs produce byte-identical
output. Stdlib + cbor2 + cryptography only. The matching rule is drawn from the
package in proofbundle docs/scitt/statement_identification/package at commit
eb1b7eeb28a4f77a4fe9fb1eadc21be0fb03746d (label -70001, ToBeSigned). These
examples sign with the fully-specified Ed25519 algorithm -19 of RFC 9864; the
package there uses EdDSA -8, which RFC 9864 lists as deprecated. Identification is
over ToBeSigned and does not depend on the signature algorithm.
"""
import hashlib
import json
import struct
import sys

import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ALG, CONTENT_TYPE, KID, CWT_CLAIMS = 1, 3, 4, 15
ISS, SUB, IAT = 1, 2, 6
# Fully-specified Ed25519 (RFC 9864), which deprecates EdDSA -8; the identification over ToBeSigned does
# not depend on this value, so the examples carry the current algorithm id.
ED25519, SHA256 = -19, -16
REF, ADDED = -70001, -70002
SUBJECT = "pkg:generic/example-widget@1.0.0"


def test_key(label: str) -> Ed25519PrivateKey:
    seed = hashlib.sha256(("draft-gruszka-scitt-statement-identification test key " + label).encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def spki(key) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.DER,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)


def kid(key) -> bytes:
    return hashlib.sha256(spki(key)).digest()


def to_be_signed(protected: bytes, payload: bytes, aad: bytes = b"") -> bytes:
    return cbor2.dumps(["Signature1", protected, aad, payload])


# ---- the sig_valid rule (Section 6 of the draft; RFC 8032 arithmetic) -------------------
_P = 2 ** 255 - 19
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_L = 2 ** 252 + 27742317777372353535851937790883648493
_I = pow(2, (_P - 1) // 4, _P)
_O = (0, 1, 1, 0)


def _decode(b: bytes):
    """RFC 8032 Section 5.1.3; None when decoding fails."""
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    if y >= _P:
        return None
    u, v = (y * y - 1) % _P, (_D * y * y + 1) % _P
    x = (u * pow(v, 3, _P) * pow(u * pow(v, 7, _P), (_P - 5) // 8, _P)) % _P
    if (v * x * x - u) % _P != 0:
        if (v * x * x + u) % _P != 0:
            return None
        x = (x * _I) % _P
    if x == 0 and sign == 1:
        return None
    if x & 1 != sign:
        x = _P - x
    return (x, y, 1, (x * y) % _P)


def _add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = p[3] * 2 * _D * q[3] % _P
    d = p[2] * 2 * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(k: int, p):
    q = _O
    while k:
        if k & 1:
            q = _add(q, p)
        p, k = _add(p, p), k >> 1
    return q


def _neutral(p) -> bool:
    return p[0] % _P == 0 and (p[1] - p[2]) % _P == 0


def _same(p, q) -> bool:
    return (p[0] * q[2] - q[0] * p[2]) % _P == 0 and (p[1] * q[2] - q[1] * p[2]) % _P == 0


_B = _decode(((4 * pow(5, _P - 2, _P)) % _P).to_bytes(32, "little"))


def _raw(public_key) -> bytes:
    return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _order_l(p) -> bool:
    return not _neutral(p) and _neutral(_mul(_L, p))


def sig_valid_rule(a_bytes: bytes, sig, message: bytes, cofactored: bool = False, rule2: bool = True) -> bool:
    """True iff the four rules hold: A and R decode (RFC 8032 Section 5.1.3), A and R have order L (L*A and
    L*R are the neutral element, A and R are not), S < L, and S*B = R + k*A with k = SHA-512(R || A ||
    message) mod L. rule2=False leaves rule 2 out and cofactored=True replaces only the equation by
    8*S*B = 8*R + 8*k*A; both are measured counterfactuals, not the rule."""
    if not isinstance(sig, bytes) or len(sig) != 64:
        return False
    a, r = _decode(a_bytes), _decode(sig[:32])
    if a is None or r is None:
        return False
    if rule2 and not (_order_l(a) and _order_l(r)):
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _L:
        return False
    k = int.from_bytes(hashlib.sha512(sig[:32] + a_bytes + message).digest(), "little") % _L
    left, right = _mul(s, _B), _add(r, _mul(k, a))
    if cofactored:
        left, right = _mul(8, left), _mul(8, right)
    return _same(left, right)


ISSUER = test_key("issuer")
AUDITOR = test_key("auditor")
IAT1, IAT2, IAT3 = 1758362400, 1758551400, 1758791700  # fixed epoch seconds


def jbytes(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def protected_of(key, iss, content_type, refs=None, extra=None):
    hdr = {ALG: ED25519, CONTENT_TYPE: content_type, KID: kid(key),
           CWT_CLAIMS: {ISS: iss, SUB: SUBJECT, IAT: IAT1}}
    if refs:
        hdr[REF] = refs
    if extra:
        hdr.update(extra)
    return cbor2.dumps(hdr)


def sign1(key, protected: bytes, payload: bytes, aad: bytes = b"", tagged=True,
          unprotected=None, signature=None):
    sig = signature if signature is not None else key.sign(to_be_signed(protected, payload, aad))
    body = [protected, unprotected or {}, payload, sig]
    return cbor2.dumps(cbor2.CBORTag(18, body) if tagged else body)


# ---- base statements (faithful to the package) --------------------------------
ARTIFACT_DIGEST = hashlib.sha256(b"example-widget-1.0.0.tar.gz, example bytes\n").hexdigest()
P01 = protected_of(ISSUER, "https://issuer.example", "application/json")
PAY01 = jbytes({"artifact": "example-widget-1.0.0.tar.gz", "sha256": ARTIFACT_DIGEST, "license": "MIT"})
STMT01 = sign1(ISSUER, P01, PAY01)
TBS01 = to_be_signed(P01, PAY01)
REF_TO_01 = [SHA256, "ToBeSigned", hashlib.sha256(TBS01).digest()]

P02 = protected_of(AUDITOR, "https://auditor.example", "text/plain", refs=[REF_TO_01])
PAY02 = (b"The artifact digest in the referenced statement was recomputed and matches. "
         b"This audit covers the referenced bytes only.\n")
STMT02 = sign1(AUDITOR, P02, PAY02)

P03 = protected_of(ISSUER, "https://issuer.example", "application/json", refs=[REF_TO_01])
PAY03 = jbytes({"artifact": "example-widget-1.0.0.tar.gz", "sha256": ARTIFACT_DIGEST,
                "license": "Apache-2.0", "note": "The license in the referenced statement was wrong."})
STMT03 = sign1(ISSUER, P03, PAY03)


# ---- the matcher (the thing under test) ---------------------------------------
def _item(b: bytes, i: int):
    """One well-formed and valid CBOR data item at offset i -> (the item as a comparable value, the offset after
    it); ValueError otherwise. Well-formed is RFC 8949 Section 3 and Appendix F; valid is the basic validity of
    Section 5.3.1: every text string is UTF-8, and no map holds two keys equal under the key equivalence of
    Section 5.6.1 (the integer 1 and true are two keys; 0x01 and 0x18 0x01 are one, and so are 0.0 and -0.0,
    and two NaNs of one significand; two NaNs of different significands are two). Whether a tag's content is
    valid for that tag is not checked (Section 5.3.2 is not applied), so the result does not depend on which
    tags a decoder knows; the data items inside a tag are checked like any other data item."""
    if i >= len(b):
        raise ValueError("the item ends early")
    major, ai = b[i] >> 5, b[i] & 31
    i += 1
    if ai == 31 and major in (2, 3, 4, 5):
        return _indefinite(b, i, major)
    if ai < 24:
        n = ai
    elif ai < 28:
        size = 1 << (ai - 24)
        if i + size > len(b):
            raise ValueError("the head ends early")
        n, i = int.from_bytes(b[i:i + size], "big"), i + size
    else:
        raise ValueError("additional information %d is not well-formed for major type %d" % (ai, major))
    if major in (0, 1):
        return ("int", n if major == 0 else -1 - n), i
    if major in (2, 3):
        if i + n > len(b):
            raise ValueError("the string ends early")
        raw = b[i:i + n]
        if major == 3:
            raw.decode("utf-8")  # UnicodeDecodeError is a ValueError
        return ("bytes" if major == 2 else "text", raw), i + n
    if major == 4:
        out = []
        for _ in range(n):
            v, i = _item(b, i)
            out.append(v)
        return ("array", tuple(out)), i
    if major == 5:
        out = []
        for _ in range(2 * n):
            v, i = _item(b, i)
            out.append(v)
        return _map(out), i
    if major == 6:
        v, i = _item(b, i)
        return ("tag", n, v), i
    if ai == 24 and n < 32:
        raise ValueError("a two-byte simple value below 32 is not well-formed")
    if ai in (25, 26, 27):
        raw = b[i - (1 << (ai - 24)):i]
        f = struct.unpack({25: ">e", 26: ">f", 27: ">d"}[ai], raw)[0]
        if f == f:
            return ("float", f), i
        width = {25: 10, 26: 23, 27: 52}[ai]  # the significand, zero-extended at the right to 64 bits
        return ("float", "NaN", (int.from_bytes(raw, "big") & ((1 << width) - 1)) << (64 - width)), i
    return ("simple", n), i


def _indefinite(b: bytes, i: int, major: int):
    out = []
    while True:
        if i >= len(b):
            raise ValueError("the item ends early")
        if b[i] == 0xFF:
            i += 1
            break
        if major in (2, 3) and (b[i] >> 5 != major or b[i] & 31 == 31):
            raise ValueError("a chunk of an indefinite-length string is not a definite string of its type")
        v, i = _item(b, i)
        out.append(v)
    if major in (2, 3):
        return ("bytes" if major == 2 else "text", b"".join(v[1] for v in out)), i
    if major == 4:
        return ("array", tuple(out)), i
    if len(out) % 2:
        raise ValueError("an indefinite-length map ends after a key")
    return _map(out), i


def _map(flat):
    keys = flat[0::2]
    if len(set(keys)) != len(keys):
        raise ValueError("a map holds two equal keys")
    return ("map", frozenset(zip(keys, flat[1::2])))


def _one_item(b: bytes):
    """The comparable form of B if B is exactly one well-formed and valid data item; ValueError otherwise."""
    item, end = _item(b, 0)
    if end != len(b):
        raise ValueError("data follows the data item")
    return item


def open_sign1(raw: bytes):
    """The candidate as a COSE_Sign1 (RFC 9052 Section 4.2), bare or with tag 18, read by _item alone (no
    decoder interprets a tag); ValueError if it is not one well-formed and valid CBOR data item, or not such a
    COSE_Sign1."""
    top = _one_item(raw)
    tagged = top[0] == "tag"
    if tagged and top[1] != 18:
        raise ValueError("a tag other than 18")
    body = top[2] if tagged else top
    if body[0] != "array" or len(body[1]) != 4:
        raise ValueError("not a 4-element COSE_Sign1")
    protected, unprotected, payload, signature = body[1]
    if not (protected[0] == "bytes" and unprotected[0] == "map" and signature[0] == "bytes"
            and (payload[0] == "bytes" or payload == ("simple", 22))):
        raise ValueError("the members of the COSE_Sign1 do not have their types")
    header = ("map", frozenset())
    if protected[1]:
        header = _one_item(protected[1])
        if header[0] != "map":
            raise ValueError("the protected header is not a map")
    return (tagged, tagged, protected[1], unprotected, payload[1] if payload[0] == "bytes" else None, signature[1],
            header)


def matches(ref, candidate_bytes, *, detached=None, aad=b"", scheme_alg=SHA256, verify_key=None):
    """Return a dict of the four axes for one candidate against `ref`.

    ref_usable is about the reference alone: well-formed [alg, covers, digest] and compatible with the named
    scheme (its algorithm is the scheme's). is_scitt and sig_valid are axes of the candidate and are
    evaluated whether or not the reference is usable; None only where a required input is absent. An
    unusable reference makes match INDETERMINATE, never NO_MATCH or MATCH, and there is no fallback to the
    reference's own algorithm."""
    out = {"ref_usable": None, "is_scitt": None, "match": None, "sig_valid": None, "note": ""}
    out["ref_usable"] = (isinstance(ref, list) and len(ref) == 3 and ref[0] == scheme_alg
                         and ref[1] in ("ToBeSigned", "COSE_Sign1") and isinstance(ref[2], bytes))
    try:
        tagged, is18, protected, _unprot, payload, signature, _hdr = open_sign1(candidate_bytes)
    except Exception as e:  # noqa: BLE001
        out["match"] = "NO_MATCH" if out["ref_usable"] else "INDETERMINATE"
        out["is_scitt"] = False
        out["note"] = f"candidate not a COSE_Sign1: {type(e).__name__}"
        return out
    out["is_scitt"] = bool(is18)
    # sig_valid in the order of Section 6, after the read checks: a signature that is not 64 bytes gives False;
    # otherwise an absent, unsupplied payload leaves no ToBeSigned and sig_valid None; otherwise the four rules
    body_payload = payload if payload is not None else detached
    if verify_key is not None:
        if not isinstance(signature, bytes) or len(signature) != 64:
            out["sig_valid"] = False
        elif body_payload is not None:
            out["sig_valid"] = sig_valid_rule(_raw(verify_key), signature,
                                              to_be_signed(protected, body_payload, aad))
    if body_payload is None:  # detached payload, not supplied
        out["match"] = "INDETERMINATE"
        out["note"] = "detached payload not supplied; a missing input is never a match"
        return out
    if not out["ref_usable"]:
        out["match"] = "INDETERMINATE"
        return out
    if ref[1] == "ToBeSigned":
        candidate_digest = hashlib.sha256(to_be_signed(protected, body_payload, aad)).digest()
    else:
        candidate_digest = hashlib.sha256(candidate_bytes).digest()
    out["match"] = "MATCH" if candidate_digest == ref[2] else "NO_MATCH"
    return out


# ---- the cases ----------------------------------------------------------------
CASES = []


def case(cid, requirement, description, candidate, expected, **kw):
    res = matches(REF_TO_01, candidate, verify_key=ISSUER.public_key(), **kw)
    rec = {
        "id": cid, "requirement": requirement, "description": description,
        "candidate_sha256_cose_sign1": hashlib.sha256(candidate).hexdigest(),
        "candidate_bytes": len(candidate), "candidate_hex": candidate.hex(),
        "expected": expected, "result": {k: res[k] for k in ("ref_usable", "is_scitt", "match", "sig_valid")},
        "note": res["note"], "origin": "synthetic",
    }
    # A non-empty external_aad is an explicit input of the scheme (Section 5.1). When a case supplies one,
    # record its bytes and, as a measured counterfactual, what the same candidate bytes would report under
    # the fixed empty-external_aad rule, so a reader can check both.
    aad = kw.get("aad", b"")
    if aad:
        rec["aad_hex"] = aad.hex()
        alt_kw = {k: v for k, v in kw.items() if k != "aad"}  # aad defaults to the empty byte string
        alt = matches(REF_TO_01, candidate, verify_key=ISSUER.public_key(), **alt_kw)
        rec["empty_aad_result"] = {k: alt[k] for k in ("match", "sig_valid")}
    CASES.append(rec)


def build_cases():
    # C1 positive control: the reference's own target, unchanged.
    case("C1", "A1", "Unchanged reference and candidate (the reference target 01).",
         STMT01, {"ref_usable": True, "match": "MATCH", "is_scitt": True, "sig_valid": True})

    # C2 same iss/sub, different statement: grouping is not single identity.
    case("C2", "A1", "Same issuer and subject, different statement (03): subject grouping does not select 01.",
         STMT03, {"ref_usable": True, "match": "NO_MATCH", "is_scitt": True})

    # C3 changed target payload: differs under a payload-binding rule.
    pay = jbytes({"artifact": "example-widget-1.0.0.tar.gz", "sha256": ARTIFACT_DIGEST, "license": "BSD-3-Clause"})
    c3 = sign1(ISSUER, P01, pay)
    case("C3", "A1", "Changed target payload (re-signed): ToBeSigned differs.",
         c3, {"ref_usable": True, "match": "NO_MATCH", "is_scitt": True, "sig_valid": True})

    # C4 changed protected header: differs (signature context is part of ToBeSigned).
    p4 = protected_of(ISSUER, "https://issuer.example", "application/cbor")
    c4 = sign1(ISSUER, p4, PAY01)
    case("C4", "A1", "Changed protected header (content type), re-signed: ToBeSigned differs.",
         c4, {"ref_usable": True, "match": "NO_MATCH", "is_scitt": True, "sig_valid": True})

    # C5 changed unprotected envelope: ToBeSigned preserved, whole-object digest changes. KEY case.
    c5 = sign1(ISSUER, P01, PAY01, unprotected={ADDED: "added after signing"})
    case("C5", "A4", "Added one unprotected parameter after signing (tag 18 kept): ToBeSigned and signature "
                     "unchanged, whole-object digest changes.",
         c5, {"ref_usable": True, "match": "MATCH", "is_scitt": True, "sig_valid": True})

    # C6 different signature value, identical signing input: match names signed inputs, not the signature.
    c6 = sign1(ISSUER, P01, PAY01, signature=AUDITOR.sign(TBS01))
    case("C6", "A1", "Same ToBeSigned, signature replaced with one from a different key: matches the "
                     "ToBeSigned reference, but does not verify under the issuer key.",
         c6, {"ref_usable": True, "match": "MATCH", "is_scitt": True, "sig_valid": False})

    # C7 non-empty external_aad: external context is part of identity; empty-aad reference does not match.
    c7 = sign1(ISSUER, P01, PAY01, aad=b"ctx:deployment-42")
    case("C7", "A1", "Target signed over a non-empty external_aad. The scheme applies the supplied AAD bytes "
                     "(given in Appendix A) to both reference matching and signature verification, so the "
                     "empty-external_aad reference does not match while the signature verifies. The same "
                     "candidate bytes under the fixed empty-external_aad rule are reported separately in "
                     "Appendix A. A missing external context is not assumed empty.",
         c7, {"ref_usable": True, "match": "NO_MATCH", "is_scitt": True, "sig_valid": True}, aad=b"ctx:deployment-42")

    # C8 detached payload missing: a required input is absent, never a match.
    c8 = sign1(ISSUER, P01, None)  # payload field is CBOR null (detached)
    case("C8", "A1", "Detached payload (payload field is nil) and the detached bytes are not supplied: the "
                     "match is INDETERMINATE, never a success.",
         c8, {"ref_usable": True, "match": "INDETERMINATE", "is_scitt": True})

    # C9 tag 18 removed: generic COSE case, not an RFC 9943 Signed Statement.
    c9 = sign1(ISSUER, P01, PAY01, tagged=False)
    case("C9", "A1/RFC9943-6.1", "Tag 18 removed, nothing else changed: the ToBeSigned digest still matches, "
                                 "but the object is not a tagged COSE_Sign1, so it is not a valid SCITT Signed "
                                 "Statement (RFC 9943 Section 6.1 requires tag 18).",
         c9, {"ref_usable": True, "match": "MATCH", "is_scitt": False, "sig_valid": True})

    # C10 contradictory algorithm/scheme (reading B): the reference is not usable under the scheme, so match is
    # INDETERMINATE with no fallback; is_scitt and sig_valid are the candidate's own axes and are evaluated.
    res = matches(REF_TO_01, STMT01, scheme_alg=-44, verify_key=ISSUER.public_key())
    CASES.append({
        "id": "C10", "requirement": "A1", "candidate_sha256_cose_sign1": hashlib.sha256(STMT01).hexdigest(),
        "candidate_bytes": len(STMT01), "candidate_hex": STMT01.hex(),
        "description": "The scheme names SHA-512 (-44), while the reference carries SHA-256 (-16), so ref_usable "
                       "is False and match is INDETERMINATE; no fallback is performed.",
        "expected": {"ref_usable": False, "match": "INDETERMINATE", "is_scitt": True, "sig_valid": True},
        "result": {k: res[k] for k in ("ref_usable", "is_scitt", "match", "sig_valid")},
        "origin": "synthetic"})

    # C11 the acceptance equation is fixed: statement 01 with its 64 signature bytes replaced by a signature
    # whose R is a canonical point of mixed order and whose S is below L. The cofactored equation holds, the
    # cofactorless equation of the rule does not; the ToBeSigned reference still matches.
    sig11 = bytes.fromhex("9599999999999999999999999999999999999999999999999999999999999999"
                          "2d5ac5acb4933c1790098a56557795abf48a9f65f4636552659e0a89d2a3110d")
    c11 = sign1(ISSUER, P01, PAY01, signature=sig11)
    assert c11 == STMT01[:-64] + sig11 and len(c11) == 330
    assert hashlib.sha256(c11).hexdigest() == "d1e77e708d759c9b393e93708968887df1ef0e56872166877f68d4ff9e43afe1"
    r11 = _decode(sig11[:32])
    assert r11 is not None and not _neutral(_mul(8, r11)) and not _neutral(_mul(_L, r11))  # mixed order
    assert int.from_bytes(sig11[32:], "little") < _L
    case("C11", "A1", "Statement 01 with its 64 signature bytes replaced: R is a canonical encoding of a point "
                      "of mixed order, and S is below L. Rule 2 refuses R, so sig_valid is False while the "
                      "ToBeSigned reference matches. With rule 2 left out, the cofactored equation holds and "
                      "the cofactorless equation does not.",
         c11, {"ref_usable": True, "match": "MATCH", "is_scitt": True, "sig_valid": False})
    pk = _raw(ISSUER.public_key())
    CASES[-1]["without_rule_2"] = {
        "cofactorless": sig_valid_rule(pk, sig11, TBS01, rule2=False),
        "cofactored": sig_valid_rule(pk, sig11, TBS01, cofactored=True, rule2=False)}


def expected_ok(c):
    return all(c["result"].get(k) == v for k, v in c["expected"].items())


def main():
    build_cases()
    doc = {
        "package": "draft-gruszka-scitt-statement-identification-00 illustrative test cases",
        "scheme": "SHA-256 over ToBeSigned (RFC 9052 Sections 4.4 and 9), external_aad empty unless stated",
        "reference_label": REF,
        "algorithm": "fully-specified Ed25519 (COSE algorithm -19, RFC 9864); the source package uses EdDSA "
                     "-8, which RFC 9864 deprecates; identification is over ToBeSigned and is independent of "
                     "the signature algorithm",
        "statements": {
            "01": {"iss": "https://issuer.example", "sub": SUBJECT,
                   "sha256_to_be_signed": hashlib.sha256(TBS01).hexdigest(),
                   "sha256_cose_sign1": hashlib.sha256(STMT01).hexdigest(), "bytes": len(STMT01),
                   "hex": STMT01.hex()},
            "02": {"iss": "https://auditor.example", "sub": SUBJECT, "refers_to": "01",
                   "sha256_cose_sign1": hashlib.sha256(STMT02).hexdigest(), "bytes": len(STMT02),
                   "hex": STMT02.hex()},
            "03": {"iss": "https://issuer.example", "sub": SUBJECT, "refers_to": "01",
                   "sha256_cose_sign1": hashlib.sha256(STMT03).hexdigest(), "bytes": len(STMT03),
                   "hex": STMT03.hex()},
        },
        "reference_to_01": {"digest_algorithm": "SHA-256 (-16)", "covers": "ToBeSigned",
                            "digest": REF_TO_01[2].hex()},
        "test_keys": {
            "issuer": {"ed25519_seed_hex": ISSUER.private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                serialization.NoEncryption()).hex(), "kid_hex": kid(ISSUER).hex()},
            "auditor": {"ed25519_seed_hex": AUDITOR.private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                serialization.NoEncryption()).hex(), "kid_hex": kid(AUDITOR).hex()},
        },
        "test_key_notice": "PURE TEST KEYS derived by SHA-256 from fixed labels. They MUST NOT be used "
                           "for any real statement.",
        "cases": CASES,
    }
    out = sys.argv[1] if len(sys.argv) > 1 else "cases.json"
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    bad = [c["id"] for c in CASES if not expected_ok(c)]
    print("wrote %s  (%d cases)" % (out, len(CASES)), file=sys.stderr)
    hdr = f"{'id':<4} {'req':<14} {'ref_usable':<10} {'match':<13} {'is_scitt':<9} {'sig_valid':<9} {'expected?':<9}"
    print(hdr, file=sys.stderr)
    for c in CASES:
        r = c["result"]
        print(f"{c['id']:<4} {c['requirement']:<14} {str(r['ref_usable']):<10} {str(r['match']):<13} {str(r['is_scitt']):<9} "
              f"{str(r['sig_valid']):<9} {'OK' if expected_ok(c) else 'MISMATCH'}", file=sys.stderr)
    if bad:
        print("UNEXPECTED:", bad, file=sys.stderr)
        sys.exit(1)
    print("all cases match expectation", file=sys.stderr)


if __name__ == "__main__":
    main()
