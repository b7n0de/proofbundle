#!/usr/bin/env python3
"""Recompute, offline, what a real CCF receipt commits to, and say which bytes enter the data-hash.

Input: the files fetched by fetch_external.py into ./fetched (pinned by size and sha256).
Output: recompute_result.json next to this file, and a short summary on stdout.

FOUR VALUES, KEPT APART (ADR 0009):

  1. hash envelope payload  the digest of an artifact, carried as the payload of an RFC 9995
                            COSE Hash Envelope (label 258 hash alg, 259 preimage content type,
                            260 location; label 3 forbidden)
  2. local ToBeSigned ID    a local rule, versioned; measured here as SHA-256 over the RFC 9052
                            Sig_structure (ToBeSigned) of the statement, only to show that it
                            is a different value from 3
  3. CCF data-hash          the third leaf component; SHA-256 over the registered signed
                            statement bytes, per the service's rule. Which bytes those are is
                            the measured question below
  4. CCF Merkle root        computed from the inclusion proof; the detached payload over which
                            the receipt signature is checked

THE MEASURED QUESTION. For every statement that carries a receipt, several candidate byte
strings are hashed and held against the data-hash in the receipt's leaf: the file as served,
the statement with the unprotected header emptied (tagged and untagged), with the payload
detached, re-encoded from the decoded values, the ToBeSigned bytes, the payload alone. The
rule that matches is recorded, and so is every rule that does not.

WHAT THIS IS NOT. Not a basis for src/: the CBOR reader below is a measuring aid, deliberately
narrow (definite lengths only, no floats, no duplicate keys, no trailing bytes, depth 16),
and it refuses rather than guesses. The trust material is the key set or trust store published
next to the statements at the pinned commits; its authenticity against the live services is
NOT MEASURED here (see README.md).

Standard library plus `cryptography`. No network.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import platform
import sys
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
FETCHED = HERE / "fetched"
RESULT = HERE / "recompute_result.json"

MAX_DEPTH = 16
MAX_INPUT = 1 << 20

# COSE and SCITT labels (RFC 9052, RFC 9942, RFC 9943, RFC 9995)
ALG, CRIT, CTY, KID, CWT, X5CHAIN = 1, 2, 3, 4, 15, 33
PAYLOAD_HASH_ALG, PREIMAGE_CTY, PAYLOAD_LOCATION = 258, 259, 260
RECEIPTS, VDS, VDP, INCLUSION = 394, 395, 396, -1
CCF_LEDGER_SHA256 = 2          # requested assignment in draft -05 (TBD_1), not yet assigned
SHA256_COSE = -16

#: Pinned by the upstream project for transparent-statement.cose (corpus/README.md at the
#: pinned commit), computed there with pyscitt and cbor2. Held against ours, not assumed.
UPSTREAM_PINS = {
    "transparent-statement.cose": {
        "signed_statement_length": 4809,
        "claim_digest": "6f7607e4d68fd01298c47897357a093944de8c033c99bbb3284b8243aa0e6d11",
        "merkle_root": "c8dee06dcaa9268cd2910ca78d24a18490789a9d24acba96534dfe8f3b788c14",
    },
}


# ------------------------------------------------------------------------------------------
# A narrow CBOR reader that keeps byte spans
# ------------------------------------------------------------------------------------------
class Refused(ValueError):
    """The reader will not interpret these bytes. Never a verdict about the evidence."""


@dataclass(frozen=True)
class Tag:
    number: int
    value: object


def _head(b: bytes, i: int):
    if i >= len(b):
        raise Refused(f"truncated at offset {i}")
    ib = b[i]
    mt, ai = ib >> 5, ib & 0x1F
    i += 1
    if ai < 24:
        return mt, ai, i, True
    if ai in (24, 25, 26, 27):
        n = 1 << (ai - 24)
        if i + n > len(b):
            raise Refused(f"truncated head at offset {i - 1}")
        arg = int.from_bytes(b[i:i + n], "big")
        shortest = arg >= (24 if ai == 24 else 1 << (8 * (n // 2)))
        if mt == 7:
            raise Refused(f"float or extended simple value at offset {i - 1}")
        return mt, arg, i + n, shortest
    if ai == 31:
        raise Refused(f"indefinite length at offset {i - 1}")
    raise Refused(f"reserved additional information {ai} at offset {i - 1}")


def decode(b: bytes, i: int = 0, depth: int = 0):
    """(value, end, shortest) for one data item at i. `shortest` is True if every head in the
    item used the shortest form of its argument (RFC 8949 section 4.2.1, preferred)."""
    if depth > MAX_DEPTH:
        raise Refused(f"nesting deeper than {MAX_DEPTH} at offset {i}")
    mt, arg, i, shortest = _head(b, i)
    if mt == 0:
        return arg, i, shortest
    if mt == 1:
        return -1 - arg, i, shortest
    if mt in (2, 3):
        if i + arg > len(b):
            raise Refused(f"string runs past the end at offset {i}")
        raw = bytes(b[i:i + arg])
        if mt == 3:
            try:
                raw = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise Refused(f"invalid UTF-8 in text string at offset {i}") from exc
        return raw, i + arg, shortest
    if mt == 4:
        out = []
        for _ in range(arg):
            v, i, s = decode(b, i, depth + 1)
            out.append(v)
            shortest &= s
        return out, i, shortest
    if mt == 5:
        out, seen = {}, set()
        for _ in range(arg):
            k, i, s1 = decode(b, i, depth + 1)
            if not isinstance(k, (int, str, bytes)) or isinstance(k, bool):
                raise Refused(f"map key of type {type(k).__name__} before offset {i}")
            if (type(k), k) in seen:
                raise Refused(f"duplicate map key {k!r} before offset {i}")
            seen.add((type(k), k))
            v, i, s2 = decode(b, i, depth + 1)
            out[k] = v
            shortest &= s1 and s2
        return out, i, shortest
    if mt == 6:
        v, i, s = decode(b, i, depth + 1)
        return Tag(arg, v), i, shortest and s
    # mt == 7, simple values below 24 only
    if arg == 20:
        return False, i, shortest
    if arg == 21:
        return True, i, shortest
    if arg == 22:
        return None, i, shortest
    raise Refused(f"simple value {arg} at offset {i - 1}")


def loads(b: bytes):
    if len(b) > MAX_INPUT:
        raise Refused(f"input larger than {MAX_INPUT} bytes")
    v, end, shortest = decode(b, 0)
    if end != len(b):
        raise Refused(f"{len(b) - end} trailing byte(s) after the data item")
    return v, shortest


def _h(mt: int, n: int) -> bytes:
    if n < 24:
        return bytes([(mt << 5) | n])
    for ai, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * width):
            return bytes([(mt << 5) | ai]) + n.to_bytes(width, "big")
    raise ValueError("argument too large")


def encode(o) -> bytes:
    """Preferred (shortest-head), definite-length encoding of the few types used here."""
    if o is None:
        return b"\xf6"
    if isinstance(o, bool):
        return b"\xf5" if o else b"\xf4"
    if isinstance(o, int):
        return _h(0, o) if o >= 0 else _h(1, -1 - o)
    if isinstance(o, bytes):
        return _h(2, len(o)) + o
    if isinstance(o, str):
        r = o.encode("utf-8")
        return _h(3, len(r)) + r
    if isinstance(o, list):
        return _h(4, len(o)) + b"".join(encode(x) for x in o)
    if isinstance(o, dict):
        return _h(5, len(o)) + b"".join(encode(k) + encode(v) for k, v in o.items())
    if isinstance(o, Tag):
        return _h(6, o.number) + encode(o.value)
    raise TypeError(type(o).__name__)


@dataclass
class Sign1:
    raw: bytes
    tagged: bool
    tag_span: tuple
    array_head_span: tuple
    spans: list            # (start, end) of the four elements in raw
    protected_raw: bytes   # content of the protected bstr, exactly as served
    protected: dict
    unprotected: dict
    payload: object        # bytes, or None when detached
    signature: bytes
    shortest: bool


def parse_sign1(raw: bytes) -> Sign1:
    """COSE_Sign1 (RFC 9052 section 4.2): optional tag 18, then exactly four elements."""
    _, shortest = loads(raw)                       # whole-item checks: no trailing bytes, limits
    i = 0
    mt, arg, j, _ = _head(raw, i)
    tagged = mt == 6
    if tagged:
        if arg != 18:
            raise Refused(f"tag {arg} where COSE_Sign1 (18) or no tag was expected")
        tag_span, i = (0, j), j
        mt, arg, j, _ = _head(raw, i)
    else:
        tag_span = (0, 0)
    if mt != 4 or arg != 4:
        raise Refused(f"COSE_Sign1 must be an array of four elements (got major {mt}, n {arg})")
    head_span, i = (i, j), j
    spans, values = [], []
    for _ in range(4):
        v, end, _ = decode(raw, i, 1)
        spans.append((i, end))
        values.append(v)
        i = end
    prot_raw, unprot, payload, sig = values
    if not isinstance(prot_raw, bytes):
        raise Refused("protected header is not a byte string")
    if not isinstance(unprot, dict):
        raise Refused("unprotected header is not a map")
    if payload is not None and not isinstance(payload, bytes):
        raise Refused("payload is neither a byte string nor nil")
    if not isinstance(sig, bytes):
        raise Refused("signature is not a byte string")
    prot = {}
    if prot_raw:
        prot, _ = loads(prot_raw)
        if not isinstance(prot, dict):
            raise Refused("protected header does not decode to a map")
    return Sign1(raw, tagged, tag_span, head_span, spans, prot_raw, prot, unprot, payload, sig,
                 shortest)


def sig_structure(protected_raw: bytes, payload: bytes, external_aad: bytes = b"") -> bytes:
    """RFC 9052 section 4.4, ToBeSigned for COSE_Sign1."""
    return encode(["Signature1", protected_raw, external_aad, payload])


def sha(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


# ------------------------------------------------------------------------------------------
# Signatures with cryptography
# ------------------------------------------------------------------------------------------
def _crypto():
    from cryptography import x509  # noqa: PLC0415
    from cryptography.exceptions import InvalidSignature  # noqa: PLC0415
    from cryptography.hazmat.primitives import hashes, serialization  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils  # noqa: PLC0415
    return x509, InvalidSignature, hashes, serialization, ec, padding, rsa, utils


_EC = {  # COSE alg -> (curve name, hash, coordinate length)
    -7: ("SECP256R1", "SHA256", 32),
    -35: ("SECP384R1", "SHA384", 48),
    -36: ("SECP521R1", "SHA512", 66),
}
_PS = {-37: "SHA256", -38: "SHA384", -39: "SHA512"}


def verify_cose_signature(alg: int, public_key, tbs: bytes, signature: bytes) -> bool:
    """True or False for the algorithms named above; Refused for anything else."""
    x509, InvalidSignature, hashes, _ser, ec, padding, rsa, utils = _crypto()
    try:
        if alg in _EC:
            curve, hname, n = _EC[alg]
            if not isinstance(public_key, ec.EllipticCurvePublicKey) \
                    or public_key.curve.name.upper() != curve:
                return False                         # algorithm and key do not belong together
            if len(signature) != 2 * n:
                return False
            der = utils.encode_dss_signature(int.from_bytes(signature[:n], "big"),
                                             int.from_bytes(signature[n:], "big"))
            public_key.verify(der, tbs, ec.ECDSA(getattr(hashes, hname)()))
            return True
        if alg in _PS:
            if not isinstance(public_key, rsa.RSAPublicKey):
                return False
            h = getattr(hashes, _PS[alg])()
            public_key.verify(signature, tbs,
                              padding.PSS(mgf=padding.MGF1(h), salt_length=h.digest_size), h)
            return True
    except InvalidSignature:
        return False
    raise Refused(f"COSE algorithm {alg} is not implemented by this tool")


def cose_keyset(raw: bytes) -> dict:
    """kid (bytes) -> (public key, SPKI DER). EC2 keys only; anything else is listed, not used."""
    _x509, _inv, _h, serialization, ec, *_ = _crypto()
    keys, _ = loads(raw)
    if not isinstance(keys, list):
        raise Refused("COSE_KeySet is not an array")
    curves = {1: ec.SECP256R1(), 2: ec.SECP384R1(), 3: ec.SECP521R1()}
    out, skipped = {}, []
    for k in keys:
        if not isinstance(k, dict) or k.get(1) != 2 or k.get(-1) not in curves:
            skipped.append({"kty": k.get(1) if isinstance(k, dict) else None})
            continue
        x, y = k.get(-2), k.get(-3)
        pub = ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"),
                                            curves[k[-1]]).public_key()
        spki = pub.public_bytes(serialization.Encoding.DER,
                                serialization.PublicFormat.SubjectPublicKeyInfo)
        out[k.get(2)] = (pub, spki)
    return {"keys": out, "skipped": skipped}


def _no_duplicate_keys(pairs):
    seen = {}
    for k, v in pairs:
        if k in seen:
            raise Refused(f"duplicate JSON key {k!r}")
        seen[k] = v
    return seen


def _strict_b64():
    """The repository's one strict base64 decoder. tests/test_wire_bytes_strict.py and
    tests/test_lauf11_l2_scripts_dekodieren_strikt.py refuse a stdlib decode anywhere else, because
    only the wrapper refuses non-canonical input (one wire form per artefact)."""
    try:
        from proofbundle._wire_b64 import decode_b64  # noqa: PLC0415
        return decode_b64
    except ImportError:
        import importlib.util  # noqa: PLC0415
        path = HERE.parents[1] / "src" / "proofbundle" / "_wire_b64.py"
        spec = importlib.util.spec_from_file_location("_wire_b64_for_tool", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.decode_b64


def service_trust_store(raw: bytes) -> dict:
    """The JSON trust store of scitt-ccf-ledger's tests: CCF service certificates.

    Each certificate's key is filed under kid = hex(SHA-256(SubjectPublicKeyInfo)), the
    self-binding the receipts use. The store's own `signatureAlgorithm` label is recorded,
    never used: the algorithm comes from the protected header of what was signed.
    """
    decode_b64 = _strict_b64()
    x509, _inv, _h, serialization, *_ = _crypto()
    doc = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
    keys, entries = {}, []
    for p in doc["parameters"]:
        der = decode_b64(p["serviceCertificate"])
        cert = x509.load_der_x509_certificate(der)
        pub = cert.public_key()
        spki = pub.public_bytes(serialization.Encoding.DER,
                                serialization.PublicFormat.SubjectPublicKeyInfo)
        kid = sha(spki).hex().encode("ascii")
        keys[kid] = (pub, spki)
        entries.append({
            "kid": kid.decode("ascii"),
            "curve": getattr(getattr(pub, "curve", None), "name", None),
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "store_label_signatureAlgorithm": p.get("signatureAlgorithm"),
            "store_label_treeAlgorithm": p.get("treeAlgorithm"),
            "serviceId_equals_sha256_of_certificate": sha(der).hex() == p.get("serviceId")})
    return {"keys": keys, "skipped": [], "entries": entries}


# ------------------------------------------------------------------------------------------
# The four values
# ------------------------------------------------------------------------------------------
def data_hash_candidates(st: Sign1) -> dict:
    """Candidate byte strings for value 3, each with its sha256."""
    p, pl, sg = (st.raw[a:b] for (a, b) in (st.spans[0], st.spans[2], st.spans[3]))
    tag18 = b"\xd2"
    cands = {
        "as-served": st.raw,
        "unprotected-emptied/tagged/elements-as-served": tag18 + b"\x84" + p + b"\xa0" + pl + sg,
        "unprotected-emptied/untagged/elements-as-served": b"\x84" + p + b"\xa0" + pl + sg,
        "unprotected-emptied/tagged/payload-detached": tag18 + b"\x84" + p + b"\xa0\xf6" + sg,
        "unprotected-emptied/tagged/re-encoded": encode(
            Tag(18, [st.protected_raw, {}, st.payload, st.signature])),
        "tobesigned": sig_structure(st.protected_raw, st.payload or b""),
        "payload-only": st.payload or b"",
        "protected-only": st.protected_raw,
    }
    return {k: {"length": len(v), "sha256": sha(v).hex()} for k, v in cands.items()}


def value_1_hash_envelope(st: Sign1, artifacts: dict) -> dict:
    ph, uh = st.protected, st.unprotected
    if PAYLOAD_HASH_ALG not in ph:
        return {"present": False, "reason": "label 258 absent from the protected header"}
    out = {
        "present": True,
        "258_in_protected": ph.get(PAYLOAD_HASH_ALG),
        "258_in_unprotected": PAYLOAD_HASH_ALG in uh,
        "259_preimage_content_type": ph.get(PREIMAGE_CTY),
        "260_location_present": PAYLOAD_LOCATION in ph or PAYLOAD_LOCATION in uh,
        "label_3_present": CTY in ph or CTY in uh,
        "payload_length": None if st.payload is None else len(st.payload),
        "artifacts": {},
    }
    sizes = {SHA256_COSE: 32, -43: 48, -44: 64}
    out["payload_length_matches_hash_alg"] = (st.payload is not None and
                                              sizes.get(ph.get(PAYLOAD_HASH_ALG)) == len(st.payload))
    if not artifacts:
        out["artifacts"] = "NOT MEASURABLE: the hashed artifact is not published with the statement"
    elif ph.get(PAYLOAD_HASH_ALG) == SHA256_COSE and st.payload is not None:
        for name, raw in artifacts.items():
            out["artifacts"][name] = {"sha256": sha(raw).hex(), "equals_payload": sha(raw) == st.payload}
    return out


def value_2_local_tbs(st: Sign1) -> dict:
    if st.payload is None:
        return {"computed": False, "reason": "payload detached; ToBeSigned needs the payload "
                "from outside, and a missing payload is not an empty one"}
    tbs = sig_structure(st.protected_raw, st.payload)
    return {"computed": True, "rule": "SHA-256(Sig_structure), RFC 9052 section 4.4, "
            "external_aad empty; measured only to show it differs from value 3",
            "tobesigned_length": len(tbs), "sha256": sha(tbs).hex()}


def statement_signature(st: Sign1) -> dict:
    x509, *_ = _crypto()
    alg = st.protected.get(ALG)
    chain = st.protected.get(X5CHAIN)
    leaf = chain[0] if isinstance(chain, list) and chain else chain
    if not isinstance(leaf, bytes):
        return {"alg": alg, "evaluated": False, "reason": "no x5chain leaf in the protected header"}
    if st.payload is None:
        return {"alg": alg, "evaluated": False, "reason": "payload detached"}
    cert = x509.load_der_x509_certificate(leaf)
    try:
        ok = verify_cose_signature(alg, cert.public_key(), sig_structure(st.protected_raw,
                                                                         st.payload), st.signature)
    except Refused as exc:
        return {"alg": alg, "evaluated": False, "reason": str(exc)}
    return {"alg": alg, "evaluated": True, "valid_with_embedded_leaf_key": ok,
            "trust": "none: the key comes from the evidence itself (x5chain); this is a "
                     "consistency check, not an identity or trust decision"}


def fold(leaf_hash: bytes, path) -> bytes:
    h = leaf_hash
    for left, sibling in path:
        h = sha(sibling + h) if left else sha(h + sibling)
    return h


def receipt(raw_receipt: bytes, keyset: dict | None, expected_data_hash: bytes | None) -> dict:
    """Three separate results: readable, signature_valid, receipt_profile_satisfied."""
    r = {"length": len(raw_receipt), "sha256": sha(raw_receipt).hex(),
         "readable": False, "signature_valid": None, "receipt_profile_satisfied": False,
         "problems": []}
    try:
        rc = parse_sign1(raw_receipt)
    except Refused as exc:
        r["problems"].append(f"not readable: {exc}")
        return r
    ph, uh = rc.protected, rc.unprotected
    r["tagged"] = rc.tagged
    r["protected_labels"] = sorted(map(str, ph))
    r["alg"], r["vds"] = ph.get(ALG), ph.get(VDS)
    kid = ph.get(KID)
    r["kid"] = kid.decode("ascii", "replace") if isinstance(kid, bytes) else kid
    r["crit_present"] = CRIT in ph
    cwt = ph.get(CWT) if isinstance(ph.get(CWT), dict) else {}
    r["cwt"] = {"iss": cwt.get(1), "sub": cwt.get(2), "iat": cwt.get(6)}
    ccf = ph.get("ccf.v1") if isinstance(ph.get("ccf.v1"), dict) else {}
    r["ccf_txid"] = ccf.get("txid")
    r["payload_detached"] = rc.payload is None
    proofs = (uh.get(VDP) or {}).get(INCLUSION) if isinstance(uh.get(VDP), dict) else None
    if not isinstance(proofs, list) or not proofs:
        r["problems"].append("no inclusion proofs under 396/-1")
        return r
    roots, leaves = [], []
    for pr in proofs:
        try:
            d, _ = loads(pr) if isinstance(pr, bytes) else (None, None)
        except Refused as exc:
            r["problems"].append(f"inclusion proof not readable: {exc}")
            return r
        if not isinstance(d, dict) or not isinstance(d.get(1), list) or len(d[1]) != 3 \
                or not isinstance(d.get(2), list):
            r["problems"].append("inclusion proof is not {1: leaf[3], 2: path}")
            return r
        itx, ev, dh = d[1]
        if not (isinstance(itx, bytes) and len(itx) == 32 and isinstance(dh, bytes)
                and len(dh) == 32 and isinstance(ev, str) and 1 <= len(ev.encode()) <= 1024):
            r["problems"].append("leaf components violate the -05 CDDL sizes")
            return r
        path = d[2]
        if not all(isinstance(e, list) and len(e) == 2 and isinstance(e[0], bool)
                   and isinstance(e[1], bytes) and len(e[1]) == 32 for e in path):
            r["problems"].append("path element is not [bool, bstr .size 32]")
            return r
        leaf_input = itx + sha(ev.encode("utf-8")) + dh
        lh = sha(leaf_input)
        root = fold(lh, path)
        leaves.append({"internal_transaction_hash": itx.hex(), "internal_evidence": ev,
                       "data_hash": dh.hex(), "leaf_input_length": len(leaf_input),
                       "leaf_hash": lh.hex(), "path_length": len(path),
                       "path_left_bits": "".join("1" if e[0] else "0" for e in path),
                       "merkle_root": root.hex()})
        roots.append(root)
    r["readable"] = True
    r["inclusion_proofs"] = leaves
    r["all_proofs_same_root"] = len(set(roots)) == 1
    root = roots[0]
    if expected_data_hash is not None:
        r["bound_to_statement"] = all(bytes.fromhex(x["data_hash"]) == expected_data_hash
                                      for x in leaves)
    if keyset is None:
        r["trust"] = "none supplied"
        r["problems"].append("signature NOT EVALUATED: no trust material")
    else:
        hit = keyset["keys"].get(kid)
        if hit is None:
            r["trust"] = "kid not in the relying party's key set"
            r["problems"].append("signature NOT EVALUATED: no trusted key for this kid")
        else:
            pub, spki = hit
            r["trust"] = "key selected by kid from the relying party's key set"
            r["kid_equals_hex_sha256_spki"] = (isinstance(kid, bytes)
                                               and kid.decode("ascii", "replace") == sha(spki).hex())
            try:
                r["signature_valid"] = verify_cose_signature(
                    r["alg"], pub, sig_structure(rc.protected_raw, root), rc.signature)
            except Refused as exc:
                r["problems"].append(f"signature NOT EVALUATED: {exc}")
    # The RECEIPT side of the profile only. The statement side (value 1 as an RFC 9995 hash
    # envelope equal to a proofbundle root) is reported per statement, not folded in here.
    r["receipt_profile_satisfied"] = bool(
        r["readable"] and r["vds"] == CCF_LEDGER_SHA256 and r["payload_detached"]
        and r["all_proofs_same_root"] and r["signature_valid"] is True
        and r.get("bound_to_statement") is True)
    return r


def _tags(v, path="") -> list:
    """Every CBOR tag inside a decoded value, with where it sits."""
    out = []
    if isinstance(v, Tag):
        out.append({"at": path or "/", "tag": v.number})
        out += _tags(v.value, f"{path}/tag{v.number}")
    elif isinstance(v, list):
        for i, x in enumerate(v):
            out += _tags(x, f"{path}[{i}]")
    elif isinstance(v, dict):
        for k, x in v.items():
            out += _tags(x, f"{path}/{k}")
    return out


def statement_case(raw: bytes, keyset: dict | None, artifacts: dict) -> dict:
    out = {"length": len(raw), "sha256": sha(raw).hex()}
    try:
        st = parse_sign1(raw)
    except Refused as exc:
        out["readable"] = False
        out["problem"] = str(exc)
        return out
    out["readable"] = True
    out["tagged"] = st.tagged
    out["outer_array"] = "definite, 4 elements"
    out["all_heads_shortest_form"] = st.shortest
    out["elements"] = {n: {"offset": a, "length": b - a}
                       for n, (a, b) in zip(("protected", "unprotected", "payload", "signature"),
                                            st.spans)}
    out["protected_labels"] = sorted(map(str, st.protected))
    out["unprotected_labels"] = sorted(map(str, st.unprotected))
    out["tags_inside_protected_header"] = _tags(st.protected)
    out["payload"] = "detached" if st.payload is None else f"embedded, {len(st.payload)} B"
    out["value_1_hash_envelope"] = value_1_hash_envelope(st, artifacts)
    out["value_2_local_tobesigned"] = value_2_local_tbs(st)
    out["statement_signature"] = statement_signature(st)
    receipts = st.unprotected.get(RECEIPTS)
    if not isinstance(receipts, list):
        out["value_3_data_hash"] = {"evaluated": False, "reason": "no receipt (label 394 absent)"}
        return out
    cands = data_hash_candidates(st)
    leaf_dhs = set()
    rec = []
    rule = "unprotected-emptied/tagged/elements-as-served"
    for rr in receipts:
        rec.append(receipt(rr, keyset, bytes.fromhex(cands[rule]["sha256"])))
        for p in rec[-1].get("inclusion_proofs", []):
            leaf_dhs.add(p["data_hash"])
    for c in cands.values():
        c["equals_a_receipt_data_hash"] = c["sha256"] in leaf_dhs
    out["value_3_data_hash"] = {
        "evaluated": True, "data_hashes_in_receipts": sorted(leaf_dhs),
        "candidates": cands,
        "matching_rules": [k for k, v in cands.items() if v["equals_a_receipt_data_hash"]]}
    out["receipts"] = rec
    out["value_4_merkle_roots"] = sorted({p["merkle_root"] for r in rec
                                          for p in r.get("inclusion_proofs", [])})
    return out


# ------------------------------------------------------------------------------------------
# Probes: every comparison must be seen to fail once
# ------------------------------------------------------------------------------------------
def _flip(raw: bytes, offset: int) -> bytes:
    b = bytearray(raw)
    b[offset] ^= 0x01
    return bytes(b)


def probes(raw: bytes, keyset: dict, other_keyset: dict) -> list:
    st = parse_sign1(raw)
    rr = st.unprotected[RECEIPTS][0]
    rule = "unprotected-emptied/tagged/elements-as-served"
    dh = bytes.fromhex(data_hash_candidates(st)[rule]["sha256"])
    control = receipt(rr, keyset, dh)
    out = [{"probe": "control, unchanged statement and receipt",
            "signature_valid": control["signature_valid"],
            "bound_to_statement": control.get("bound_to_statement"),
            "receipt_profile_satisfied": control["receipt_profile_satisfied"]}]

    a, b = st.spans[3]                                   # last byte of the statement signature
    flipped = parse_sign1(_flip(raw, b - 1))
    dh2 = bytes.fromhex(data_hash_candidates(flipped)[rule]["sha256"])
    r2 = receipt(rr, keyset, dh2)
    out.append({"probe": "one bit of the statement's signature element flipped",
                "data_hash_rule_still_matches": r2.get("bound_to_statement"),
                "statement_signature_valid":
                    statement_signature(flipped).get("valid_with_embedded_leaf_key"),
                "receipt_signature_valid": r2["signature_valid"],
                "receipt_profile_satisfied": r2["receipt_profile_satisfied"]})

    rc = parse_sign1(rr)
    prf, _ = loads(rc.unprotected[VDP][INCLUSION][0])
    itx, ev, leaf_dh = prf[1]
    path = [list(e) for e in prf[2]]
    path[0][1] = _flip(path[0][1], 0)
    root_bad = fold(sha(itx + sha(ev.encode()) + leaf_dh), path)
    pub = keyset["keys"][rc.protected[KID]][0]
    out.append({"probe": "one bit of the first path hash flipped",
                "receipt_signature_valid": verify_cose_signature(
                    rc.protected[ALG], pub, sig_structure(rc.protected_raw, root_bad),
                    rc.signature)})

    root = fold(sha(itx + sha(ev.encode()) + leaf_dh), prf[2])
    out.append({"probe": "external_aad one byte 0x00 instead of empty",
                "receipt_signature_valid": verify_cose_signature(
                    rc.protected[ALG], pub, sig_structure(rc.protected_raw, root, b"\x00"),
                    rc.signature)})

    # The two literal readings of -04 measured in tools/scitt_ccf_merkle_lesarten, and the
    # hybrid named there, now held against a real receipt. -05 states reading 3.2 explicitly.
    for label, leaf_input in (
            ("leaf = HASH(CBOR(ccf-leaf)), the -04 reading of section 2.1",
             encode([itx, ev, leaf_dh])),
            ("leaf = HASH(itx || internal-evidence || data-hash), evidence not hashed (hybrid)",
             itx + ev.encode("utf-8") + leaf_dh),
            ("leaf = HASH(itx || HASH(internal-evidence) || data-hash), -05 and -04 section 3.2",
             itx + sha(ev.encode("utf-8")) + leaf_dh)):
        out.append({"probe": label, "receipt_signature_valid": verify_cose_signature(
            rc.protected[ALG], pub, sig_structure(rc.protected_raw, fold(sha(leaf_input), prf[2])),
            rc.signature)})

    # Value 2 is not value 3. ECDSA signatures are randomised, so one ToBeSigned has many valid
    # statements. Synthetic: a key generated here, an invented protected header, no service.
    _x509, _inv, hashes, _ser, ec, _pad, _rsa, utils = _crypto()
    key = ec.generate_private_key(ec.SECP256R1())
    prot = encode({ALG: -7})
    tbs = sig_structure(prot, b"\x00" * 32)
    stmts = []
    for _ in range(2):
        r_, s_ = utils.decode_dss_signature(key.sign(tbs, ec.ECDSA(hashes.SHA256())))
        stmts.append(parse_sign1(encode(Tag(18, [prot, {}, b"\x00" * 32,
                                                 r_.to_bytes(32, "big") + s_.to_bytes(32, "big")]))))
    v2 = [value_2_local_tbs(s)["sha256"] for s in stmts]
    v3 = [data_hash_candidates(s)[rule]["sha256"] for s in stmts]
    out.append({"probe": "synthetic: one ToBeSigned signed twice with ECDSA P-256 (key made here)",
                "value_2_equal": v2[0] == v2[1], "value_3_equal": v3[0] == v3[1],
                "both_signatures_valid": all(verify_cose_signature(
                    -7, key.public_key(), tbs, s.signature) for s in stmts)})

    r3 = receipt(rr, other_keyset, dh)
    out.append({"probe": "trust material of another service (kid absent)",
                "signature_valid": r3["signature_valid"], "trust": r3.get("trust"),
                "receipt_profile_satisfied": r3["receipt_profile_satisfied"]})
    r4 = receipt(rr, None, dh)
    out.append({"probe": "no trust material at all",
                "signature_valid": r4["signature_valid"], "trust": r4.get("trust"),
                "receipt_profile_satisfied": r4["receipt_profile_satisfied"]})
    return out


def main() -> int:
    try:
        import cryptography  # noqa: PLC0415
    except ImportError:
        print("NOT MEASURABLE: the `cryptography` package is not installed.", file=sys.stderr)
        return 2
    sys.path.insert(0, str(HERE))
    from fetch_external import EXPECTED  # noqa: PLC0415

    files = {}
    for name, (_s, _p, size, digest) in EXPECTED.items():
        path = FETCHED / name
        if not path.is_file():
            print(f"NOT MEASURABLE: {path} is missing; run fetch_external.py first.",
                  file=sys.stderr)
            return 2
        raw = path.read_bytes()
        if len(raw) != size or sha(raw).hex() != digest:
            print(f"REFUSED: {name} does not match its pinned digest.", file=sys.stderr)
            return 1
        files[name] = raw

    keyset = cose_keyset(files["mst-test-scitt-keys.cbor"])
    other = cose_keyset(files["other-service-scitt-keys.cbor"])
    artifacts = {n: files[n] for n in ("hash-envelope-artifact.spdx.json",
                                       "hash-envelope-bad-artifact.spdx.json")}
    cases = {}
    for name in ("transparent-statement.cose", "cbor-header.cose", "nested-sign1.cose",
                 "appended-receipt.cose", "payload-tampered.cose", "tampered-statement.cose",
                 "hash-envelope.cose"):
        cases[name] = statement_case(files[name], keyset, artifacts)
    cases["microsoft-mst-receipt.cbor"] = {
        "note": "a receipt without its statement and without reachable trust material",
        "receipt": receipt(files["microsoft-mst-receipt.cbor"], None, None)}
    # Production Microsoft Signing Transparency, via scitt-ccf-ledger's own test data: a hash
    # envelope statement and the service trust store that repository checks it against.
    store = service_trust_store(files["esrp-cts-db.json"])
    cases["uvm_0.2.10.cose"] = statement_case(files["uvm_0.2.10.cose"], store, {})
    cases["cts-hashv-cwtclaims-b64url.cose"] = statement_case(
        files["cts-hashv-cwtclaims-b64url.cose"], None, {})

    pins = {}
    for name, pin in UPSTREAM_PINS.items():
        c = cases[name]
        cand = c["value_3_data_hash"]["candidates"]["unprotected-emptied/tagged/elements-as-served"]
        pins[name] = {"upstream": pin, "ours": {
            "signed_statement_length": cand["length"], "claim_digest": cand["sha256"],
            "merkle_root": c["value_4_merkle_roots"][0]},
            "equal": (pin["signed_statement_length"] == cand["length"]
                      and pin["claim_digest"] == cand["sha256"]
                      and [pin["merkle_root"]] == c["value_4_merkle_roots"])}

    result = {
        "tool": "tools/scitt_ccf_external/recompute.py",
        "measured_on": datetime.date.today().isoformat(),
        "environment": {"python": platform.python_version(),
                        "implementation": platform.python_implementation(),
                        "machine": platform.machine(),
                        "cryptography": cryptography.__version__},
        "profile_basis": "draft-ietf-scitt-receipts-ccf-profile-05, leaf "
                         "HASH(internal-transaction-hash || HASH(internal-evidence) || data-hash)",
        "inputs": {n: {"length": len(v), "sha256": sha(v).hex(),
                       "source": EXPECTED[n][0], "path": EXPECTED[n][1]}
                   for n, v in files.items()},
        "trust_material": {
            "key_set": "mst-test-scitt-keys.cbor",
            "kids": sorted(k.decode("ascii", "replace") for k in keyset["keys"]),
            "other_service_kids": sorted(k.decode("ascii", "replace") if isinstance(k, bytes)
                                         else str(k) for k in other["keys"]),
            "other_service_skipped_keys": other["skipped"],
            "esrp_cts_db_trust_store": store["entries"]},
        "cases": cases,
        "probes_on_transparent_statement": probes(files["transparent-statement.cose"], keyset,
                                                  other),
        "upstream_pins": pins,
    }
    RESULT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    ts = cases["transparent-statement.cose"]
    print("value 3 rule matching the receipt:", ts["value_3_data_hash"]["matching_rules"])
    for name, c in cases.items():
        recs = c.get("receipts") or ([c["receipt"]] if "receipt" in c else [])
        for i, r in enumerate(recs):
            print(f"  {name:28s} receipt {i}: readable={r['readable']!s:5} "
                  f"signature_valid={r['signature_valid']!s:5} "
                  f"bound={r.get('bound_to_statement')!s:5} "
                  f"receipt_profile_satisfied={r['receipt_profile_satisfied']}")
    print("upstream pins equal:", {k: v["equal"] for k, v in pins.items()})
    print(f"written: {RESULT.relative_to(HERE.parents[1])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
