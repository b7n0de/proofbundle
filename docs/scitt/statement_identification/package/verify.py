#!/usr/bin/env python3
"""Check this package offline: every signature, every digest, every reference. Needs cbor2 and cryptography.

Usage: python3 verify.py [package directory]   (default: the directory this file is in)
Prints one line per check, OK or FAIL, and exits 0 only if every check is OK.
"""
import hashlib
import json
import sys
from pathlib import Path

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

ALG, CWT_CLAIMS, ISS, SUB = 1, 15, 1, 2
EDDSA, SHA256 = -8, -16
REF = -70001  # the private-use header label this package uses for references

HERE = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent
failed = 0


def check(ok: bool, text: str) -> None:
    global failed
    print(("OK   " if ok else "FAIL ") + text)
    failed += not ok


def read_hex(name: str) -> bytes:
    return bytes.fromhex("".join((HERE / name).read_text(encoding="ascii").split()))


def open_sign1(raw: bytes):
    """-> (tagged, protected bytes, unprotected map, payload, signature) of a COSE_Sign1."""
    item = cbor2.loads(raw)
    tagged = isinstance(item, cbor2.CBORTag)
    if tagged:
        if item.tag != 18:
            raise ValueError(f"tag {item.tag}, not 18 (COSE_Sign1)")
        item = item.value
    if not (isinstance(item, (list, tuple)) and len(item) == 4):
        raise ValueError("a COSE_Sign1 is an array of four elements")
    protected, unprotected, payload, signature = item
    return tagged, protected, unprotected, payload, signature


def to_be_signed(protected: bytes, payload: bytes) -> bytes:
    """RFC 9052 section 4.4: Sig_structure ["Signature1", protected, external_aad, payload], aad empty."""
    return cbor2.dumps(["Signature1", protected, b"", payload])


def signature_ok(key: Ed25519PublicKey, signature: bytes, message: bytes) -> bool:
    try:
        key.verify(signature, message)
        return True
    except InvalidSignature:
        return False


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    doc = json.loads((HERE / "references.json").read_text(encoding="utf-8"))
    raw, headers, tbs = {}, {}, {}

    # 1. Every statement: shape, signature, the two digests, issuer and subject.
    for name, want in doc["statements"].items():
        raw[name] = read_hex(name)
        try:
            tagged, protected, _unprotected, payload, signature = open_sign1(raw[name])
            headers[name] = cbor2.loads(protected)
        except (ValueError, TypeError, cbor2.CBORDecodeError) as exc:
            check(False, f"{name}: not a readable COSE_Sign1 ({type(exc).__name__}: {exc})")
            continue
        tbs[name] = to_be_signed(protected, payload)
        key = load_pem_public_key((HERE / want["public_key"]).read_bytes())
        check(tagged and headers[name].get(ALG) == EDDSA and isinstance(key, Ed25519PublicKey),
              f"{name}: COSE_Sign1 with tag 18, alg -8 (EdDSA), {len(raw[name])} bytes")
        check(signature_ok(key, signature, tbs[name]), f"{name}: signature verifies under {want['public_key']}")
        check(sha256(tbs[name]) == want["sha256_to_be_signed"],
              f"{name}: SHA-256 of ToBeSigned = {sha256(tbs[name])}")
        check(sha256(raw[name]) == want["sha256_cose_sign1"],
              f"{name}: SHA-256 of the whole COSE_Sign1 = {sha256(raw[name])}")
        claims = headers[name].get(CWT_CLAIMS, {})
        check(claims.get(ISS) == want["iss"] and claims.get(SUB) == want["sub"],
              f"{name}: iss {claims.get(ISS)}, sub {claims.get(SUB)}")

    # 2. Every reference: the signed header carries it, and it names the bytes it says it names.
    for i, ref in enumerate(doc["references"]):
        src, dst = ref["from"], ref["to"]
        if src not in headers or dst not in headers:
            check(False, f"reference {i}: {src} -> {dst}: a statement it needs is not readable")
            continue
        carried = headers[src].get(REF, [])
        index = int(ref["location"].rsplit("entry ", 1)[1])
        entry = list(carried[index]) if index < len(carried) else None
        check(entry == [SHA256, ref["covers"], bytes.fromhex(ref["digest"])],
              f"reference {i}: {src} carries [-16, {ref['covers']!r}, {ref['digest'][:16]}...] "
              f"under label {REF} in its protected header")
        if ref["covers"] == "ToBeSigned":
            covered = tbs[dst]
        elif ref["covers"] == "COSE_Sign1":
            covered = raw[dst]
        else:
            check(False, f"reference {i}: unknown covered bytes {ref['covers']!r}")
            continue
        check(sha256(covered) == ref["digest"],
              f"reference {i}: {src} -> {dst}: SHA-256 over its {ref['covers']} matches")

    # 3. Same issuer, same subject, different statements: the subject does not tell them apart.
    a, b = "01-original.cose.hex", "03-correction.cose.hex"
    if a not in headers or b not in headers:
        check(False, f"{a} and {b}: not both readable, the last two checks cannot run")
        print(f"FAILED: {failed} check(s) failed")
        return 1
    same = all(headers[a][CWT_CLAIMS][k] == headers[b][CWT_CLAIMS][k] for k in (ISS, SUB))
    check(same and sha256(tbs[a]) != sha256(tbs[b]),
          f"{a} and {b}: same iss and sub, different ToBeSigned digests")

    # 4. The same statement in another envelope: untagged, with an unprotected header added after
    #    signing, as a transparency service adds a receipt. Signature and ToBeSigned stay the same.
    _tagged, protected, _unprotected, payload, signature = open_sign1(raw[a])
    moved = cbor2.dumps([protected, {-70002: "added after signing"}, payload, signature])
    _t, p2, _u, pl2, s2 = open_sign1(moved)
    key = load_pem_public_key((HERE / doc["statements"][a]["public_key"]).read_bytes())
    check(signature_ok(key, s2, to_be_signed(p2, pl2)) and to_be_signed(p2, pl2) == tbs[a]
          and sha256(moved) != sha256(raw[a]),
          f"{a} re-enveloped ({len(moved)} bytes): signature and ToBeSigned digest unchanged, "
          f"whole-COSE_Sign1 digest changed")

    print(f"{'FAILED' if failed else 'ALL OK'}: {failed} check(s) failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
