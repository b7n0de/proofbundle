#!/usr/bin/env python3
"""Checks for the examples of draft-gruszka-evaluation-receipt-mappings-01. It does not import the
generator; it re-derives every claim from the bytes in mappings.json:

  D1  the receipt digest is SHA-256 over B, and B is the payload of the receipt bytes;
  M1  the DSSE envelope's payload is B, its payloadType is the receipt type, and its signature verifies
      as a DSSE signature, Ed25519 over PAE(payloadType, payload), under the issuer key, with the
      bytes of the receipt's own signature (no new signature);
  M2  the COSE_Sign1 is tag 18, its unprotected header is empty, the protected header carries alg -19,
      kid = RFC 9679 thumbprint of the issuer key, CWT iss and sub, 258 = -16 and 259 = the receipt
      type, its payload equals the receipt digest, and its signature verifies over Sig_structure;
  C   for each citation case, the match result computed here from the candidate's bytes (read from the
      receipts draft's vectors.json and checked against the SHA-256 in mappings.json) equals the
      expected one. B is obtained by steps 1 to 3 of the receipts draft, written here again; only
      SHA-256 is a defined citation algorithm.
  S   for M2 with P1 and for each status vector, the status computed here by steps 1 to 7 of the checking
      procedure, written here again from the text, under the one configured pair of the examples (the issuer
      URI and the issuer test key), equals the expected status; the candidate is read from the receipts
      draft's vectors.json and checked against the SHA-256 in mappings.json, and step 5 runs the receipts
      draft's own checker.
Exit 0 when all hold.
"""
import base64
import hashlib
import json
import os
import re
import sys
from collections.abc import Mapping

import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

TYPE = "application/vnd.signed-evidence.eval-receipt+json"
RECEIPT_VECTORS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "ser", "examples",
                               "vectors.json")
B64_RE = re.compile(r"\A(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\Z")


class NoB(Exception):
    """B cannot be obtained from the candidate (a step from 1 to 3 of the receipts draft fails)."""


def _pairs(pairs):
    names = [k for k, _ in pairs]
    if len(names) != len(set(names)):
        raise NoB("duplicate member name")
    return dict(pairs)


def _strings(v):
    if isinstance(v, str):
        yield v
    elif isinstance(v, dict):
        for k, x in v.items():
            yield k
            yield from _strings(x)
    elif isinstance(v, list):
        for x in v:
            yield from _strings(x)


def b_of(receipt: bytes) -> bytes:
    """Steps 1 to 3 of the receipts draft: strict parse, member sets, schema, canonical base64."""
    if receipt.startswith(b"\xef\xbb\xbf"):
        raise NoB("byte order mark")
    try:
        text = receipt.decode("utf-8")
        obj = json.loads(text, object_pairs_hook=_pairs)
    except NoB:
        raise
    except (UnicodeDecodeError, ValueError) as e:
        raise NoB("not one JSON text: %s" % e) from None
    for st in _strings(obj):
        for ch in st:
            c = ord(ch)
            if 0xD800 <= c <= 0xDFFF or 0xFDD0 <= c <= 0xFDEF or (c & 0xFFFE) == 0xFFFE:
                raise NoB("surrogate or noncharacter")
    if not isinstance(obj, dict) or set(obj) != {"schema", "payload_b64", "signature"}:
        raise NoB("receipt member set")
    sig = obj["signature"]
    if not isinstance(sig, dict) or set(sig) not in ({"alg", "sig"}, {"alg", "sig", "key"}):
        raise NoB("signature member set")
    if obj["schema"] != TYPE:
        raise NoB("schema")
    pb = obj["payload_b64"]
    if not isinstance(pb, str) or not B64_RE.match(pb):
        raise NoB("payload_b64 not base64 with padding")
    raw = base64.b64decode(pb, validate=True)
    if base64.b64encode(raw).decode("ascii") != pb:
        raise NoB("payload_b64 not canonical")
    return raw


def match(citation, receipt: bytes) -> str:
    if citation.get("alg") != "sha-256" or not re.fullmatch(r"[0-9a-f]{64}", citation.get("hex", "")):
        return "INDETERMINATE"
    try:
        b = b_of(receipt)
    except NoB:
        return "INDETERMINATE"
    return "MATCH" if hashlib.sha256(b).hexdigest() == citation["hex"] else "NO_MATCH"


ISS_RE = re.compile(r"\A[A-Za-z][A-Za-z0-9+.-]*:[^#\s\[\]]+\Z")
SUB_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
L_ORDER = 2 ** 252 + 27742317777372353535851937790883648493


def deterministic(b: bytes):
    """One CBOR data item in the core deterministic encoding: decoded, then re-encoded byte for byte."""
    try:
        item = cbor2.loads(b)
    except Exception:  # noqa: BLE001  not well-formed, trailing bytes, invalid UTF-8
        return None, False
    try:
        again = cbor2.dumps(item, canonical=True)
    except Exception:  # noqa: BLE001
        return item, False
    return item, again == b


def check_statement(stmt: bytes, candidate: bytes, receipt_key: bytes, pairs):
    """Steps 1 to 7; returns (status, step) with step None for accepted."""
    import check_receipts  # noqa: PLC0415  the receipts draft's own checker, for step 5 only
    item, det = deterministic(stmt)
    if item is None or not det:
        return "malformed", 1
    if isinstance(item, cbor2.CBORTag):
        if item.tag != 18:
            return "malformed", 1
        arr, tagged = item.value, True
    else:
        arr, tagged = item, False
    # cbor2 5 decodes an array as list and a map as dict, cbor2 6 inside an array as tuple and frozendict
    if not (isinstance(arr, (list, tuple)) and len(arr) == 4 and isinstance(arr[0], bytes)
            and isinstance(arr[1], Mapping) and isinstance(arr[2], (bytes, type(None))) and isinstance(arr[3], bytes)):
        return "malformed", 1
    prot_b, unprot, payload, sig = arr
    prot, pdet = deterministic(prot_b) if prot_b else ({}, True)
    if not isinstance(prot, Mapping) or not pdet:
        return "malformed", 1
    cwt = prot.get(15)
    if (not tagged or unprot != {} or set(prot) != {1, 4, 15, 258, 259} or prot[1] not in (-19, -8)
            or not (isinstance(prot[4], bytes) and len(prot[4]) == 32) or not isinstance(cwt, Mapping)
            or set(cwt) != {1, 2} or not isinstance(cwt[1], str) or not ISS_RE.match(cwt[1])
            or not isinstance(cwt[2], str) or not SUB_RE.match(cwt[2]) or prot[258] != -16 or prot[259] != TYPE
            or not isinstance(payload, bytes) or len(payload) != 32 or len(sig) != 64):
        return "outside_profile", 2
    selected = [k for iss, k in pairs if iss == cwt[1] and len(k) == 32
                and hashlib.sha256(cbor2.dumps({1: 1, -1: 6, -2: k}, canonical=True)).digest() == prot[4]]
    if not selected:
        return "untrusted_key", 3
    tbs = cbor2.dumps(["Signature1", prot_b, b"", payload], canonical=True)
    good = False
    for k in selected:
        if int.from_bytes(sig[32:], "little") >= L_ORDER:
            continue
        try:
            Ed25519PublicKey.from_public_bytes(k).verify(sig, tbs)
            good = True
        except Exception:  # noqa: BLE001
            pass
    if not good:
        return "signature_invalid", 4
    verdict, _step, _ = check_receipts.verify(candidate, receipt_key)
    if verdict != "PASS":
        return "receipt_not_verified", 5
    cb = b_of(candidate)
    if payload != hashlib.sha256(cb).digest():
        return "digest_mismatch", 6
    if cwt[2] != json.loads(cb)["model_id_commit"]:
        return "subject_mismatch", 7
    return "accepted", None


def pae(typ, body):
    t = typ.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(body), body)


def check(label, cond):
    print(("OK   " if cond else "FAIL ") + label)
    return bool(cond)


def main():
    d = json.load(open(sys.argv[1] if len(sys.argv) > 1 else "mappings.json", encoding="utf-8"))
    pub = base64.b64decode(d["issuer_public_key_b64"])
    vk = Ed25519PublicKey.from_public_bytes(pub)
    receipt = json.loads(bytes.fromhex(d["receipt_hex"]))
    B = base64.b64decode(receipt["payload_b64"])
    ok = True
    ok &= check("D1 B in the summary is the receipt's payload", B.hex() == d["payload_B_hex"])
    ok &= check("D1 receipt digest = SHA-256(B)", hashlib.sha256(B).hexdigest() == d["receipt_digest"]["hex"])

    ok &= check("D1 the summary carries no leaf hash (the receipt has no inclusion proof)", "leaf_hash_hex" not in d)
    ok &= check("D1 SHA-256 of the receipt bytes differs from the receipt digest",
                hashlib.sha256(bytes.fromhex(d["receipt_hex"])).hexdigest() != d["receipt_digest"]["hex"])
    env = json.loads(bytes.fromhex(d["M1_dsse"]["envelope_hex"]))
    eB = base64.b64decode(env["payload"])
    ok &= check("M1 payloadType is the receipt type", env["payloadType"] == TYPE)
    ok &= check("M1 payload is B", eB == B)
    esig = base64.b64decode(env["signatures"][0]["sig"])
    ok &= check("M1 DSSE signature bytes equal the receipt signature",
                esig == base64.b64decode(receipt["signature"]["sig"]))
    try:
        vk.verify(esig, pae(env["payloadType"], eB))
        dsse_ok = True
    except Exception:  # noqa: BLE001
        dsse_ok = False
    ok &= check("M1 DSSE verification: Ed25519 over PAE(payloadType, payload) under the issuer key", dsse_ok)

    tag = cbor2.loads(bytes.fromhex(d["M2_scitt_hash_envelope"]["cose_sign1_hex"]))
    ok &= check("M2 CBOR tag 18 (COSE_Sign1)", isinstance(tag, cbor2.CBORTag) and tag.tag == 18)
    prot_b, unprot, payload, sig = tag.value
    prot = cbor2.loads(prot_b)
    thumb = hashlib.sha256(cbor2.dumps({1: 1, -1: 6, -2: pub}, canonical=True)).digest()
    ok &= check("M2 unprotected header is empty", unprot == {})
    keys_sorted = sorted(prot, key=lambda k: cbor2.dumps(k))
    ok &= check("M2 protected header keys in bytewise order of their encodings (RFC 8949 Section 4.2.1)",
                list(prot) == keys_sorted)
    ok &= check("M2 protected header bytes are the deterministic encoding of the map",
                cbor2.dumps({k: prot[k] for k in keys_sorted}) == prot_b)
    ok &= check("M2 alg -19", prot.get(1) == -19)
    ok &= check("M2 kid = RFC 9679 thumbprint of the issuer key", prot.get(4) == thumb)
    ok &= check("M2 CWT claims iss and sub present", isinstance(prot.get(15), dict) and {1, 2} <= set(prot[15]))
    ok &= check("M2 sub = the receipt's model commitment", prot[15].get(2) == json.loads(B)["model_id_commit"])
    ok &= check("M2 258 = -16 (SHA-256)", prot.get(258) == -16)
    ok &= check("M2 259 = the receipt type", prot.get(259) == TYPE)
    ok &= check("M2 payload = receipt digest", payload == hashlib.sha256(B).digest())
    tbs = cbor2.dumps(["Signature1", prot_b, b"", payload], canonical=True)
    try:
        vk.verify(sig, tbs)
        cose_ok = True
    except Exception:  # noqa: BLE001
        cose_ok = False
    ok &= check("M2 COSE signature over Sig_structure verifies under the issuer key", cose_ok)
    ok &= check("M2 ToBeSigned in the summary equals the recomputed one",
                tbs.hex() == d["M2_scitt_hash_envelope"]["to_be_signed_hex"])
    rv = json.load(open(RECEIPT_VECTORS, encoding="utf-8"))
    by_id = {v["id"]: v for v in rv["vectors"]}
    for c in d["citation_cases"]:
        cand = bytes.fromhex(by_id[c["candidate"]]["receipt_hex"])
        ok &= check("%s candidate bytes are %s of the receipts draft" % (c["id"], c["candidate"]),
                    hashlib.sha256(cand).hexdigest() == c["candidate_receipt_sha256"])
        h = {"sha-256": hashlib.sha256, "sha-512": hashlib.sha512}[c["citation"]["alg"]]
        ok &= check("%s cited value is %s over B of P1" % (c["id"], c["citation"]["alg"]),
                    h(B).hexdigest() == c["citation"]["hex"])
        got = match(c["citation"], cand)
        ok &= check("%s match = %s (expected %s)" % (c["id"], got, c["expected_match"]), got == c["expected_match"])
    sys.path.insert(0, os.path.dirname(RECEIPT_VECTORS))
    pairs = [(d["receiver_pairs"][0][0], pub)]
    ok &= check("S the examples configure one pair: the issuer URI of M2 and the issuer test key",
                d["receiver_pairs"] == [[d["M2_scitt_hash_envelope"]["iss"], "issuer test key"]])
    p1 = bytes.fromhex(by_id["P1"]["receipt_hex"])
    got = check_statement(bytes.fromhex(d["M2_scitt_hash_envelope"]["cose_sign1_hex"]), p1, pub, pairs)
    ok &= check("S M2 with P1: %s (expected accepted)" % (got,), got == ("accepted", None))
    seen = {"accepted"}
    for s in d["status_vectors"]:
        stmt = bytes.fromhex(s["statement_hex"])
        cand = bytes.fromhex(by_id[s["candidate"]]["receipt_hex"])
        ok &= check("%s statement bytes match their SHA-256" % s["id"],
                    hashlib.sha256(stmt).hexdigest() == s["statement_sha256"])
        ok &= check("%s candidate bytes are %s of the receipts draft" % (s["id"], s["candidate"]),
                    hashlib.sha256(cand).hexdigest() == s["candidate_receipt_sha256"])
        got = check_statement(stmt, cand, pub, pairs)
        ok &= check("%s status %s at step %s (expected %s at step %s)" % (s["id"], got[0], got[1],
                    s["expected_status"], s["step"]), got == (s["expected_status"], s["step"]))
        seen.add(got[0])
    every = {"accepted", "malformed", "outside_profile", "untrusted_key", "signature_invalid",
             "receipt_not_verified", "digest_mismatch", "subject_mismatch"}
    ok &= check("S every status of the checking procedure has a vector", seen == every)
    s1 = next(s for s in d["status_vectors"] if s["id"] == "S1")
    ok &= check("S S1 carries alg -8 and is accepted",
                cbor2.loads(cbor2.loads(bytes.fromhex(s1["statement_hex"])).value[0])[1] == -8
                and s1["expected_status"] == "accepted")
    print("all checks hold" if ok else "SOME CHECKS FAILED")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
