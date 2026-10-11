#!/usr/bin/env python3
"""Examples for draft-gruszka-evaluation-receipt-mappings-01.

Input: the positive vector P1 of draft-gruszka-signed-evaluation-receipts-00 (its exact receipt bytes,
read from that draft's vectors.json). Output, all bytes deterministic:

  * the receipt digest: SHA-256 over B, the receipt's payload bytes;
  * M1, a DSSE envelope that carries B and the receipt's own signature unchanged: the signature is a
    valid DSSE signature without re-signing, because both sign PAE(type, B);
  * M2, a SCITT Signed Statement as a COSE Hash Envelope whose payload is the receipt digest and which
    names the receipt only by that digest (header 258 SHA-256, header 259 the receipt type);
  * C1 to C8, citation matching cases: a citation (algorithm, digest) against a candidate receipt
    from the receipts draft's vectors, with the expected match result (MATCH, NO_MATCH or
    INDETERMINATE) and, separately, the candidate's verification verdict under that draft;
  * S1 to S8, status vectors: Signed Statements, each presented with a candidate receipt of the receipts
    draft, one for every status of the checking procedure besides accepted (M2 with P1), and S1, a
    statement with alg -8 that every Receiver accepts. The foreign key that signs S4 and S5 is a pure test
    key whose seed is SHA-256 over FOREIGN_SEED_LABEL.

The test key is the pure test key of the receipts draft; it MUST NOT be used for anything real.
"""
import base64
import hashlib
import json
import os
import sys

import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = os.path.dirname(os.path.abspath(__file__))
RECEIPT_VECTORS = os.path.join(HERE, "..", "..", "ser", "examples", "vectors.json")
sys.path.insert(0, os.path.join(HERE, "..", "..", "ser", "examples"))
import check_receipts  # noqa: E402  the receipts draft's own checker, used for the verdict column only

#: (case, candidate vector of the receipts draft, citation algorithm, what the case shows)
CASES = [
    ("C1", "P1", "sha-256", "the receipt the citation was made from"),
    ("C2", "P4", "sha-256", "other receipt bytes (an escaped character in schema), same B"),
    ("C3", "P6", "sha-256", "other receipt bytes (no key hint), same B"),
    ("C4", "P2", "sha-256", "another receipt with another B"),
    ("C5", "N7", "sha-256", "same B, signature made over another type: a match is not a verification"),
    ("C6", "N13", "sha-256", "payload_b64 is not canonical base64: B is not obtained"),
    ("C7", "N14", "sha-256", "the receipt has duplicate member names: B is not obtained"),
    ("C8", "P1", "sha-512", "the citation names an algorithm this document does not define"),
]

TYPE = "application/vnd.signed-evidence.eval-receipt+json"
# COSE (RFC 9052), CWT claims in the header (RFC 9597), Hash Envelope (RFC 9995), alg (RFC 9864)
H_ALG, H_KID, H_CWT = 1, 4, 15
H_PAYLOAD_HASH_ALG, H_PREIMAGE_CT = 258, 259
CWT_ISS, CWT_SUB = 1, 2
ALG_ED25519, ALG_SHA256 = -19, -16
TAG_COSE_SIGN1 = 18
ISS = "https://issuer.example/eval"
FOREIGN_SEED_LABEL = "receipt-cose foreign statement key, PURE TEST KEY"

#: (vector, candidate receipt, expected status, first failing step or None, what it shows)
STATUS = [
    ("S1", "P1", "accepted", None, "M2 with alg -8 in place of -19, signed again under the issuer test key"),
    ("S2", "P1", "malformed", 1, "the bytes of M2 with CBOR tag 98 (COSE_Sign) in place of tag 18"),
    ("S3", "P1", "outside_profile", 2, "alg -7 (ES256), signed again under the issuer test key"),
    ("S4", "P1", "untrusted_key", 3, "kid names the foreign test key, which signs it; no configured pair has that key"),
    ("S5", "P1", "signature_invalid", 4, "kid names the issuer test key, the foreign test key signs it"),
    ("S6", "N7", "receipt_not_verified", 5, "M2, presented with N7, which fails step 11 of the receipts draft"),
    ("S7", "P1", "digest_mismatch", 6, "a statement on B of P2, with sub its model commitment, presented with P1"),
    ("S8", "P1", "subject_mismatch", 7, "M2 with sub the dataset commitment of P1, signed again"),
]


def jcs(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def pae(typ: str, body: bytes) -> bytes:
    t = typ.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(body), body)


def kid_thumbprint(pub: bytes) -> bytes:
    """COSE Key Thumbprint (RFC 9679), SHA-256, of the OKP Ed25519 key {1: 1, -1: 6, -2: x}."""
    return hashlib.sha256(cbor2.dumps({1: 1, -1: 6, -2: pub}, canonical=True)).digest()


def main():
    rv = json.load(open(RECEIPT_VECTORS, encoding="utf-8"))
    p1 = next(v for v in rv["vectors"] if v["id"] == "P1")
    receipt_bytes = bytes.fromhex(p1["receipt_hex"])
    receipt = json.loads(receipt_bytes)
    B = base64.b64decode(receipt["payload_b64"])
    sig = base64.b64decode(receipt["signature"]["sig"])
    payload = json.loads(B)
    seed = bytes.fromhex(rv["test_keys"]["issuer"]["ed25519_seed_hex"])
    key = Ed25519PrivateKey.from_private_bytes(seed)
    pub = key.public_key().public_bytes_raw()
    digest = hashlib.sha256(B).digest()

    # M1: the DSSE envelope. keyid is optional and unauthenticated in DSSE; it is left out.
    dsse = {"payloadType": TYPE, "payload": base64.b64encode(B).decode("ascii"),
            "signatures": [{"sig": base64.b64encode(sig).decode("ascii")}]}
    dsse_bytes = jcs(dsse)

    # M2: the SCITT Signed Statement (COSE Hash Envelope). sub is the model commitment of the receipt.
    protected = {H_ALG: ALG_ED25519, H_KID: kid_thumbprint(pub),
                 H_CWT: {CWT_ISS: ISS, CWT_SUB: payload["model_id_commit"]},
                 H_PAYLOAD_HASH_ALG: ALG_SHA256, H_PREIMAGE_CT: TYPE}
    protected_bstr = cbor2.dumps(protected, canonical=True)
    to_be_signed = cbor2.dumps(["Signature1", protected_bstr, b"", digest], canonical=True)
    cose_sig = key.sign(to_be_signed)
    statement = cbor2.dumps(cbor2.CBORTag(TAG_COSE_SIGN1, [protected_bstr, {}, digest, cose_sig]),
                            canonical=True)

    doc = {
        "draft": "draft-gruszka-evaluation-receipt-mappings-01",
        "source": {"draft": rv["draft"], "vector": "P1", "receipt_sha256_of_bytes": p1["receipt_sha256"]},
        "issuer_public_key_b64": base64.b64encode(pub).decode("ascii"),
        "receipt_hex": receipt_bytes.hex(),
        "payload_B_hex": B.hex(),
        "receipt_digest": {"alg": "sha-256", "over": "B (the receipt's payload bytes)",
                           "hex": digest.hex(), "sha256_prefixed": "sha256:" + digest.hex()},
        "pae_hex": pae(TYPE, B).hex(),
        "M1_dsse": {"envelope_hex": dsse_bytes.hex(), "envelope_sha256": hashlib.sha256(dsse_bytes).hexdigest(),
                    "payloadType": TYPE, "signature_equals_receipt_signature": True},
        "M2_scitt_hash_envelope": {
            "cose_sign1_hex": statement.hex(), "cose_sign1_sha256": hashlib.sha256(statement).hexdigest(),
            "protected_hex": protected_bstr.hex(), "to_be_signed_hex": to_be_signed.hex(),
            "to_be_signed_sha256": hashlib.sha256(to_be_signed).hexdigest(),
            "kid_hex": kid_thumbprint(pub).hex(), "iss": ISS, "sub": payload["model_id_commit"],
            "payload_is_receipt_digest": True},
        "test_material_notice": "PURE TEST KEY. It MUST NOT be used for anything real.",
    }
    # Citation matching: steps 1 to 3 of the receipts draft give B; only SHA-256 is defined.
    cases = []
    by_id = {v["id"]: v for v in rv["vectors"]}
    for cid, vid, alg, shows in CASES:
        cand = bytes.fromhex(by_id[vid]["receipt_hex"])
        verdict, step, _ = check_receipts.verify(cand, base64.b64decode(by_id[vid]["verification_key_b64"]))
        cited = hashlib.sha256(B).hexdigest() if alg == "sha-256" else hashlib.sha512(B).hexdigest()
        first = int(str(step).split()[0]) if verdict == "FAIL" else None
        if alg != "sha-256":
            match, why = "INDETERMINATE", "citation algorithm not defined"
        elif first is not None and first <= 3:
            match, why = "INDETERMINATE", "B not obtained, step %d of the receipts draft fails" % first
        else:
            cb = base64.b64decode(json.loads(cand)["payload_b64"])
            match = "MATCH" if hashlib.sha256(cb).hexdigest() == cited else "NO_MATCH"
            why = "SHA-256 over the candidate's B " + ("equals" if match == "MATCH" else "differs from") + \
                " the cited digest"
        cases.append({"id": cid, "candidate": vid, "shows": shows,
                      "citation": {"alg": alg, "hex": cited},
                      "candidate_receipt_sha256": by_id[vid]["receipt_sha256"],
                      "candidate_payload_sha256": by_id[vid]["payload_sha256"],
                      "expected_match": match, "reason": why,
                      "candidate_verdict": verdict, "candidate_step": step})
    doc["citation_cases"] = cases

    # Status vectors: one per status of the checking procedure; M2 with P1 is the accepted one.
    foreign = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(FOREIGN_SEED_LABEL.encode("utf-8")).digest())
    foreign_pub = foreign.public_key().public_bytes_raw()

    def prot(**change):
        p = dict(protected)
        for name, value in change.items():
            p[{"alg": H_ALG, "kid": H_KID, "cwt": H_CWT}[name]] = value
        return p

    def sign1(prot_map, signer=key, payload_digest=digest):
        raw = cbor2.dumps(prot_map, canonical=True)
        tbs = cbor2.dumps(["Signature1", raw, b"", payload_digest], canonical=True)
        return cbor2.dumps(cbor2.CBORTag(TAG_COSE_SIGN1, [raw, {}, payload_digest, signer.sign(tbs)]),
                           canonical=True)

    p2 = by_id["P2"]
    p2_b = base64.b64decode(json.loads(bytes.fromhex(p2["receipt_hex"]))["payload_b64"])
    made = {
        "S1": sign1(prot(alg=-8)),
        "S2": bytes([0xD8, 98]) + statement[1:],
        "S3": sign1(prot(alg=-7)),
        "S4": sign1(prot(kid=kid_thumbprint(foreign_pub)), signer=foreign),
        "S5": sign1(prot(), signer=foreign),
        "S6": statement,
        "S7": sign1(prot(cwt={CWT_ISS: ISS, CWT_SUB: json.loads(p2_b)["model_id_commit"]}),
                    payload_digest=hashlib.sha256(p2_b).digest()),
        "S8": sign1(prot(cwt={CWT_ISS: ISS, CWT_SUB: payload["dataset_id_commit"]})),
    }
    assert statement[0] == 0xD2 and made["S6"] == statement
    doc["foreign_public_key_b64"] = base64.b64encode(foreign_pub).decode("ascii")
    doc["foreign_seed"] = "SHA-256 over the UTF-8 bytes of " + repr(FOREIGN_SEED_LABEL)
    doc["receiver_pairs"] = [[ISS, "issuer test key"]]
    doc["status_vectors"] = [
        {"id": sid, "candidate": vid, "candidate_receipt_sha256": by_id[vid]["receipt_sha256"],
         "statement_hex": made[sid].hex(), "statement_sha256": hashlib.sha256(made[sid]).hexdigest(),
         "expected_status": status, "step": step, "shows": shows}
        for sid, vid, status, step, shows in STATUS]

    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "mappings.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    print("wrote", out, file=sys.stderr)


if __name__ == "__main__":
    main()
