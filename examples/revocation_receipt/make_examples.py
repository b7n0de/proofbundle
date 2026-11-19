#!/usr/bin/env python3
"""Regenerate every receipt, key file and case of this example.

WARNING: the private keys below are TEST KEYS WITH NO VALUE. They are published on
purpose so anyone can rebuild the examples byte for byte. Never use them for anything
real. All parties, the authorization and the agent are invented.

Ed25519 signatures are deterministic, so running this script again gives the same bytes.
Run from this folder: python3 make_examples.py
"""
import base64
import hashlib
import json
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

# Test-only private key seeds (32 bytes each, hex). Worthless by design.
TEST_SEED_CUSTOMER = "0f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff0"
TEST_SEED_PROVIDER = "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
TEST_SEED_STRANGER = "5555555555555555555555555555555555555555555555555555555555555555"

PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
REVOCATION_TYPE = "https://signed-evidence.org/predicates/authority-revocation/v0.1"
ACK_TYPE = "https://signed-evidence.org/predicates/authority-revocation-ack/v0.1"

ACTION_TIME = "2026-11-25T10:15:00Z"
REVOKED_AT = "2026-11-25T09:30:00Z"
RECEIVED_AT = "2026-11-25T09:30:04Z"

# Invented authorization and agent. Only their fingerprints go into a receipt.
AUTHORITY = {
    "type": "agent-authorization",
    "authorizationId": "auth-example-0001",
    "scope": ["read-balances", "initiate-transfers-up-to-500-EUR"],
    "grantedAt": "2026-11-20T08:00:00Z",
    "agent": "agent-example-7",
}
OTHER_AUTHORITY = dict(AUTHORITY, authorizationId="auth-example-0002")
AGENT = {"agentId": "agent-example-7", "operator": "provider-example"}
OTHER_AGENT = {"agentId": "agent-example-8", "operator": "provider-example"}


def canonical(v):
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def h(b):
    return hashlib.sha256(b).hexdigest()


def key(seed_hex):
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))


def key_id(priv):
    raw = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "sha256:" + h(raw)


def pae(ptype, payload):
    t = ptype.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)


def statement(ptype, name, pred):
    return {"_type": STATEMENT_TYPE, "predicateType": ptype, "predicate": pred,
            "subject": [{"name": name, "digest": {"sha256": h(canonical(pred))}}]}


def envelope(payload, signer, ptype=PAYLOAD_TYPE):
    sig = signer.sign(pae(ptype, payload))
    return {"payload": base64.b64encode(payload).decode("ascii"), "payloadType": ptype,
            "signatures": [{"keyid": key_id(signer), "sig": base64.b64encode(sig).decode("ascii")}]}


C, P, S = key(TEST_SEED_CUSTOMER), key(TEST_SEED_PROVIDER), key(TEST_SEED_STRANGER)

# A degenerate public key: the identity point (01 then 31 zero bytes). Under it the signature 01 then 63 zero bytes
# verifies for every message, so anyone can "sign". The checker must refuse such a key.
IDENTITY_RAW = bytes([1]) + bytes(31)
FORGED_SIG = bytes([1]) + bytes(63)
IDENTITY_KEY_ID = "sha256:" + hashlib.sha256(IDENTITY_RAW).hexdigest()


def forged_envelope(payload):
    return {"payload": base64.b64encode(payload).decode("ascii"), "payloadType": PAYLOAD_TYPE,
            "signatures": [{"keyid": IDENTITY_KEY_ID, "sig": base64.b64encode(FORGED_SIG).decode("ascii")}]}
AUTH_FP, AGENT_FP = h(canonical(AUTHORITY)), h(canonical(AGENT))


def rev_pred(**over):
    pred = {
        "revocationId": "rev-example-0001",
        "revoker": {"role": "customer", "keyId": key_id(C)},
        "authority": {"digestAlgorithm": "jcs-sha256-v1", "digest": AUTH_FP},
        "agent": {"digestAlgorithm": "jcs-sha256-v1", "digest": AGENT_FP},
        "revokedAt": REVOKED_AT,
    }
    pred.update(over)
    return pred


def rev_payload(pred=None, ptype=REVOCATION_TYPE, stype=None):
    pred = pred or rev_pred()
    st = statement(ptype, "revocation:" + pred["revocationId"], pred)
    if stype:
        st["_type"] = stype
    return canonical(st)


def ack(rev_bytes, signer=P, received_at=RECEIVED_AT, role="provider", ptype=ACK_TYPE):
    pred = {
        "acknowledger": {"role": role, "keyId": key_id(signer)},
        "revocationDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": h(rev_bytes)},
        "receivedAt": received_at,
    }
    return envelope(canonical(statement(ptype, "revocation-ack:rev-example-0001", pred)), signer)


def write(path, obj):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "wb") as f:
        f.write(json.dumps(obj, indent=2, sort_keys=True).encode("utf-8") + b"\n")


def main():
    for name, k in (("customer", C), ("provider", P)):
        os.makedirs("keys", exist_ok=True)
        with open("keys/%s.pub.pem" % name, "wb") as f:
            f.write(k.public_key().public_bytes(serialization.Encoding.PEM,
                                                serialization.PublicFormat.SubjectPublicKeyInfo))

    good = rev_payload()
    write("revocation_customer_only.json", {"revocation": envelope(good, C)})
    write("revocation_countersigned.json", {"revocation": envelope(good, C), "countersignature": ack(good)})

    cases = []

    def case(name, bundle, verdict, first):
        write("cases/%s.json" % name, bundle)
        cases.append({"file": "cases/%s.json" % name, "verdict": verdict, "firstNonPass": first})

    # customer revocation must fail
    case("bad_customer_signature", {"revocation": envelope(good, S)}, "INVALID", "revocation.signature")
    env = envelope(good, C)
    env["payload"] = base64.b64encode(rev_payload(rev_pred(revokedAt="2026-11-25T08:00:00Z"))).decode("ascii")
    case("tampered_content", {"revocation": env}, "INVALID", "revocation.signature")
    st = json.loads(good)
    st["predicate"]["revokedAt"] = "2026-11-25T08:00:00Z"  # subject digest left stale
    case("stale_subject_digest", {"revocation": envelope(canonical(st), C)}, "INVALID", "revocation.statement")
    case("noncanonical_payload", {"revocation": envelope(json.dumps(json.loads(good)).encode(), C)},
         "INVALID", "revocation.canonical")
    case("wrong_payload_type", {"revocation": envelope(good, C, "application/json")},
         "INVALID", "revocation.envelope")
    case("wrong_statement_type", {"revocation": envelope(rev_payload(stype="https://example.invalid/Statement"), C)},
         "INVALID", "revocation.statement")
    case("wrong_predicate_type", {"revocation": envelope(rev_payload(ptype=ACK_TYPE), C)},
         "INVALID", "revocation.statement")
    case("revoker_not_customer",
         {"revocation": envelope(rev_payload(rev_pred(revoker={"role": "provider", "keyId": key_id(C)})), C)},
         "INVALID", "revocation.revoker_role")
    case("revoker_key_mismatch",
         {"revocation": envelope(rev_payload(rev_pred(revoker={"role": "customer", "keyId": key_id(S)})), C)},
         "INVALID", "revocation.revoker_key")
    case("revoked_after_action", {"revocation": envelope(rev_payload(rev_pred(revokedAt="2026-11-25T10:20:00Z")), C)},
         "INVALID", "revocation.covers_action")
    case("wrong_authority", {"revocation": envelope(rev_payload(rev_pred(
        authority={"digestAlgorithm": "jcs-sha256-v1", "digest": h(canonical(OTHER_AUTHORITY))})), C)},
         "INVALID", "revocation.authority_match")
    case("wrong_agent", {"revocation": envelope(rev_payload(rev_pred(
        agent={"digestAlgorithm": "jcs-sha256-v1", "digest": h(canonical(OTHER_AGENT))})), C)},
         "INVALID", "revocation.agent_match")

    # provider confirmation must not succeed
    case("countersignature_missing", {"revocation": envelope(good, C)}, "VALID_CUSTOMER_ONLY", "countersignature")
    case("countersignature_foreign_key", {"revocation": envelope(good, C), "countersignature": ack(good, signer=S)},
         "INVALID", "countersignature.signature")
    other = rev_payload(rev_pred(revocationId="rev-example-0002"))
    case("countersignature_other_revocation", {"revocation": envelope(good, C), "countersignature": ack(other)},
         "INVALID", "countersignature.binds_revocation")
    case("countersignature_before_revocation",
         {"revocation": envelope(good, C), "countersignature": ack(good, received_at="2026-11-25T09:29:59Z")},
         "INVALID", "countersignature.time_order")
    case("countersignature_wrong_role",
         {"revocation": envelope(good, C), "countersignature": ack(good, role="customer")},
         "INVALID", "countersignature.acknowledger")
    case("countersignature_wrong_type",
         {"revocation": envelope(good, C), "countersignature": ack(good, ptype=REVOCATION_TYPE)},
         "INVALID", "countersignature.statement")

    # times must use ASCII digits: a year in Arabic-Indic digits (2025) in a receipt time is refused
    case("unicode_year_in_receipt",
         {"revocation": envelope(good, C),
          "countersignature": ack(good, received_at="\u0662\u0660\u0662\u0665-11-25T09:30:04Z")},
         "INVALID", "countersignature.time_order")
    # ... and in the action time given to the checker it is a usage error (exit 2 on the command line)
    cases.append({"file": "revocation_countersigned.json", "actionTime": "\u0662\u0660\u0662\u0666-11-25T10:15:00Z",
                  "verdict": "USAGE_ERROR", "firstNonPass": "arguments"})
    # a fingerprint argument must be exactly 64 lowercase hex characters: a trailing line break is a usage error
    cases.append({"file": "revocation_countersigned.json", "authorityDigest": AUTH_FP + chr(10),
                  "verdict": "USAGE_ERROR", "firstNonPass": "arguments"})
    cases.append({"file": "revocation_countersigned.json", "agentDigest": AGENT_FP + chr(10),
                  "verdict": "USAGE_ERROR", "firstNonPass": "arguments"})

    # a supplied key must be an Ed25519 point of prime order: with the identity point as customer key or as provider
    # key, a signature made without any private key would verify, so both are usage errors (exit 2)
    os.makedirs("cases", exist_ok=True)
    with open("cases/identity_key.pub.pem", "wb") as f:
        f.write(Ed25519PublicKey.from_public_bytes(IDENTITY_RAW).public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    forged_rev = rev_payload(rev_pred(revoker={"role": "customer", "keyId": IDENTITY_KEY_ID}))
    write("cases/forged_revocation_identity_key.json", {"revocation": forged_envelope(forged_rev)})
    cases.append({"file": "cases/forged_revocation_identity_key.json", "customerKey": "cases/identity_key.pub.pem",
                  "verdict": "USAGE_ERROR", "firstNonPass": "arguments"})
    forged_ack = canonical(statement(ACK_TYPE, "revocation-ack:rev-example-0001", {
        "acknowledger": {"role": "provider", "keyId": IDENTITY_KEY_ID},
        "revocationDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": h(good)},
        "receivedAt": RECEIVED_AT,
    }))
    write("cases/forged_countersignature_identity_key.json",
          {"revocation": envelope(good, C), "countersignature": forged_envelope(forged_ack)})
    cases.append({"file": "cases/forged_countersignature_identity_key.json", "providerKey": "cases/identity_key.pub.pem",
                  "verdict": "USAGE_ERROR", "firstNonPass": "arguments"})

    expected = {
        "inputs": {"customerKey": "keys/customer.pub.pem", "providerKey": "keys/provider.pub.pem",
                   "authorityDigest": AUTH_FP, "agentDigest": AGENT_FP, "actionTime": ACTION_TIME},
        "cases": [
            {"file": "revocation_countersigned.json", "verdict": "VALID_PROVIDER_CONFIRMED", "firstNonPass": None},
            {"file": "revocation_customer_only.json", "verdict": "VALID_CUSTOMER_ONLY",
             "firstNonPass": "countersignature"},
        ] + cases,
    }
    write("cases/expected.json", expected)
    print("authority fingerprint", AUTH_FP)
    print("agent fingerprint    ", AGENT_FP)
    print("cases", len(expected["cases"]))


if __name__ == "__main__":
    main()
