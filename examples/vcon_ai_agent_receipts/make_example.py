"""Producer side of the example: a sample Claude Code transcript in, a signed vCon with decision receipts out.

    python make_example.py --out out

1. claude_jsonl_to_vcon.py turns sample_session.jsonl into a vCon with the ai_agent extension.
2. A gate party and three attachments are added: the approval record of the "Approved." message,
   an ALLOW decision receipt (Case 1) inline and a DENY decision receipt (Case 2) referenced by url and
   content_hash. Both receipts name the session by agent_session_id and the tool call by its call_id in
   traceContext.
3. The vCon is signed three times over the same payload bytes, its RFC 8785 serialization: in the signed
   form of vCon core (JWS) with EdDSA and, as a second file, with RS256, and in the COSE_Sign1
   signed-agent-record of Appendix B of the ai_agent draft, with trace-metadata.
4. A third receipt, dec-0003, cites the signed conversation record by digest.

Test keys only. Each Ed25519 seed is SHA-256 over a public ASCII label, and the RSA test key is derived
from its label by vcon_profile.rsa_from_label, so every byte can be rebuilt; the gate key is the gate-1
test key of draft-gruszka-audit-decision-receipts. Ed25519 and RSASSA-PKCS1-v1_5 are deterministic, so
every output file is the same on every run. Needs proofbundle 6.4.0 or later.
"""
from __future__ import annotations

import argparse
import base64
import copy
import datetime
import hashlib
import json
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import NameOID
from proofbundle import decision

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import claude_jsonl_to_vcon as conv  # noqa: E402
import vcon_profile as vp  # noqa: E402

LABEL_GATE = "draft-gruszka-audit-decision-receipts test key gate-1"
LABEL_RECORDER = "vcon ai_agent decision receipt example test key vcon-recorder-1"
LABEL_RECORDER_RSA = "vcon ai_agent decision receipt example test key vcon-recorder-rs256-1"
DENY_URL = "https://receipts.example/acme/widgets/dec-0002.dsse.json"
RECORDS = "https://records.example/acme/widgets/"
ISSUER = "https://records.example/acme/widgets/recorder"
APPROVAL_ENTRY = "00000000-0000-4000-8000-000000000003"
PEOPLE = {"user_id": "user-123", "user_name": "Alice", "agent_id": "agent-42", "agent_name": "Coding Agent",
          "model_provider": "example-provider"}
POLICY_BYTES = b"example gate rules, revision 1\n"


def key(label):
    sk = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode("ascii")).digest())
    return sk, sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


GATE_SK, GATE_PK = key(LABEL_GATE)
REC_SK, REC_PK = key(LABEL_RECORDER)
_NAME = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vcon-recorder-1 TEST KEY ONLY"),
                   x509.NameAttribute(NameOID.ORGANIZATION_NAME, "example")])
CERT_DER = (x509.CertificateBuilder().subject_name(_NAME).issuer_name(_NAME).public_key(REC_SK.public_key())
            .serial_number(1)
            .not_valid_before(datetime.datetime(2026, 10, 1, tzinfo=datetime.timezone.utc))
            .not_valid_after(datetime.datetime(2027, 10, 1, tzinfo=datetime.timezone.utc))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(REC_SK, None).public_bytes(Encoding.DER))
REC_RSA = vp.rsa_from_label(LABEL_RECORDER_RSA)
_NAME_RSA = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vcon-recorder-rs256-1 TEST KEY ONLY"),
                       x509.NameAttribute(NameOID.ORGANIZATION_NAME, "example")])
CERT_RSA_DER = (x509.CertificateBuilder().subject_name(_NAME_RSA).issuer_name(_NAME_RSA)
                .public_key(REC_RSA.public_key()).serial_number(2)
                .not_valid_before(datetime.datetime(2026, 10, 1, tzinfo=datetime.timezone.utc))
                .not_valid_after(datetime.datetime(2027, 10, 1, tzinfo=datetime.timezone.utc))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .sign(REC_RSA, hashes.SHA256()).public_bytes(Encoding.DER))

COMMON = {
    "schemaVersion": "0.1.0", "decisionType": "preActionAuthorization", "decisionMaker": {"id": "gate-1"},
    "agent": {"id": PEOPLE["agent_id"]}, "principal": {"id": PEOPLE["user_id"]},
    "notChecked": [{"field": "content", "reason": "the gate does not judge whether the text is true",
                    "impact": "an approved text can be wrong"}],
    "decisionChangeConditions": [{"conditionType": "ruleChange",
                                  "description": "a changed gate, mode or rule of the gate"}],
    "privacy": {"rawInputsIncluded": False},
}
PUSH = {"name": "https://git.example/acme/widgets refs/heads/topic", "uri": "https://git.example/acme/widgets"}
PR7 = {"name": "https://git.example/acme/widgets/pull/7", "uri": "https://git.example/acme/widgets/pull/7"}


def boundary(path):
    return {"policyEngine": "proofbundle-pilot/github-write", "policyId": "outbound-gate-rules",
            "decisionPath": path, "policyDigest": {"sha256": vp.sha256(POLICY_BYTES)}, "bundleRevision": "1"}


def emit(pred):
    errs = decision.validate_decision_predicate(pred, strict=True)
    assert not errs, errs
    env = decision.emit_decision_receipt(pred, GATE_SK)
    return env


def envelope_bytes(env):
    return (json.dumps(env, indent=2) + "\n").encode("ascii")


def content_hash(b, algs=("sha512", "sha256")):
    return [a + "-" + vp.b64u(hashlib.new(a, b).digest()) for a in algs]


def converted():
    lines = (HERE / "sample_session.jsonl").read_text(encoding="utf-8").splitlines()
    return conv.convert(lines, **PEOPLE)


def call(v, call_id):
    return next(e for e in v["events"] if e["type"] == "tool-call" and e.get("call_id") == call_id)


def allow(v, sid, did, decided, expires, call_id, approval_bytes):
    a = vp.jcs(call(v, call_id)["input"])
    p = dict(COMMON)
    p.update({
        "decisionId": did, "decidedAt": decided,
        "proposedAction": {"actionType": "git.push", "method": "write", "target": dict(PUSH),
                           "parametersDigest": {"sha256": vp.sha256(a)}},
        "inputSnapshot": [
            {"name": "approved bytes", "digest": {"sha256": vp.sha256(a)}, "mediaType": "application/json"},
            {"name": "approval record", "digest": {"sha256": vp.sha256(approval_bytes)},
             "mediaType": "application/json"}],
        "policyBoundary": boundary("outbound-gate/allow-write"), "evidenceRefs": [],
        "decision": {"verdict": "ALLOW", "reasonCodes": ["user_approval"]},
        "traceContext": {"traceId": sid, "parentId": call_id},
        "validity": {"audience": ["observer-1"], "nonce": did, "expiresAt": expires}})
    return emit(p)


def base():
    """The example without changes: every file of out/ as bytes, and the parts the cases reuse."""
    v, report = converted()
    sid = v["sessions"][0]["agent_session_id"]
    answer = next(i for i, d in enumerate(v["dialog"]) if d.get("entry_id") == APPROVAL_ENTRY)
    approval = {"approvalId": APPROVAL_ENTRY, "approver": PEOPLE["user_id"], "session": sid,
                "actionDigest": {"sha256": vp.sha256(vp.jcs(call(v, "toolu_example_01")["input"]))},
                "approvedAt": "2026-10-15T09:00:04Z", "validUntil": "2026-10-15T09:15:04Z"}
    ap = vp.jcs(approval)
    env1 = allow(v, sid, "dec-0001", "2026-10-15T09:00:06Z", "2026-10-15T09:05:06Z", "toolu_example_01", ap)
    a2 = vp.jcs(call(v, "toolu_example_02")["input"])
    p2 = dict(COMMON)
    p2.update({
        "decisionId": "dec-0002", "decidedAt": "2026-10-15T09:05:01Z",
        "proposedAction": {"actionType": "github.merge", "method": "write", "target": dict(PR7),
                           "parametersDigest": {"sha256": vp.sha256(a2)}},
        "inputSnapshot": [{"name": "proposed bytes", "digest": {"sha256": vp.sha256(a2)},
                           "mediaType": "application/json"}],
        "policyBoundary": boundary("outbound-gate/deny-write"), "evidenceRefs": [],
        "decision": {"verdict": "DENY", "reasonCodes": ["required_check_failed"]},
        "actionOutcome": {"status": "blocked", "performedAt": None, "outcomeRef": None},
        "traceContext": {"traceId": sid, "parentId": "toolu_example_02"},
        "validity": {"audience": ["observer-1"], "nonce": "dec-0002", "expiresAt": "2026-10-15T09:10:01Z"}})
    env2 = envelope_bytes(emit(p2))
    full = copy.deepcopy(v)
    full["parties"].append({"name": "gate-1", "type": "bot", "uuid": "gate-1"})
    full["attachments"] = [
        {"purpose": "approval record", "start": "2026-10-15T09:00:04Z", "party": 2, "dialog": answer, "session": 0,
         "mediatype": "application/json", "filename": "approval-record.json", "encoding": "json",
         "body": approval},
        {"purpose": "decision receipt", "start": "2026-10-15T09:00:06Z", "party": 2, "session": 0,
         "mediatype": "application/json", "filename": "dec-0001.dsse.json", "encoding": "json", "body": env1},
        {"purpose": "decision receipt", "start": "2026-10-15T09:05:01Z", "party": 2, "session": 0,
         "mediatype": "application/json", "filename": "dec-0002.dsse.json", "url": DENY_URL,
         "content_hash": content_hash(env2)}]
    return {"converted": v, "report": report, "full": full, "approval": ap, "env1": env1, "env2": env2,
            "ap_obj": approval}


def sign(v):
    """The payload bytes, the JWS signed form and the COSE_Sign1 signed-agent-record of one vCon."""
    payload = vp.jcs(v)
    jws = vp.pretty(vp.jws_sign(payload, REC_SK, {"x5c": [base64.b64encode(CERT_DER).decode("ascii")],
                                                  "uuid": v["uuid"]}))
    s = v["sessions"][0]
    start = vp.when(s["start"])
    meta = {"session-id": s["agent_session_id"], "agent-vendor": v["parties"][1]["agent_meta"]["model_provider"],
            "trace-format": "ietf-vac-v3.0", "timestamp-start": vp.iso(start),
            "timestamp-end": vp.iso(start + datetime.timedelta(seconds=s["duration"])),
            "content-hash": vp.sha256(payload), "content-hash-alg": "sha-256"}
    cose = vp.cose_sign1(payload, REC_SK,
                         {vp.COSE_ALG: -8, vp.COSE_CTY: vp.VCON_MEDIA,
                          vp.COSE_CWT: {1: ISSUER, 2: "urn:uuid:" + v["uuid"]}, vp.COSE_X5CHAIN: CERT_DER},
                         {vp.TRACE_METADATA: meta})
    return payload, jws, cose


def sign_rs256(v):
    """The same payload bytes in a second JWS signed form, alg RS256 as vCon core 6.2.2 recommends."""
    return vp.pretty(vp.jws_sign_rs256(vp.jcs(v), REC_RSA, {"x5c": [base64.b64encode(CERT_RSA_DER).decode("ascii")],
                                                             "uuid": v["uuid"]}))


def citing(v, payload, cose):
    """dec-0003: the gate declines a second push with the same approval in a later session and cites the signed
    conversation record twice, by the digest of its payload and by the digest of the COSE_Sign1 bytes."""
    d, uri = vp.sha256(payload), RECORDS + v["uuid"]
    a1 = vp.jcs(call(v, "toolu_example_01")["input"])
    p = dict(COMMON)
    p.update({
        "decisionId": "dec-0003", "decidedAt": "2026-10-15T09:20:00Z",
        "proposedAction": {"actionType": "git.push", "method": "write", "target": dict(PUSH),
                           "parametersDigest": {"sha256": vp.sha256(a1)}},
        "inputSnapshot": [
            {"name": "proposed bytes", "digest": {"sha256": vp.sha256(a1)}, "mediaType": "application/json"},
            {"name": "conversation record", "uri": uri + ".vcon", "digest": {"sha256": d},
             "mediaType": vp.VCON_MEDIA}],
        "policyBoundary": boundary("outbound-gate/deny-write"),
        "evidenceRefs": [
            {"relation": "conversationRecord", "digest": {"sha256": d}, "uri": uri + ".vcon",
             "typedDigest": {"type": "vcon", "digestAlgorithm": "jcs-sha256-v1", "digest": d,
                             "purpose": "the approval was already used by dec-0001"}},
            {"relation": "signedConversationRecord", "digest": {"sha256": vp.sha256(cose)}, "uri": uri + ".cose"}],
        "decision": {"verdict": "DENY", "reasonCodes": ["approval_already_used"]},
        "actionOutcome": {"status": "blocked", "performedAt": None, "outcomeRef": None},
        "traceContext": {"traceId": "5e551011-0000-4000-8000-000000000002", "parentId": "toolu_example_05"},
        "validity": {"audience": ["observer-1"], "nonce": "dec-0003", "expiresAt": "2026-10-15T09:25:00Z"}})
    return envelope_bytes(emit(p))


def files():
    b = base()
    payload, jws, cose = sign(b["full"])
    return {
        "conversion-report.json": vp.pretty(b["report"]),
        "vcon.converted.json": vp.pretty(b["converted"]),
        "approval-record.json": b["approval"],
        "receipts/dec-0001.dsse.json": envelope_bytes(b["env1"]),
        "external/dec-0002.dsse.json": b["env2"],
        "receipts/dec-0003.dsse.json": citing(b["full"], payload, cose),
        "vcon.unsigned.json": vp.pretty(b["full"]),
        "vcon.payload.json": payload,
        "vcon.signed.json": jws,
        "vcon.signed-rs256.json": sign_rs256(b["full"]),
        "vcon.cose": cose,
        "recorder-test-cert.der": CERT_DER,
        "recorder-rs256-test-cert.der": CERT_RSA_DER,
        "test-keys.json": vp.pretty({
            "note": "TEST KEYS ONLY. Each seed is SHA-256 over the label; never use them for real records.",
            "gate-1": {"label": LABEL_GATE, "public_b64": base64.b64encode(GATE_PK).decode()},
            "vcon-recorder-1": {"label": LABEL_RECORDER, "public_b64": base64.b64encode(REC_PK).decode(),
                                "certificate_der_sha256": vp.sha256(CERT_DER)},
            "vcon-recorder-rs256-1": {"label": LABEL_RECORDER_RSA, "derivation": "vcon_profile.rsa_from_label",
                                      "certificate_der_sha256": vp.sha256(CERT_RSA_DER)}}),
    }


def write(out: Path, fs: dict):
    for rel, data in fs.items():
        p = out / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)


def main():
    ap = argparse.ArgumentParser(description="Write the example files.")
    ap.add_argument("--out", default=str(HERE / "out"))
    a = ap.parse_args()
    write(Path(a.out), files())
    print("wrote", a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
