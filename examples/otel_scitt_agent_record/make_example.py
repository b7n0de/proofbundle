"""Producer side of the example: two OpenTelemetry spans and an approval in, a signed record anchored in SCITT out.

    python make_example.py [--out out]

1. The agent's domain holds two spans in the OTLP JSON form, named and attributed after the GenAI semantic
   conventions at the pinned commit (CONVENTIONS below): the agent run (``invoke_agent``, internal) and its tool
   call (``execute_tool``), with the opt-in arguments and result. A person approved the call; the conventions
   define no span or attribute for that, so the approval is a proofbundle decision receipt signed by the gate,
   linked to the call by ``gen_ai.tool.call.id``.
2. The record is an in-toto Statement signed in DSSE by the recorder. It carries no trace id, span id,
   conversation id, tool call id, agent name, argument or result in clear. For each of run, approval and action it
   carries a salted fingerprint (``evalclaim.salted_commit``, sha256-salted-v1, 32-byte salts) over a fixed
   selection of the span's fields as RFC 8785 JSON; the tool call id and the trace id appear only as salted
   references, the same value in both places that name them. It also carries the SHA-256 of the rule, the order
   and the conclusion the recorder draws.
3. The record is anchored: a signed SCITT statement (a hash envelope over the SHA-256 of the record's payload
   bytes) is registered with the local test service in scitt_local.py, which returns a receipt. Statement and
   receipt together are the Transparent Statement.
4. Everything a disclosure in a dispute would hand over is written under out/disclosure/: the spans, the salts,
   the approval receipt and the rule. In a real deployment it stays with the issuer.

Test keys only. Each key is derived from a public label, and the salts are derived from public labels too, so
every byte can be rebuilt and every output file is the same on every run; never use any of them for real records.
Needs proofbundle 6.6.1 or later with the [scitt] extra.
"""
from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import json
import sys
from pathlib import Path

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from proofbundle import decision, dsse
from proofbundle.evalclaim import COMMIT_ALG, salted_commit

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import scitt_local as sl  # noqa: E402

CONVENTIONS = {"source": "https://github.com/open-telemetry/semantic-conventions-genai",
               "commit": "e6658f14c9d9ea0760825f029cb82e7673f48fab", "status": "Development"}
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
INTOTO = "application/vnd.in-toto+json"
#: The predicate type of this example's record. Our own, for this example; not registered anywhere.
PREDICATE_TYPE = "https://b7n0de.com/proofbundle/examples/otel-agent-record/v0.1"
PROFILE = "otel-genai-scitt-example/v0.1"
APPROVAL_NOTE = ("not standardized: the GenAI semantic conventions at the pinned commit define no span and no "
                 "attribute for a human approval; it is a proofbundle decision receipt linked by gen_ai.tool.call.id")

LABEL_RECORDER = "otel scitt agent record example test key recorder-1"
LABEL_GATE = "otel scitt agent record example test key approval-gate-1"
LABEL_STATEMENT = "otel scitt agent record example test key statement-signer-1"
LABEL_STATEMENT_ISSUER = "otel scitt agent record example test key certificate-issuer-1"
LABEL_SERVICE = "otel scitt agent record example test key scitt-service-1"
SALT_LABEL = "otel scitt agent record example test salt "
SALT_NAMES = ("run", "approval", "action", "call", "trace")
STATEMENT_ISS = "https://records.example/recorder-1"
STATEMENT_SUB = "otel-agent-record"
SERVICE_ISSUER = "scitt.example"
RECEIPT_IAT = 1795169000            # 2026-11-20T10:03:20Z
AUDIENCE = "record-reader-1"

#: The fixed selection of span attributes each fingerprint covers (keys of the pinned conventions).
RUN_ATTRIBUTES = ("gen_ai.operation.name", "gen_ai.agent.name", "gen_ai.conversation.id")
ACTION_ATTRIBUTES = ("gen_ai.operation.name", "gen_ai.tool.name", "gen_ai.tool.call.id", "gen_ai.tool.type",
                     "gen_ai.agent.name", "gen_ai.conversation.id", "gen_ai.tool.call.arguments",
                     "gen_ai.tool.call.result")

RULE = {"rule": "a transfer of more than the threshold needs the approval of a person before it runs",
        "tool": "transfer_funds", "threshold": "100.00", "currency": "EUR", "revision": 1}


def ed_key(label):
    sk = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode("ascii")).digest())
    return sk, sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


RECORDER_SK, RECORDER_PK = ed_key(LABEL_RECORDER)
GATE_SK, GATE_PK = ed_key(LABEL_GATE)
STATEMENT_KEY = sl.ec_key(LABEL_STATEMENT)
SERVICE_KEY = sl.ec_key(LABEL_SERVICE)
STATEMENT_CERT = sl.test_certificate(STATEMENT_KEY, "statement-signer-1", LABEL_STATEMENT_ISSUER)


def jcs(v) -> bytes:
    return rfc8785.dumps(v)


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def pretty(v) -> bytes:
    return (json.dumps(v, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def nanos(iso: str) -> str:
    t = datetime.datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    return str(int(t.timestamp()) * 1_000_000_000)


def salts() -> dict:
    """32 bytes each, derived from public labels so the example is reproducible. A real issuer draws them at
    random and keeps them; anyone who knows a salt can test guesses against its fingerprint."""
    return {n: hashlib.sha256((SALT_LABEL + n).encode("ascii")).hexdigest() for n in SALT_NAMES}


def attr(key, value):
    return {"key": key, "value": {"stringValue": value}}


ARGUMENTS = {"amount": "250.00", "currency": "EUR", "recipient": "acct-example-4711"}
RESULT = {"status": "executed", "reference": "tx-example-0001"}


def spans() -> dict:
    """The two spans of the agent's domain, in the OTLP JSON form (one resource, one scope)."""
    trace, run_id, tool_id = "4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7", "b9c7c989f97918e1"
    run = {"traceId": trace, "spanId": run_id, "parentSpanId": "", "name": "invoke_agent payments-assistant",
           "kind": 1, "startTimeUnixNano": nanos("2026-11-20T10:00:00Z"),
           "endTimeUnixNano": nanos("2026-11-20T10:00:08Z"),
           "attributes": [attr("gen_ai.operation.name", "invoke_agent"),
                          attr("gen_ai.agent.name", "payments-assistant"),
                          attr("gen_ai.conversation.id", "conv-example-0001")]}
    tool = {"traceId": trace, "spanId": tool_id, "parentSpanId": run_id, "name": "execute_tool transfer_funds",
            "kind": 1, "startTimeUnixNano": nanos("2026-11-20T10:00:05Z"),
            "endTimeUnixNano": nanos("2026-11-20T10:00:06Z"),
            "attributes": [attr("gen_ai.operation.name", "execute_tool"),
                           attr("gen_ai.tool.name", "transfer_funds"),
                           attr("gen_ai.tool.call.id", "call-example-7f3a"),
                           attr("gen_ai.tool.type", "function"),
                           attr("gen_ai.agent.name", "payments-assistant"),
                           attr("gen_ai.conversation.id", "conv-example-0001"),
                           attr("gen_ai.tool.call.arguments", jcs(ARGUMENTS).decode("utf-8")),
                           attr("gen_ai.tool.call.result", jcs(RESULT).decode("utf-8"))]}
    return {"resourceSpans": [{"resource": {"attributes": [attr("service.name", "payments-assistant-example")]},
                               "scopeSpans": [{"scope": {"name": "example-genai-instrumentation"},
                                               "spans": [run, tool]}]}]}


def span_list(doc) -> list:
    return [s for rs in doc["resourceSpans"] for ss in rs["scopeSpans"] for s in ss["spans"]]


def attributes(span) -> dict:
    return {a["key"]: a["value"]["stringValue"] for a in span["attributes"]}


def selection(span, keys, *, parent: bool) -> dict:
    """The fixed selection a span's fingerprint covers: ids, name, kind, times and the named attributes."""
    a = attributes(span)
    sel = {"traceId": span["traceId"], "spanId": span["spanId"], "name": span["name"], "kind": span["kind"],
           "startTimeUnixNano": span["startTimeUnixNano"], "endTimeUnixNano": span["endTimeUnixNano"],
           "attributes": {k: a[k] for k in keys if k in a}}
    if parent:
        sel["parentSpanId"] = span["parentSpanId"]
    return sel


def fingerprint(value_or_text, salt_hex: str) -> str:
    text = value_or_text if isinstance(value_or_text, str) else jcs(value_or_text).decode("utf-8")
    return salted_commit(text, bytes.fromhex(salt_hex))


def approval_receipt(run, tool, *, verdict="ALLOW", call_id=None, decided="2026-11-20T10:00:04Z",
                     change=None) -> bytes:
    """The gate's decision receipt for the call. It lives in the agent's domain and is disclosed in a dispute.
    ``change``, when given, edits the predicate before it is signed; measure_cases.py uses it for its cases."""
    a = attributes(tool)
    args = jcs(json.loads(a["gen_ai.tool.call.arguments"]))
    p = {
        "schemaVersion": "0.1.0", "decisionType": "preActionAuthorization", "decisionMaker": {"id": "approval-gate-1"},
        "decisionId": "dec-otel-0001", "decidedAt": decided,
        "agent": {"id": a["gen_ai.agent.name"]}, "principal": {"id": "person-1"},
        "proposedAction": {"actionType": "tool.call", "method": "write",
                           "target": {"name": a["gen_ai.tool.name"], "uri": "urn:example:tool:" + a["gen_ai.tool.name"]},
                           "parametersDigest": {"sha256": sha256(args)}},
        "inputSnapshot": [{"name": "proposed arguments", "digest": {"sha256": sha256(args)},
                           "mediaType": "application/json"}],
        "policyBoundary": {"policyEngine": "example-approval-gate", "policyId": "transfer-approval",
                           "decisionPath": "transfer-approval/" + verdict.lower(),
                           "policyDigest": {"sha256": sha256(pretty(RULE))}, "bundleRevision": "1"},
        "evidenceRefs": [],
        "decision": {"verdict": verdict, "reasonCodes": ["user_approval" if verdict == "ALLOW" else "user_denied"]},
        "notChecked": [{"field": "arguments", "reason": "the gate does not judge whether the transfer is wise",
                        "impact": "an approved transfer can still be a mistake"}],
        "decisionChangeConditions": [{"conditionType": "ruleChange", "description": "a changed approval rule"}],
        "privacy": {"rawInputsIncluded": False},
        "traceContext": {"traceId": run["traceId"], "parentId": call_id or a["gen_ai.tool.call.id"]},
        "validity": {"audience": [AUDIENCE], "nonce": "dec-otel-0001", "expiresAt": "2026-11-20T10:15:04Z"}}
    if verdict != "ALLOW":
        p["actionOutcome"] = {"status": "blocked", "performedAt": None, "outcomeRef": None}
    if change:
        change(p)
    errs = decision.validate_decision_predicate(p, strict=True)
    if errs:
        raise ValueError(errs)
    return pretty(decision.emit_decision_receipt(p, GATE_SK))


def record_statement(doc, receipt_bytes: bytes, s: dict, rule_bytes: bytes) -> dict:
    """The in-toto Statement of the record: fingerprints, references, rule digest, order and conclusion."""
    run, tool = span_list(doc)
    a = attributes(tool)
    call_ref = fingerprint(a["gen_ai.tool.call.id"], s["call"])
    run_fp = fingerprint(selection(run, RUN_ATTRIBUTES, parent=False), s["run"])
    approved = json.loads(base64.b64decode(json.loads(receipt_bytes)["payload"]))["predicate"]
    amount = float(json.loads(a["gen_ai.tool.call.arguments"])["amount"])
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": "otel-agent-run", "digest": {"sha256": run_fp.split(":", 1)[1]}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "profile": PROFILE,
            "conventions": dict(CONVENTIONS),
            "traceRef": {"alg": COMMIT_ALG, "value": fingerprint(run["traceId"], s["trace"])},
            "entries": [
                {"seq": 1, "role": "run", "span": "invoke_agent", "alg": COMMIT_ALG, "fingerprint": run_fp},
                {"seq": 2, "role": "approval", "kind": "proofbundle decision receipt", "standard": APPROVAL_NOTE,
                 "alg": COMMIT_ALG, "fingerprint": fingerprint({"receiptSha256": sha256(receipt_bytes)}, s["approval"]),
                 "callRef": call_ref},
                {"seq": 3, "role": "action", "span": "execute_tool", "alg": COMMIT_ALG,
                 "fingerprint": fingerprint(selection(tool, ACTION_ATTRIBUTES, parent=True), s["action"]),
                 "callRef": call_ref}],
            "policyDigest": {"sha256": sha256(rule_bytes)},
            "conclusion": {"approvalRequired": amount > float(RULE["threshold"]),
                           "approvedBeforeAction": approved["decision"]["verdict"] == "ALLOW"},
        }}


def sign_record(statement: dict, key=RECORDER_SK) -> tuple:
    payload = jcs(statement)
    return payload, pretty(dsse.sign_envelope(payload, key, payload_type=INTOTO))


def anchor(payload: bytes, *, statement_key=STATEMENT_KEY, cert=STATEMENT_CERT) -> tuple:
    """The signed statement over SHA-256(payload), its receipt from the local test service, and both together."""
    st = sl.signed_statement(hashlib.sha256(payload).digest(), statement_key, cert, iss=STATEMENT_ISS,
                             sub=STATEMENT_SUB)
    rc = ledger().register(st)
    return st, rc, sl.transparent(st, [rc])


def ledger() -> sl.LocalLedger:
    return sl.LocalLedger(SERVICE_KEY, issuer=SERVICE_ISSUER, iat=RECEIPT_IAT)


def base() -> dict:
    """The parts of the example the cases reuse."""
    doc, s, rule_bytes = spans(), salts(), pretty(RULE)
    run, tool = span_list(doc)
    receipt = approval_receipt(run, tool)
    statement = record_statement(doc, receipt, s, rule_bytes)
    payload, envelope = sign_record(statement)
    st, rc, ts = anchor(payload)
    return {"spans": doc, "salts": s, "rule": rule_bytes, "receipt": receipt, "statement": statement,
            "payload": payload, "envelope": envelope, "signed_statement": st, "receipt_cose": rc,
            "transparent": ts}


def files(b=None) -> dict:
    b = b or base()
    return {
        "record.dsse.json": b["envelope"],
        "record.payload.json": b["payload"],
        "scitt/signed-statement.cose": b["signed_statement"],
        "scitt/receipt.cose": b["receipt_cose"],
        "scitt/transparent-statement.cose": b["transparent"],
        "statement-signer-test-cert.der": STATEMENT_CERT,
        "disclosure/spans.otlp.json": pretty(b["spans"]),
        "disclosure/salts.json": pretty({"note": "TEST SALTS, derived from public labels; a real issuer keeps "
                                                 "random salts to itself and discloses them only in a dispute",
                                         "alg": COMMIT_ALG, "salts_hex": b["salts"]}),
        "disclosure/approval.dsse.json": b["receipt"],
        "disclosure/rule.json": b["rule"],
        "test-keys.json": pretty({
            "note": "TEST KEYS ONLY. Each key derives from its public label; never use them for real records.",
            "recorder-1": {"label": LABEL_RECORDER, "alg": "Ed25519", "derivation": "seed = SHA-256(label)",
                           "public_b64": base64.b64encode(RECORDER_PK).decode("ascii")},
            "approval-gate-1": {"label": LABEL_GATE, "alg": "Ed25519", "derivation": "seed = SHA-256(label)",
                                "public_b64": base64.b64encode(GATE_PK).decode("ascii")},
            "statement-signer-1": {"label": LABEL_STATEMENT, "alg": "ES256",
                                   "derivation": "scalar = SHA-256(label) mod (n - 1) + 1, scitt_local.ec_key",
                                   "spki_sha256": sha256(sl.spki(STATEMENT_KEY)),
                                   "certificate_der_sha256": sha256(STATEMENT_CERT),
                                   "certificate_issuer_label": LABEL_STATEMENT_ISSUER},
            "scitt-service-1": {"label": LABEL_SERVICE, "alg": "ES256", "issuer": SERVICE_ISSUER,
                                "derivation": "scalar = SHA-256(label) mod (n - 1) + 1, scitt_local.ec_key",
                                "spki_sha256": sha256(sl.spki(SERVICE_KEY))}}),
    }


def write(out: Path, fs: dict):
    for rel, data in fs.items():
        p = out / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Write the example files.")
    ap.add_argument("--out", default=str(HERE / "out"))
    a = ap.parse_args(argv)
    write(Path(a.out), files())
    print("wrote", a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
