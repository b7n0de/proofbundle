"""Offline check of an agent record made from OpenTelemetry spans and anchored in SCITT.

    python check_example.py DIR [--disclosure DIR2] [--report FILE]

DIR holds record.dsse.json (the signed record) and scitt/transparent-statement.cose (the signed statement with
its receipt). DIR2, when given, holds what a disclosure in a dispute hands over: disclosure/spans.otlp.json,
salts.json, approval.dsse.json and rule.json (out/disclosure in the example).

Three states, and the exit code for each:

* PASSED (exit 0): every check below passed, with the disclosure.
* FAILED (exit 1): a check failed; the report names the first one.
* OPEN (exit 3): every check that runs without a disclosure passed, and no disclosure was given. Whether the
  fingerprints belong to the real spans, whether their content is true, and whether the rule holds for them is
  then open: not passed, and not failed either, in the sense of SCORE_WITHHELD in proofbundle.evalclaim: a
  commitment is present, the value behind it is withheld.

Exit 2 is a usage error. The keys are pinned here and never taken from DIR or DIR2: the recorder key that signs
the record, the gate key that signs the approval, the statement signer's key and the SCITT service's key under
its issuer. The anchoring is checked with proofbundle.scitt_ccf.verify_transparent_statement (needs the [scitt]
extra), the approval with proofbundle.decision.verify_decision_receipt.

Check ids. Without a disclosure: K1 the record's signature, K2 its form, K3 its fingerprints, K4 links and
order, A1 the anchoring. With one, also: D1 the salts, D2 the spans, D3 the fingerprints recomputed, D4 the
approval, D5 the rule and the conclusion, D6 no identifier in clear. The report has no clock time and no
absolute path.
"""
from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import json
import re
import sys
from pathlib import Path

import rfc8785
from proofbundle import decision, dsse, scitt_ccf

#: The pins. Test keys of this example (see out/test-keys.json and make_example.py); never real trust.
RECORDER_PUBLIC_KEY = "CRmuVCANabPavn2xC54Vl6Uovqf3wohMlLZD/2dktSA="
GATE_PUBLIC_KEY = "IKCIKm7udaFy18B+4pE3pRbLU+XNg7konHjKDvjEwms="
STATEMENT_SPKI = ("3059301306072a8648ce3d020106082a8648ce3d0301070342000429def251108f614fc044054d1f7256b294eb6d"
                  "5ad601088567811405a2a57aa4d3cbb12ac4324e2343caf22f0b80b9e0cf47ffd1258d53372d49011cf87558be")
SERVICE_ISSUER = "scitt.example"
SERVICE_SPKI = ("3059301306072a8648ce3d020106082a8648ce3d03010703420004ab12d6bab5681443c5ddfff42bd49ce24581e31b"
                "a2fdd80671d716a40022e9b32f9764e33cccbc7e24d027f7aa420b10ddfa45719f5933b59e64b1a64257662e")
AUDIENCE = "record-reader-1"

INTOTO = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://b7n0de.com/proofbundle/examples/otel-agent-record/v0.1"
PROFILE = "otel-genai-scitt-example/v0.1"
CONVENTIONS = {"source": "https://github.com/open-telemetry/semantic-conventions-genai",
               "commit": "e6658f14c9d9ea0760825f029cb82e7673f48fab", "status": "Development"}
COMMIT_ALG = "sha256-salted-v1"
FP = re.compile(r"sha256:[0-9a-f]{64}")
HEX32, HEX16 = re.compile(r"[0-9a-f]{32}"), re.compile(r"[0-9a-f]{16}")
SALT_NAMES = ("run", "approval", "action", "call", "trace")

#: The closed field sets of the record. A field outside them, a conversation id in clear for example, is refused.
STATEMENT_KEYS = {"_type", "subject", "predicateType", "predicate"}
PREDICATE_KEYS = {"profile", "conventions", "traceRef", "entries", "policyDigest", "conclusion"}
ENTRY_KEYS = {"run": {"seq", "role", "span", "alg", "fingerprint"},
              "approval": {"seq", "role", "kind", "standard", "alg", "fingerprint", "callRef"},
              "action": {"seq", "role", "span", "alg", "fingerprint", "callRef"}}
SPAN_OF = {"run": "invoke_agent", "action": "execute_tool"}
#: The fixed attribute selections of make_example.py, keys of the pinned conventions.
RUN_ATTRIBUTES = ("gen_ai.operation.name", "gen_ai.agent.name", "gen_ai.conversation.id")
ACTION_ATTRIBUTES = ("gen_ai.operation.name", "gen_ai.tool.name", "gen_ai.tool.call.id", "gen_ai.tool.type",
                     "gen_ai.agent.name", "gen_ai.conversation.id", "gen_ai.tool.call.arguments",
                     "gen_ai.tool.call.result")
SPAN_KIND_INTERNAL = 1

OPEN_ITEMS = ["that the fingerprints of run, approval and action belong to the real spans and the real approval",
              "that the content of the spans is true",
              "that the rule, recomputed over the spans, gives the conclusion the record states"]
NEVER_ITEMS = ["that the recording is complete: a span that was never recorded leaves no trace in the record",
               "that the action really ran as the spans say: the record repeats what the recorder was given"]


class Stop(Exception):
    pass


class Report:
    def __init__(self):
        self.checks, self.first = [], None

    def ok(self, cid, detail):
        self.checks.append({"id": cid, "result": "PASS", "detail": detail})

    def fail(self, cid, detail):
        self.first = {"id": cid, "result": "FAIL", "detail": detail}
        self.checks.append(self.first)
        raise Stop()

    def need(self, cond, cid, bad, good=None):
        if not cond:
            self.fail(cid, bad)
        if good:
            self.ok(cid, good)


def strict_json(b: bytes):
    def pairs(p):
        d = {}
        for k, v in p:
            if k in d:
                raise ValueError("duplicate member " + k)
            d[k] = v
        return d

    def const(c):
        raise ValueError("constant " + c)

    if b.startswith(b"\xef\xbb\xbf"):
        raise ValueError("byte order mark")
    return json.loads(b.decode("utf-8", errors="strict"), object_pairs_hook=pairs, parse_constant=const)


def jcs(v) -> bytes:
    return rfc8785.dumps(v)


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def salted(text: str, salt: bytes) -> str:
    """sha256-salted-v1 as proofbundle.evalclaim.salted_commit computes it."""
    return "sha256:" + hashlib.sha256(salt + text.encode("utf-8")).hexdigest()


def when(iso: str) -> int:
    t = datetime.datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    return int(t.timestamp()) * 1_000_000_000


# ---------------------------------------------------------------- without a disclosure
def check_record(rep, env_bytes: bytes):
    env = strict_json(env_bytes)
    rep.need(isinstance(env, dict) and env.get("payloadType") == INTOTO, "K1",
             "the record is not a DSSE envelope with payloadType " + INTOTO)
    good = dsse.verify_envelope(env, base64.b64decode(RECORDER_PUBLIC_KEY), payload_type=INTOTO)
    rep.need(good is True, "K1", "the record's DSSE signature does not verify under the pinned recorder key",
             "the record's DSSE signature verifies under the pinned recorder key")
    payload = base64.b64decode(env["payload"], validate=True)
    st = strict_json(payload)
    rep.need(jcs(st) == payload, "K2", "the record's payload is not in its RFC 8785 form, so its digest is not "
                                       "the one a reader recomputes")
    rep.need(isinstance(st, dict) and set(st) == STATEMENT_KEYS and st["_type"] == STATEMENT_TYPE
             and st["predicateType"] == PREDICATE_TYPE, "K2",
             "the record is not an in-toto Statement v1 of the example's predicate type with exactly the fields "
             + ", ".join(sorted(STATEMENT_KEYS)))
    p = st["predicate"]
    rep.need(isinstance(p, dict) and set(p) == PREDICATE_KEYS, "K2",
             "the predicate has fields outside the profile or lacks one: %s; a field outside the profile can carry "
             "an identifier in clear" % sorted(set(p) ^ PREDICATE_KEYS if isinstance(p, dict) else []))
    rep.need(p["profile"] == PROFILE and p["conventions"] == CONVENTIONS, "K2",
             "the predicate does not name the profile and the pinned commit of the conventions",
             "an in-toto Statement v1 in RFC 8785 form, closed field sets, conventions pinned at "
             + CONVENTIONS["commit"])
    rep.need(isinstance(p["conclusion"], dict) and set(p["conclusion"]) == {"approvalRequired", "approvedBeforeAction"}
             and all(isinstance(x, bool) for x in p["conclusion"].values())
             and isinstance(p["policyDigest"], dict) and set(p["policyDigest"]) == {"sha256"}
             and isinstance(p["policyDigest"]["sha256"], str)
             and re.fullmatch(r"[0-9a-f]{64}", p["policyDigest"]["sha256"]), "K2", "the conclusion or the rule digest is not in form")
    return payload, st


def check_fingerprints(rep, st):
    p = st["predicate"]
    entries = p["entries"]
    rep.need(isinstance(entries, list) and [e.get("role") if isinstance(e, dict) else None for e in entries]
             == ["run", "approval", "action"], "K3", "the entries are not run, approval and action, in that order")
    for e in entries:
        role = e["role"]
        rep.need(set(e) == ENTRY_KEYS[role], "K3", "entry %s has fields outside the profile or lacks one: %s"
                 % (role, sorted(set(e) ^ ENTRY_KEYS[role])))
        rep.need(e["alg"] == COMMIT_ALG, "K3", "entry %s has the commitment %r, not %s: a fingerprint over guessable "
                 "content (arguments, result, agent name, the approval) must be salted" % (role, e["alg"], COMMIT_ALG))
        rep.need(isinstance(e["fingerprint"], str) and FP.fullmatch(e["fingerprint"]), "K3",
                 "entry %s: the fingerprint is not sha256:<64 hex>" % role)
        if role in SPAN_OF:
            rep.need(e["span"] == SPAN_OF[role], "K3", "entry %s does not name the span %s" % (role, SPAN_OF[role]))
        if role == "approval":
            rep.need(e["kind"] == "proofbundle decision receipt" and isinstance(e["standard"], str)
                     and e["standard"].startswith("not standardized"), "K3",
                     "the approval entry does not say that the approval is not standardized in OpenTelemetry; the "
                     "conventions at the pinned commit define no span or attribute for it")
    tr = p["traceRef"]
    rep.need(isinstance(tr, dict) and set(tr) == {"alg", "value"} and tr["alg"] == COMMIT_ALG
             and isinstance(tr["value"], str) and FP.fullmatch(tr["value"]), "K3",
             "the trace reference is not a salted fingerprint (sha256-salted-v1)",
             "every fingerprint and reference is sha256-salted-v1; the approval is marked as not standardized")


def check_links(rep, st):
    entries = {e["role"]: e for e in st["predicate"]["entries"]}
    for role in ("approval", "action"):
        rep.need(isinstance(entries[role]["callRef"], str) and FP.fullmatch(entries[role]["callRef"]), "K4",
                 "entry %s: the call reference is not sha256:<64 hex>" % role)
    rep.need(entries["approval"]["callRef"] == entries["action"]["callRef"], "K4",
             "approval and action carry different call references, so the approval is not the one of this call")
    seqs = [entries[r]["seq"] for r in ("run", "approval", "action")]
    rep.need(all(type(s) is int for s in seqs) and seqs == [1, 2, 3], "K4",
             "the stated order is not run, approval, action (seq %r)" % (seqs,))
    subj = st["subject"]
    rep.need(isinstance(subj, list) and len(subj) == 1 and subj[0] == {
        "name": "otel-agent-run", "digest": {"sha256": entries["run"]["fingerprint"].split(":", 1)[1]}}, "K4",
             "the subject is not the run's fingerprint",
             "approval and action share one call reference; the order is run, approval, action; the subject is the "
             "run's fingerprint")


def check_anchor(rep, payload: bytes, ts_bytes: bytes):
    rp = {"scitt_ccf_services": {SERVICE_ISSUER: [bytes.fromhex(SERVICE_SPKI)]},
          "scitt_statement_keys": [bytes.fromhex(STATEMENT_SPKI)]}
    r = scitt_ccf.verify_transparent_statement(ts_bytes, canonical_root=hashlib.sha256(payload).digest(), rp_trust=rp)
    receipts = ", ".join("receipt %d %s" % (c.index, c.status) for c in r.receipts) or "no receipt read"
    rep.need(r.status == "confirmed" and r.profile_satisfied, "A1",
             "the Transparent Statement is %s (statement %s; %s): %s" % (r.status, r.statement_status, receipts,
                                                                         r.detail),
             "scitt-ccf/v1 confirmed: the statement's payload is SHA-256 of the record's payload, its signature "
             "verifies under the pinned statement key, and the receipt verifies under the pinned key of "
             + SERVICE_ISSUER)


# ---------------------------------------------------------------- with a disclosure
def spans_of(doc):
    return [s for rs in doc["resourceSpans"] for ss in rs["scopeSpans"] for s in ss["spans"]]


def attributes(span) -> dict:
    out = {}
    for a in span["attributes"]:
        v = a["value"]
        if set(v) != {"stringValue"} or not isinstance(v["stringValue"], str) or a["key"] in out:
            raise ValueError("attribute %r is not a single string value" % a.get("key"))
        out[a["key"]] = v["stringValue"]
    return out


def selection(span, keys, *, parent: bool) -> dict:
    a = attributes(span)
    sel = {"traceId": span["traceId"], "spanId": span["spanId"], "name": span["name"], "kind": span["kind"],
           "startTimeUnixNano": span["startTimeUnixNano"], "endTimeUnixNano": span["endTimeUnixNano"],
           "attributes": {k: a[k] for k in keys if k in a}}
    if parent:
        sel["parentSpanId"] = span["parentSpanId"]
    return sel


def check_salts(rep, d: Path):
    doc = strict_json((d / "salts.json").read_bytes())
    s = doc.get("salts_hex") if isinstance(doc, dict) else None
    rep.need(isinstance(doc, dict) and doc.get("alg") == COMMIT_ALG and isinstance(s, dict)
             and set(s) == set(SALT_NAMES), "D1", "salts.json does not hold the five salts of " + COMMIT_ALG)
    out = {}
    for n in SALT_NAMES:
        rep.need(isinstance(s[n], str) and re.fullmatch(r"(?:[0-9a-f]{2})+", s[n]), "D1", "salt %s is not hex" % n)
        out[n] = bytes.fromhex(s[n])
        rep.need(len(out[n]) >= 16, "D1", "salt %s has %d bytes; sha256-salted-v1 needs at least 16"
                 % (n, len(out[n])))
    rep.ok("D1", "five salts of at least 16 bytes")
    return out


def check_spans(rep, d: Path):
    doc = strict_json((d / "spans.otlp.json").read_bytes())
    ss = spans_of(doc)
    rep.need(len(ss) == 2, "D2", "the disclosure holds %d spans, not the two of run and action" % len(ss))
    by_op = {attributes(s).get("gen_ai.operation.name"): s for s in ss}
    rep.need(set(by_op) == {"invoke_agent", "execute_tool"}, "D2",
             "the spans are not one invoke_agent and one execute_tool (gen_ai.operation.name, Required)")
    run, tool = by_op["invoke_agent"], by_op["execute_tool"]
    ta = attributes(tool)
    rep.need(all(s["kind"] == SPAN_KIND_INTERNAL for s in (run, tool)), "D2",
             "a span is not of kind INTERNAL (the conventions: SHOULD be INTERNAL for both)")
    rep.need(isinstance(ta.get("gen_ai.tool.name"), str) and ta["gen_ai.tool.name"]
             and tool["name"] == "execute_tool " + ta["gen_ai.tool.name"], "D2",
             "the execute_tool span has no gen_ai.tool.name (Required) or is not named execute_tool {gen_ai.tool.name}")
    rep.need(all(HEX32.fullmatch(s["traceId"]) and HEX16.fullmatch(s["spanId"]) for s in (run, tool))
             and run["traceId"] == tool["traceId"] and tool["parentSpanId"] == run["spanId"]
             and run["parentSpanId"] == "", "D2",
             "the action span is not a child of the run span in one trace")
    t = {k: (int(s["startTimeUnixNano"]), int(s["endTimeUnixNano"])) for k, s in (("run", run), ("tool", tool))}
    rep.need(t["run"][0] <= t["tool"][0] <= t["tool"][1] <= t["run"][1], "D2",
             "the action span does not lie inside the run span",
             "one invoke_agent and one execute_tool span, both INTERNAL, the action a child of the run inside its time")
    json.loads(ta["gen_ai.tool.call.arguments"])
    return run, tool


def check_recomputed(rep, st, salts, run, tool, approval_bytes):
    p = st["predicate"]
    entries = {e["role"]: e for e in p["entries"]}
    want = {"run": (jcs(selection(run, RUN_ATTRIBUTES, parent=False)).decode("utf-8"), salts["run"]),
            "action": (jcs(selection(tool, ACTION_ATTRIBUTES, parent=True)).decode("utf-8"), salts["action"]),
            "approval": (jcs({"receiptSha256": sha256(approval_bytes)}).decode("utf-8"), salts["approval"])}
    for role, (text, salt) in want.items():
        fp = entries[role]["fingerprint"]
        rep.need(fp != "sha256:" + sha256(text.encode("utf-8")), "D3",
                 "entry %s: the fingerprint is the unsalted SHA-256 of the span selection, which anyone can test "
                 "guesses against" % role)
        rep.need(fp == salted(text, salt), "D3", "entry %s: the fingerprint does not match the disclosed %s"
                 % (role, "approval receipt" if role == "approval" else "span"))
    call = attributes(tool)["gen_ai.tool.call.id"]
    rep.need(entries["action"]["callRef"] == salted(call, salts["call"]), "D3",
             "the call reference is not the salted gen_ai.tool.call.id of the disclosed action span")
    rep.need(p["traceRef"]["value"] == salted(run["traceId"], salts["trace"]), "D3",
             "the trace reference is not the salted trace id of the disclosed spans",
             "the three fingerprints, the call reference and the trace reference recompute from the disclosure")


def check_approval(rep, st, run, tool, approval_bytes):
    env = strict_json(approval_bytes)
    ta = attributes(tool)
    args = jcs(json.loads(ta["gen_ai.tool.call.arguments"]))
    start = int(tool["startTimeUnixNano"])
    r = decision.verify_decision_receipt(env, base64.b64decode(GATE_PUBLIC_KEY), strict=True,
                                         expected_audience=AUDIENCE, now=start // 1_000_000_000, action_bytes=args)
    rep.need(r.get("ok") is True and r.get("crypto_ok") is True and r.get("action_bytes_ok") is True, "D4",
             "the approval receipt does not verify under the pinned gate key for these arguments: %s"
             % "; ".join(str(x) for x in r.get("errors") or ["ok %r" % r.get("ok")]))
    pred = json.loads(base64.b64decode(env["payload"]))["predicate"]
    tc = pred.get("traceContext") or {}
    rep.need(tc.get("parentId") == ta["gen_ai.tool.call.id"] and tc.get("traceId") == run["traceId"], "D4",
             "the approval receipt names another tool call or trace than the disclosed action span")
    decided = when(pred["decidedAt"])
    rep.need(int(run["startTimeUnixNano"]) <= decided <= start, "D4",
             "the approval was decided at %s, not between the run's start and the action's start" % pred["decidedAt"])
    rep.need(pred["policyBoundary"]["policyDigest"]["sha256"] == st["predicate"]["policyDigest"]["sha256"], "D4",
             "the approval receipt names another rule than the record",
             "the approval verifies under the pinned gate key (proofbundle decision verify, strict) for the "
             "arguments of the call, names the call and its trace, and was decided before the action")
    return pred


def check_rule(rep, st, d: Path, tool, approval_pred):
    rule_bytes = (d / "rule.json").read_bytes()
    rep.need(sha256(rule_bytes) == st["predicate"]["policyDigest"]["sha256"], "D5",
             "the disclosed rule is not the one whose digest the record carries")
    rule = strict_json(rule_bytes)
    ta = attributes(tool)
    args = json.loads(ta["gen_ai.tool.call.arguments"])
    required = (ta["gen_ai.tool.name"] == rule["tool"] and args.get("currency") == rule["currency"]
                and float(args["amount"]) > float(rule["threshold"]))
    approved = approval_pred["decision"]["verdict"] == "ALLOW"
    got = st["predicate"]["conclusion"]
    rep.need(got == {"approvalRequired": required, "approvedBeforeAction": approved}, "D5",
             "the conclusion %r is not what the rule gives over the disclosure %r"
             % (got, {"approvalRequired": required, "approvedBeforeAction": approved}))
    rep.need(approved or not required, "D5", "the rule needs an approval before the action, and there was none",
             "the rule, recomputed over the disclosed spans and approval, gives the record's conclusion and holds")


def check_clear(rep, payload: bytes, run, tool):
    text = payload.decode("utf-8")
    ra, ta = attributes(run), attributes(tool)
    values = {"trace id": run["traceId"], "run span id": run["spanId"], "action span id": tool["spanId"],
              "conversation id": ra.get("gen_ai.conversation.id"), "agent name": ra.get("gen_ai.agent.name"),
              "tool call id": ta["gen_ai.tool.call.id"]}
    for k, v in json.loads(ta["gen_ai.tool.call.arguments"]).items():
        values["argument " + k] = str(v)
    for k, v in json.loads(ta.get("gen_ai.tool.call.result", "{}")).items():
        values["result " + k] = str(v)
    for what, v in values.items():
        if v and len(v) >= 6:
            rep.need(v not in text, "D6", "the record carries the %s in clear" % what)
    rep.ok("D6", "no trace id, span id, conversation id, agent name, tool call id, argument or result value of six "
                 "or more characters stands in clear in the record")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Offline check of an OpenTelemetry agent record anchored in SCITT.")
    ap.add_argument("dir")
    ap.add_argument("--disclosure", help="the folder with spans.otlp.json, salts.json, approval.dsse.json, rule.json")
    ap.add_argument("--report")
    a = ap.parse_args(argv)
    rep = Report()
    d = Path(a.dir)
    try:
        payload, st = check_record(rep, (d / "record.dsse.json").read_bytes())
        check_fingerprints(rep, st)
        check_links(rep, st)
        check_anchor(rep, payload, (d / "scitt" / "transparent-statement.cose").read_bytes())
        if a.disclosure:
            dd = Path(a.disclosure)
            salts = check_salts(rep, dd)
            run, tool = check_spans(rep, dd)
            approval_bytes = (dd / "approval.dsse.json").read_bytes()
            check_recomputed(rep, st, salts, run, tool, approval_bytes)
            pred = check_approval(rep, st, run, tool, approval_bytes)
            check_rule(rep, st, dd, tool, pred)
            check_clear(rep, payload, run, tool)
    except Stop:
        pass
    except (KeyError, TypeError, IndexError, ValueError, AttributeError, OSError) as e:
        rep.first = {"id": "X", "result": "FAIL", "detail": "form: %s: %s" % (type(e).__name__, e)}
        rep.checks.append(rep.first)
    state = "FAILED" if rep.first else ("PASSED" if a.disclosure else "OPEN")
    out = {"state": state, "first_failure": rep.first, "checks": rep.checks,
           "open": OPEN_ITEMS if state == "OPEN" else [], "never": NEVER_ITEMS}
    if a.report:
        Path(a.report).write_bytes((json.dumps(out, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))
    print(state, "%s: %s" % (rep.first["id"], rep.first["detail"]) if rep.first else "(%d checks)" % len(rep.checks))
    return {"PASSED": 0, "FAILED": 1, "OPEN": 3}[state]


if __name__ == "__main__":
    sys.exit(main())
