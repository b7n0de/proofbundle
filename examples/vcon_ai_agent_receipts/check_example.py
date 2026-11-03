"""Offline check of a signed vCon that carries decision receipts.

    python check_example.py DIR [--signed FILE] [--proofbundle CMD] [--adrverify PATH]
                                [--action-bytes jcs|none] [--report FILE]

DIR holds vcon.signed.json (JWS with EdDSA or RS256; --signed names another file in DIR, such as
vcon.signed-rs256.json), vcon.cose (COSE_Sign1), external/ (the files that url members name,
by their last path segment) and receipts/dec-0003.dsse.json (the receipt that cites the record). The
check stops at the first failure and names it; the report has no clock time and no absolute path.

The keys are pinned here and never taken from DIR: the gate key that signs decisions and the SHA-256 of
the recorder's two test certificates, one for EdDSA and one for RS256. Each receipt is also verified with `proofbundle decision verify
--strict`, and, where --adrverify names a second checker of Section 3 of
draft-gruszka-audit-decision-receipts, with that checker for Case 1 or Case 2.

Check ids: V1 to V4 the vCon, A1 the attachments, R1 to R5 each receipt in the vCon, C1 to C3 the set,
Z1 to Z3 the citing receipt and the two signed forms. Exit 0 PASS, 1 FAIL, 2 usage.
"""
from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import vcon_profile as vp  # noqa: E402

GATE_PUBLIC_KEY = "TWfs75IN1In3CNI8TnyIOUHgtwilOPGcRFQLJ670CJc="
GATE_ID = "gate-1"
AUDIENCE = "observer-1"
RECORDER_CERT_SHA256 = "87c4bb91013e1f4bd9428aa5e471ea3649d0ad80f41f96cd91d91e1fc6e188b5"
RECORDER_RSA_CERT_SHA256 = "051a828a0c51395652ba6d81c6fb2b5443f8d878bf6f4772e63f7a9830351236"
CITE_TIME = "2026-10-15T09:21:00Z"
AI_AGENT_TYPES = {"tool-call", "tool-result", "reasoning", "system-event"}
RECEIPT, APPROVAL = "decision receipt", "approval record"


class Stop(Exception):
    pass


class Report:
    def __init__(self):
        self.checks, self.first = [], None

    def ok(self, cid, where, detail=""):
        self.checks.append({"id": cid, "where": where, "result": "PASS", "detail": detail})

    def fail(self, cid, where, detail):
        self.first = {"id": cid, "where": where, "result": "FAIL", "detail": detail}
        self.checks.append(self.first)
        raise Stop()

    def need(self, cond, cid, where, failure, success=""):
        if not cond:
            self.fail(cid, where, failure)
        self.ok(cid, where, success)


def index(v, n):
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v < n


def as_list(v):
    return v if isinstance(v, list) else [v]


def check_cert(rep, cid, where, der, pins):
    try:
        cert = x509.load_der_x509_certificate(der)
    except ValueError as e:
        rep.fail(cid, where, "certificate not readable: %s" % e)
    rep.need(vp.sha256(der) in pins, cid, where, "certificate is not a pinned test certificate",
             "pinned certificate " + vp.sha256(der))
    return cert.public_key()


# ---------------------------------------------------------------- the vCon in its signed form (vCon core 6.2)
def check_jws(rep, raw, pin):
    try:
        signed = vp.strict_json(raw)
    except ValueError as e:
        rep.fail("V1", "vCon", "not valid JSON: %s" % e)
    rep.need(isinstance(signed, dict) and "payload" in signed and "signatures" in signed, "V1",
             "vCon, form (vCon core 6.4)", "not the signed form", "signed form")
    sigs = signed["signatures"]
    rep.need(isinstance(sigs, list) and sigs, "V2", "JWS signatures", "no signature")
    header = None
    for i, so in enumerate(sigs):
        where = "JWS signatures[%d]" % i
        hdr = so.get("header") if isinstance(so, dict) else None
        rep.need(isinstance(hdr, dict), "V2", where, "header missing (6.2.1)")
        try:
            prot = vp.strict_json(vp.b64u_dec(so["protected"])) if "protected" in so else {}
        except (ValueError, KeyError) as e:
            rep.fail("V2", where, "protected header not readable: %s" % e)
        both = set(prot) & set(hdr)
        rep.need(not both, "V2", where, "parameter in both protected and header: %s" % sorted(both))
        alg = prot.get("alg", hdr.get("alg"))
        rep.need(alg not in (None, "none"), "V2", where, "alg missing or none (6.2.2)")
        rep.need(alg in ("EdDSA", "RS256"), "V2", where, "this profile expects alg EdDSA or RS256, found %r" % alg)
        rep.need("x5c" in hdr, "V2", where, "no x5c in header (6.2.2; x5u is not fetched offline)")
        try:
            der = vp.b64_dec(hdr["x5c"][0])
        except (ValueError, IndexError, TypeError) as e:
            rep.fail("V2", where, "x5c[0] not readable: %s" % e)
        pk = check_cert(rep, "V2", where, der, pin)
        rep.need(isinstance(pk, Ed25519PublicKey if alg == "EdDSA" else RSAPublicKey), "V2", where,
                 "certificate key does not fit alg %s" % alg)
        try:
            sig = vp.b64u_dec(so["signature"])
            tbs = (so.get("protected", "") + "." + signed["payload"]).encode("ascii")
            if alg == "EdDSA":
                pk.verify(sig, tbs)
            else:
                pk.verify(sig, tbs, padding.PKCS1v15(), hashes.SHA256())
        except (InvalidSignature, ValueError, KeyError) as e:
            rep.fail("V2", where, "JWS signature does not verify (%s)" % type(e).__name__)
        rep.ok("V2", where, "JWS signature verifies, alg %s" % alg)
        header = hdr
    try:
        payload = vp.b64u_dec(signed["payload"])
    except ValueError as e:
        rep.fail("V3", "JWS payload", str(e))
    rep.need(not payload.startswith(b"\x1f\x8b"), "V3", "JWS payload", "gzip payload, not in this profile")
    try:
        v = vp.strict_json(payload)
    except ValueError as e:
        rep.fail("V3", "JWS payload", "payload is not strict JSON: %s" % e)
    rep.need(vp.jcs(v) == payload, "V3", "JWS payload", "payload is not its own RFC 8785 serialization",
             "payload in RFC 8785 form, sha256 " + vp.sha256(payload))
    if "uuid" in header:
        rep.need(header["uuid"] == v.get("uuid"), "V3", "JWS header uuid", "header uuid differs (6.2.2)")
    return v, payload


def check_structure(rep, v):
    rep.need(isinstance(v, dict), "V4", "vCon", "vCon is not an object")
    rep.need(isinstance(v.get("uuid"), str) and len(v["uuid"]) == 36, "V4", "uuid", "uuid missing (4.1.2)")
    for where, fn in (("created_at", lambda: vp.when(v.get("created_at"))),):
        try:
            fn()
        except ValueError as e:
            rep.fail("V4", where, str(e))
    ext = v.get("extensions", [])
    rep.need(isinstance(ext, list) and "ai_agent" in ext, "V4", "extensions", "ai_agent not in extensions")
    for c in v.get("critical", []):
        rep.need(c in ext and c == "ai_agent", "V4", "critical", "unsupported critical extension %r" % c)
    parties, sessions = v.get("parties", []), v.get("sessions", [])
    dialog, events, att = v.get("dialog", []), v.get("events", []), v.get("attachments", [])
    rep.need(len(sessions) >= 1, "V4", "sessions", "no Session Object although there are dialog or events")
    for i, s in enumerate(sessions):
        rep.need(isinstance(s.get("agent_session_id"), str) and s["agent_session_id"], "V4", "sessions[%d]" % i,
                 "agent_session_id missing (needed by this profile)")
        for d in s.get("dialog", []):
            rep.need(index(d, len(dialog)), "V4", "sessions[%d].dialog" % i, "index %r invalid" % d)
    seen = set()
    for i, d in enumerate(dialog):
        where = "dialog[%d]" % i
        rep.need(d.get("type") == "text", "V4", where, "this profile only has text Dialog Objects")
        rep.need(index(d.get("parties"), len(parties)), "V4", where, "parties is not one valid index")
        try:
            vp.when(d.get("start"))
        except ValueError as e:
            rep.fail("V4", where, str(e))
        for k in [k for k, s in enumerate(sessions) if i in s.get("dialog", [])]:
            if "entry_id" in d:
                rep.need((k, d["entry_id"]) not in seen, "V4", where, "entry_id repeated in session %d" % k)
                seen.add((k, d["entry_id"]))
    for i, e in enumerate(events):
        where = "events[%d]" % i
        if e.get("type") not in AI_AGENT_TYPES:
            rep.ok("V4", where, "type %r not in this profile, ignored (vCon core 2.5)" % e.get("type"))
            continue
        try:
            vp.when(e.get("time"))
        except ValueError as ex:
            rep.fail("V4", where, "time: %s" % ex)
        if "sessions" not in e:
            rep.fail("V4", where, "parameter sessions missing (event_common_type of vCon core)"
                     + ("; session is present instead" if "session" in e else ""))
        for k in as_list(e["sessions"]):
            rep.need(index(k, len(sessions)), "V4", where, "sessions index %r invalid" % k)
        rep.need(index(e.get("party"), len(parties)), "V4", where, "party invalid")
        if e["type"] == "tool-call":
            rep.need(isinstance(e.get("tool_name"), str) and "input" in e, "V4", where, "tool_name or input missing")
        if e["type"] == "tool-result":
            rep.need("output" in e, "V4", where, "output missing")
        if "entry_id" in e:
            for k in as_list(e["sessions"]):
                rep.need((k, e["entry_id"]) not in seen, "V4", where, "entry_id repeated in session %d" % k)
                seen.add((k, e["entry_id"]))
    for i, a in enumerate(att):
        where = "attachments[%d]" % i
        try:
            vp.when(a.get("start"))
        except ValueError as e:
            rep.fail("V4", where, str(e))
        rep.need(index(a.get("party"), len(parties)), "V4", where, "party invalid (4.6.3)")
        rep.need("dialog" in a or "session" in a, "V4", where, "neither dialog nor session (4.6.4)")
        if "dialog" in a:
            rep.need(index(a["dialog"], len(dialog)), "V4", where, "dialog invalid")
        for k in as_list(a.get("session", [])):
            rep.need(index(k, len(sessions)), "V4", where, "session invalid")
    rep.ok("V4", "vCon", "%d parties, %d sessions, %d dialog, %d events, %d attachments" % (
        len(parties), len(sessions), len(dialog), len(events), len(att)))


# ---------------------------------------------------------------- attachments (vCon core 2.3, 2.4)
def attachment_bytes(rep, i, a, external):
    where = "attachments[%d] (%s)" % (i, a.get("purpose"))
    inline, ext = "body" in a or "encoding" in a, "url" in a or "content_hash" in a
    rep.need(inline != ext, "A1", where, "both inline and external, or neither")
    if inline:
        rep.need("mediatype" in a, "A1", where, "mediatype missing for inline content (4.6.6)")
        enc = a.get("encoding")
        if enc == "json":
            b = vp.jcs(a["body"])
        elif enc == "none" and isinstance(a.get("body"), str):
            b = a["body"].encode("utf-8")
        elif enc == "base64url":
            try:
                b = vp.b64u_dec(a["body"])
            except ValueError as e:
                rep.fail("A1", where, str(e))
        else:
            rep.fail("A1", where, "encoding %r not supported" % enc)
        rep.ok("A1", where, "inline %s, bytes sha256 %s" % (enc, vp.sha256(b)))
        return b
    url = a.get("url")
    rep.need(isinstance(url, str) and url.startswith("https://"), "A1", where, "url missing or not HTTPS (2.4.1)")
    tokens = as_list(a.get("content_hash"))
    try:
        b = (Path(external) / url.rstrip("/").rsplit("/", 1)[-1]).read_bytes()
    except OSError:
        rep.fail("A1", where, "external file not present")
    algs = []
    for t in tokens:
        alg, _, value = t.partition("-") if isinstance(t, str) else ("", "", "")
        rep.need(alg.isalnum() and alg == alg.lower() and value and all(
            c.isalnum() or c in "-_" for c in value), "A1", where, "content_hash token malformed: %r" % (t,))
        algs.append(alg)
        if alg in ("sha512", "sha256"):
            rep.need(vp.b64u(hashlib.new(alg, b).digest()) == value, "A1", where, "content_hash %s does not match" % alg,
                     "content_hash %s matches" % alg)
        else:
            rep.ok("A1", where, "algorithm %s not supported, skipped" % alg)
    rep.need("sha512" in algs, "A1", where, "content_hash without sha512 (2.4.2)")
    return b


# ---------------------------------------------------------------- receipts
def open_receipt(rep, cid, where, env_b, gate):
    """Steps 1 to 6 of Section 3.2 as far as the bridges need them; R5 and Z1 run the full procedure."""
    try:
        env = vp.strict_json(env_b)
        p = vp.b64_dec(env["payload"])
        if env["payloadType"] != vp.INTOTO:
            raise ValueError("payloadType")
        pae = b"DSSEv1 %d %s %d " % (len(vp.INTOTO), vp.INTOTO.encode(), len(p)) + p
    except (ValueError, KeyError, TypeError) as e:
        rep.fail(cid, where, "envelope not readable: %s" % type(e).__name__)
    good = False
    for s in env.get("signatures", []):
        try:
            gate.verify(vp.b64_dec(s["sig"]), pae)
            good = True
        except (InvalidSignature, ValueError, KeyError, TypeError):
            pass
    rep.need(good, cid, where, "no DSSE signature of the gate over PAE (step 3 of 3.2)")
    try:
        st = vp.strict_json(p)
    except ValueError as e:
        rep.fail(cid, where, "payload is not JSON: %s" % e)
    rep.need(vp.jcs(st) == p, cid, where, "payload is not its own RFC 8785 serialization (step 4 of 3.2)")
    rep.need(st.get("predicateType") == vp.PT_DECISION and isinstance(st.get("predicate"), dict), cid, where,
             "not a decision receipt")
    rep.ok(cid, where, "DSSE verifies, content root " + vp.sha256(p))
    return st["predicate"], vp.sha256(p)


def full_check(rep, cid, where, env_b, a, T, case, action=None, approval=None):
    with tempfile.TemporaryDirectory() as td:
        e = os.path.join(td, "env.json")
        Path(e).write_bytes(env_b)
        r = subprocess.run(a.proofbundle.split() + ["decision", "verify", "--pub", GATE_PUBLIC_KEY, "--strict",
                                                    "--aud", AUDIENCE, "--verification-time", T, "--json", e],
                           capture_output=True, check=False)
        try:
            errors = [str(x).replace(td, "<tmp>") for x in json.loads(r.stdout).get("errors", [])]
        except ValueError:
            errors = ["no JSON output"]
        rep.need(r.returncode == 0, cid, where + ", proofbundle",
                 "proofbundle decision verify exit %d: %s" % (r.returncode, "; ".join(errors)[:300]),
                 "proofbundle decision verify --strict --aud %s --verification-time %s, exit 0" % (AUDIENCE, T))
        if a.adrverify:
            pol = os.path.join(td, "policy.json")
            Path(pol).write_text(json.dumps({"decision": {GATE_PUBLIC_KEY: [GATE_ID]}, "outcome": {}}))
            cmd = [a.adrverify, "decision", "-policy", pol, "-pub", GATE_PUBLIC_KEY, "-signer", GATE_ID, "-t", T,
                   "-aud", AUDIENCE, "-case", case]
            for flag, data, name in (("-action", action, "action.bin"), ("-approval", approval, "approval.json")):
                if data is not None:
                    Path(td, name).write_bytes(data)
                    cmd += [flag, os.path.join(td, name)]
            r = subprocess.run(cmd + [e], capture_output=True, check=False)
            line = r.stdout.decode().strip().replace(td, "<tmp>")
            rep.need(r.returncode == 0, cid, where + ", second checker",
                     "adrverify -case %s exit %d: %s" % (case, r.returncode, line[:300]),
                     "adrverify -case %s, %s" % (case, line))


def send_time(d):
    t = vp.when(d["start"])
    return t + datetime.timedelta(seconds=d["duration"]) if "duration" in d else t


def check_receipts(rep, v, a, gate):
    parties, sessions = v.get("parties", []), v.get("sessions", [])
    dialog, events, att = v.get("dialog", []), v.get("events", []), v.get("attachments", [])
    data = {i: attachment_bytes(rep, i, x, a.external) for i, x in enumerate(att)
            if x.get("purpose") in (RECEIPT, APPROVAL)}
    approvals = {}
    for i, b in data.items():
        if att[i]["purpose"] == APPROVAL:
            try:
                approvals[i] = (b, vp.strict_json(b))
            except ValueError as e:
                rep.fail("A1", "attachments[%d] (approval record)" % i, "not JSON: %s" % e)
    found = []
    for i, b in data.items():
        if att[i]["purpose"] != RECEIPT:
            continue
        where = "attachments[%d] (decision receipt)" % i
        pred, root = open_receipt(rep, "R1", where, b, gate)
        where += " " + str(pred.get("decisionId"))
        # R2 the tool call
        tc = pred.get("traceContext", {})
        ks = [k for k, s in enumerate(sessions) if s.get("agent_session_id") == tc.get("traceId")]
        rep.need(len(ks) == 1, "R2", where, "traceContext.traceId %r names no session" % tc.get("traceId"))
        k = ks[0]
        in_k = [j for j, e in enumerate(events) if e.get("type") == "tool-call" and k in as_list(e.get("sessions", []))]
        by_call = [j for j in in_k if events[j].get("call_id") == tc.get("parentId")]
        js = by_call or [j for j in in_k if events[j].get("entry_id") == tc.get("parentId")]
        rep.need(len(js) == 1, "R2", where, "traceContext.parentId %r names no single tool call of the session"
                 % tc.get("parentId"))
        j = js[0]
        tool = events[j]
        agent = parties[tool["party"]]
        rep.need(agent.get("uuid") == pred["agent"]["id"] and "agent_meta" in agent, "R2", where,
                 "agent.id %r is not the party of the tool call" % pred["agent"]["id"])
        principal = pred.get("principal", {}).get("id")
        people = [p for p in parties if p.get("type") == "person" and p.get("uuid") == principal]
        rep.need(len(people) == 1, "R2", where, "principal.id %r is not the uuid of one person in the vCon" % principal)
        action =vp.jcs(tool["input"]) if a.action_bytes == "jcs" else None
        if action is not None:
            rep.need(vp.sha256(action) == pred["proposedAction"]["parametersDigest"]["sha256"], "R2", where,
                     "SHA-256 of the RFC 8785 form of events[%d].input is not parametersDigest" % j,
                     "events[%d] (call_id %s), parametersDigest = SHA-256(JCS(input))" % (j, tool.get("call_id")))
        else:
            rep.ok("R2", where, "events[%d] (call_id %s) bound by traceContext only; action bytes not checked"
                   % (j, tool.get("call_id")))
        # R3 the case, from the vCon
        digest = pred["proposedAction"].get("parametersDigest", {}).get("sha256")
        cands = [f for f, (fb, fv) in approvals.items() if isinstance(fv, dict)
                 and fv.get("actionDigest", {}).get("sha256") == digest
                 and fv.get("session") == sessions[k]["agent_session_id"]]
        named = [s for s in pred.get("inputSnapshot", []) if s.get("name") == "approval record"]
        rep.need(cands or not named, "R3", where, "inputSnapshot names an approval record, but no approval record "
                 "in the vCon fits the action and the session")
        case = "approval" if cands else "declined"
        rep.ok("R3", where, "Case %s, chosen from the vCon (%d matching approval records)" % (
            "1" if cands else "2", len(cands)))
        ap_b, f = None, None
        if cands:
            snap = [s for s in pred.get("inputSnapshot", []) if s.get("name") == "approval record"]
            rep.need(len(snap) == 1, "R4a", where, "inputSnapshot has not exactly one approval record")
            hit = [x for x in cands if vp.sha256(approvals[x][0]) == snap[0]["digest"]["sha256"]]
            rep.need(len(hit) == 1, "R4a", where, "no approval record in the vCon has the digest of inputSnapshot")
            f = hit[0]
            ap_b, rec = approvals[f]
            fa = att[f]
            rep.need("dialog" in fa, "R4a", where, "approval record without dialog")
            d = dialog[fa["dialog"]]
            rep.need(fa["dialog"] in sessions[k].get("dialog", []), "R4a", where, "answer not in the session")
            rep.need(rec.get("approvalId") == d.get("entry_id"), "R4a", where,
                     "approvalId is not the entry_id of the answer")
            who = parties[d["parties"]]
            rep.need(rec.get("approver") == who.get("uuid"), "R4a", where,
                     "approver %r is not the party of the answer (%r)" % (rec.get("approver"), who.get("uuid")))
            rep.need(who.get("type") == "person", "R4a", where, "answer not from a person")
            rep.need(rec.get("session") == sessions[k]["agent_session_id"], "R4a", where, "session differs")
            rep.need(vp.when(rec["approvedAt"]) == send_time(d), "R4a", where,
                     "approvedAt %s is not the send time of the answer %s" % (rec["approvedAt"], vp.iso(send_time(d))),
                     "approval record = dialog[%d] (entry_id %s, party %s)" % (fa["dialog"], d.get("entry_id"),
                                                                             who.get("uuid")))
            t = vp.when(tool["time"])
            rep.need(vp.when(rec["approvedAt"]) <= t, "R4b", where, "tool call before the approval")
            rep.need(t <= vp.when(rec["validUntil"]), "R4b", where,
                     "approval expired at the time of the tool call: time %s, validUntil %s" % (
                         tool["time"], rec["validUntil"]), "approvedAt <= tool call time <= validUntil")
        results = [e for e in events if e.get("type") == "tool-result" and e.get("call_id") is not None
                   and e.get("call_id") == tool.get("call_id") and k in as_list(e.get("sessions", []))]
        T = vp.iso(min(vp.when(e["time"]) for e in results)) if results else pred["decidedAt"]
        full_check(rep, "R5", where + ", T " + T, b, a, T, case, action, ap_b)
        found.append({"pred": pred, "root": root, "case": case, "approval": f, "call": j})
    return found, approvals


def check_set(rep, v, found, approvals):
    events = v.get("events", [])
    ident = {}
    for x in found:
        if x["case"] == "approval" and x["pred"]["decision"]["verdict"] == "ALLOW":
            rec = approvals[x["approval"]][1]
            ident.setdefault((rec["approvalId"], rec["actionDigest"]["sha256"], rec["session"]), set()).add(x["root"])
    for key, roots in sorted(ident.items()):
        rep.need(len(roots) == 1, "C1", "approval %s/%s" % (key[2], key[0]),
                 "%d distinct ALLOW payloads cite the same approval" % len(roots))
    rep.ok("C1", "set", "%d approvals, at most one ALLOW each" % len(ident))
    for x in found:
        if x["pred"]["decision"]["verdict"] in ("DENY", "REFUSE"):
            tool = events[x["call"]]
            where = "%s, tool call %s" % (x["pred"]["decisionId"], tool.get("call_id"))
            rep.need(tool.get("call_id") is not None, "C2", where, "tool call without call_id, cannot be checked")
            for e in events:
                if e.get("type") == "tool-result" and e.get("call_id") == tool["call_id"]:
                    ran = not (e.get("is_error") is True or e.get("status") == "error")
                    rep.need(not ran, "C2", where, "tool result %s after %s counts as executed" % (
                        e.get("entry_id"), x["pred"]["decision"]["verdict"]))
    rep.ok("C2", "set", "no executed tool result after DENY or REFUSE")
    cited = {x["approval"] for x in found if x["approval"] is not None}
    for f in sorted(approvals):
        rep.need(f in cited, "C3", "attachments[%d] (approval record)" % f, "no receipt in the vCon cites it")
    rep.ok("C3", "set", "every approval record is cited, every receipt is bound to a tool call")


def check_citing(rep, d, v, payload, a, gate):
    b = (Path(d) / "receipts" / "dec-0003.dsse.json").read_bytes()
    pred, _ = open_receipt(rep, "Z1", "citing receipt", b, gate)
    where = "citing receipt %s" % pred.get("decisionId")
    full_check(rep, "Z1", where + ", T " + CITE_TIME, b, a, CITE_TIME, "declined")
    snap = [s for s in pred.get("inputSnapshot", []) if s.get("name") == "conversation record"]
    rep.need(len(snap) == 1, "Z2", where, "inputSnapshot has not exactly one conversation record")
    rep.need(snap[0].get("mediaType") == vp.VCON_MEDIA, "Z2", where, "mediaType is not application/vcon")
    rep.need(snap[0]["digest"]["sha256"] == vp.sha256(payload), "Z2", where,
             "SHA-256 of the JWS payload is not the digest in inputSnapshot",
             "conversation record = SHA-256(JWS payload) " + vp.sha256(payload))
    for i, e in enumerate(pred.get("evidenceRefs", [])):
        td = e.get("typedDigest")
        if td and td.get("type") == "vcon":
            rep.need(td["digestAlgorithm"] == "jcs-sha256-v1" and td["digest"] == vp.sha256(vp.jcs(v))
                     and e["digest"]["sha256"] == td["digest"], "Z2", where + ", evidenceRefs[%d]" % i,
                     "typedDigest jcs-sha256-v1 does not match the RFC 8785 form of the vCon",
                     "typedDigest jcs-sha256-v1 = SHA-256(JCS(vCon)) = payload digest")
    return pred


def check_cose(rep, d, v, payload, pred, pin):
    raw = (Path(d) / "vcon.cose").read_bytes()
    where = "COSE_Sign1 signed-agent-record"
    try:
        prot, prot_b, unprot, cpayload, sig, tbs = vp.cose_sign1_open(raw)
    except ValueError as e:
        rep.fail("Z3", where, str(e))
    rep.need(prot.get(vp.COSE_ALG) == -8, "Z3", where, "alg is not EdDSA (-8)")
    rep.need(prot.get(vp.COSE_CTY) == vp.VCON_MEDIA, "Z3", where, "content type is not application/vcon")
    cwt = prot.get(vp.COSE_CWT)
    rep.need(isinstance(cwt, dict) and isinstance(cwt.get(1), str) and isinstance(cwt.get(2), str), "Z3", where,
             "CWT claims without iss and sub (label 15)")
    x5 = prot.get(vp.COSE_X5CHAIN)
    der = x5 if isinstance(x5, bytes) else (x5[0] if isinstance(x5, list) and x5 else None)
    rep.need(isinstance(der, bytes), "Z3", where, "no x5chain in the protected header")
    pk = check_cert(rep, "Z3", where, der, pin)
    rep.need(isinstance(pk, Ed25519PublicKey), "Z3", where, "certificate key is not Ed25519")
    try:
        pk.verify(sig, tbs)
    except InvalidSignature:
        rep.fail("Z3", where, "COSE_Sign1 signature does not verify")
    rep.ok("Z3", where, "COSE_Sign1 signature verifies, alg EdDSA")
    rep.need(cpayload == payload, "Z3", where, "COSE payload is not the JWS payload")
    meta = unprot.get(vp.TRACE_METADATA)
    rep.need(isinstance(meta, dict) and all(isinstance(meta.get(m), str) for m in (
        "session-id", "agent-vendor", "trace-format", "timestamp-start")), "Z3", where,
             "trace-metadata (label 100) incomplete")
    rep.need(meta["session-id"] == v["sessions"][0]["agent_session_id"], "Z3", where,
             "trace-metadata session-id is not agent_session_id")
    if "content-hash" in meta:
        rep.need(meta.get("content-hash-alg", "sha-256") == "sha-256" and meta["content-hash"] == vp.sha256(cpayload),
                 "Z3", where, "trace-metadata content-hash does not match the payload",
                 "trace-metadata content-hash = SHA-256(payload), not covered by the signature")
    refs = [e for e in pred.get("evidenceRefs", []) if e.get("relation") == "signedConversationRecord"]
    rep.need(len(refs) == 1 and refs[0]["digest"]["sha256"] == vp.sha256(raw), "Z3", where,
             "the citing receipt does not name the SHA-256 of these COSE_Sign1 bytes",
             "evidenceRefs signedConversationRecord = SHA-256(COSE_Sign1) " + vp.sha256(raw))


def main(argv=None):
    ap = argparse.ArgumentParser(description="Offline check of a signed vCon with decision receipts.")
    ap.add_argument("dir")
    ap.add_argument("--proofbundle", default="proofbundle", help="command that runs the proofbundle CLI")
    ap.add_argument("--adrverify", help="optional second checker of Section 3 of the decision receipts draft")
    ap.add_argument("--action-bytes", choices=("jcs", "none"), default="jcs",
                    help="jcs: action bytes are the RFC 8785 form of the tool input; none: not checked")
    ap.add_argument("--signed", default="vcon.signed.json", help="the JWS file in DIR to check")
    ap.add_argument("--recorder-cert-sha256", action="append",
                    help="pin a recorder certificate by its SHA-256 instead of the two pinned here (repeatable)")
    ap.add_argument("--report")
    a = ap.parse_args(argv)
    a.external = str(Path(a.dir) / "external")
    gate = Ed25519PublicKey.from_public_bytes(base64.b64decode(GATE_PUBLIC_KEY))
    pins = set(a.recorder_cert_sha256 or [RECORDER_CERT_SHA256, RECORDER_RSA_CERT_SHA256])
    rep = Report()
    try:
        v, payload = check_jws(rep, (Path(a.dir) / a.signed).read_bytes(), pins)
        check_structure(rep, v)
        found, approvals = check_receipts(rep, v, a, gate)
        check_set(rep, v, found, approvals)
        pred = check_citing(rep, a.dir, v, payload, a, gate)
        check_cose(rep, a.dir, v, payload, pred, pins)
    except Stop:
        pass
    except (KeyError, TypeError, IndexError, ValueError, AttributeError, OSError) as e:
        rep.first = {"id": "X", "where": "form", "result": "FAIL", "detail": "%s: %s" % (type(e).__name__, e)}
        rep.checks.append(rep.first)
    out = {"result": "FAIL" if rep.first else "PASS", "first_failure": rep.first, "checks": rep.checks}
    if a.report:
        Path(a.report).write_bytes((json.dumps(out, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))
    print(out["result"], "%s %s: %s" % (rep.first["id"], rep.first["where"], rep.first["detail"]) if rep.first else
          "(%d checks)" % len(rep.checks))
    return 1 if rep.first else 0


if __name__ == "__main__":
    sys.exit(main())
