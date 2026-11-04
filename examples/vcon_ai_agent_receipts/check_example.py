"""Offline check of a signed vCon that carries decision receipts.

    python check_example.py DIR [--signed FILE] [--proposal FILE] [--proofbundle CMD] [--adrverify PATH]
                                [--action-bytes jcs|none] [--report FILE]

DIR holds vcon.signed.json (JWS with EdDSA or RS256; --signed names another file in DIR, such as
vcon.signed-rs256.json), vcon.cose (COSE_Sign1), external/ (the files that url members name,
by their last path segment) and receipts/dec-0003.dsse.json (the receipt that cites the record). The
check stops at the first failure and names it; the report has no clock time and no absolute path.

The keys are pinned here and never taken from DIR: the gate key that signs decisions and the SHA-256 of
the recorder's two test certificates, one for EdDSA and one for RS256. Each receipt is also verified with `proofbundle decision verify
--strict`, and, where --adrverify names a second checker of Section 3 of
draft-gruszka-audit-decision-receipts, with that checker for Case 1 or Case 2.

The Event Objects follow draft-petrie-vcon-tool-invocation-00: a receipt names the operation by its
operation_id, the policy-decision of that operation must fit the verdict, and a disallowed operation has
no tool event at all. --proposal names the file under DIR with our proposed parameter on the
policy-decision (proposal/vcon.with-receipt-reference.unsigned.json in out/), checked as E1.

Check ids: V1 to V4 the vCon, A1 the attachments, R1 to R5 each receipt in the vCon, C1 to C3 the set,
Z1 to Z3 the citing receipt and the two signed forms, E1 the proposal file. Exit 0 PASS, 1 FAIL, 2 usage.
"""
from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import json
import os
import re
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
AI_AGENT_TYPES = {"reasoning", "system-event"}
TOOL_TYPES = {"tool-invocation", "tool-pending", "tool-progress", "tool-input", "tool-input-response", "tool-result",
              "tool-failure", "tool-error", "tool-denied", "tool-timeout", "tool-cancel"}
RESULT_TYPES = {"tool-result", "tool-failure", "tool-error", "tool-denied"}
TI_TYPES = TOOL_TYPES | {"policy-decision"}
DECISIONS = ("allowed", "permission-required", "disallowed")
#: The policy-decision values that fit a verdict of the receipt.
FITS = {"ALLOW": ("allowed", "permission-required"), "DENY": ("disallowed",), "REFUSE": ("disallowed",)}
COMMON = {"type", "time", "sessions", "party"}
CONTENT = {"mediatype", "encoding", "body", "url", "content_hash"}
PD_PARAMS = COMMON | {"decision", "policy_life", "reason", "operation", "operation_id", "attempt", "server", "tool"}
TOOL_PARAMS = COMMON | {"operation_id", "attempt"} | CONTENT | {"attachment"}
PROPOSAL_PARAMETER = "decision_receipt"
#: media_type_value_type and content_hash_value_type of the core CDDL
MEDIA_RX = re.compile(r"[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+(;.*)?")
HASH_RX = re.compile(r"[a-z0-9]+-[A-Za-z0-9_-]+")
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


def attempt_ok(v):
    return isinstance(v, int) and not isinstance(v, bool) and v >= 1


def content_form_ok(e):
    """Event content in one of the forms of vCon core file_content_type (tool-invocation-00 6.1.10): none; inline with
    encoding json (any body) or none or base64url (a string body), with mediatype; external url and content_hash;
    or redacted, content_hash alone."""
    keys = set(e) & CONTENT
    if not keys or keys == {"mediatype"}:
        return not keys
    if "mediatype" in e and not (isinstance(e["mediatype"], str) and MEDIA_RX.fullmatch(e["mediatype"])):
        return False
    if "content_hash" in e and not all(isinstance(t, str) and HASH_RX.fullmatch(t) for t in as_list(e["content_hash"])):
        return False
    if "body" in e or "encoding" in e:
        if "url" in e or "content_hash" in e or "mediatype" not in e or "body" not in e:
            return False
        if e.get("encoding") == "json":
            return True
        return e.get("encoding") in ("none", "base64url") and isinstance(e["body"], str)
    if "url" in e:
        return isinstance(e["url"], str) and "content_hash" in e
    return "content_hash" in e


def check_ti_event(rep, where, e, n_att, extra=()):
    """The parameters of tool-invocation-00 6.1.1 to 6.1.11 for one of its Event Object types (Tables 3 to 5)."""
    typ = e["type"]
    if typ == "policy-decision":
        allowed = PD_PARAMS | set(extra)
        rep.need(e.get("decision") in DECISIONS, "V4", where, "decision %r is not allowed, permission-required or "
                 "disallowed (6.1.4)" % (e.get("decision"),))
        rep.need(e.get("policy_life") in ("once", "standing"), "V4", where, "policy_life %r is not once or standing "
                 "(6.1.5)" % (e.get("policy_life"),))
        rep.need(isinstance(e.get("operation"), str), "V4", where, "operation missing (6.1.7)")
        rep.need(isinstance(e.get("server"), str) and e["server"] != "", "V4", where, "server missing (6.1.8)")
        if e["policy_life"] == "once":
            rep.need(isinstance(e.get("operation_id"), str) and e["operation_id"], "V4", where,
                     "operation_id missing in a policy-decision with policy_life once (6.1.2)")
            rep.need(attempt_ok(e.get("attempt")), "V4", where, "attempt missing or below 1 (6.1.3)")
            if e["operation"] == "tool-invocation":
                rep.need(isinstance(e.get("tool"), str) and e["tool"], "V4", where, "tool missing (6.1.9)")
        else:
            rep.fail("V4", where, "a standing policy-decision is not part of this example's profile: the example has "
                     "none, and how standing decisions for a tool and for all tools of a server combine is open (4.1)")
            rep.need("operation_id" not in e and "attempt" not in e, "V4", where,
                     "operation_id or attempt in a standing policy-decision (6.1.2, 6.1.3)")
        if "tool" in e:
            rep.need(isinstance(e["tool"], str), "V4", where, "tool is not a string (6.1.9)")
        if "reason" in e:
            rep.need(isinstance(e["reason"], str), "V4", where, "reason is not a string (6.1.6)")
    else:
        allowed = TOOL_PARAMS | ({"server", "tool"} if typ == "tool-invocation" else set())
        rep.need(isinstance(e.get("operation_id"), str) and e["operation_id"], "V4", where,
                 "operation_id missing (6.1.2)")
        rep.need(attempt_ok(e.get("attempt")), "V4", where, "attempt missing or below 1 (6.1.3)")
        if typ == "tool-invocation":
            rep.need(isinstance(e.get("server"), str) and e["server"] != "" and isinstance(e.get("tool"), str)
                     and e["tool"] != "", "V4", where, "server or tool missing in a tool-invocation (6.1.8, 6.1.9)")
            rep.need(e.get("encoding") != "json" or isinstance(e.get("body"), dict), "V4", where,
                     "the arguments of a tool-invocation are not a JSON object; this example profile takes objects only")
        rep.need(content_form_ok(e), "V4", where, "content is not inline (encoding, body, mediatype), external "
                 "(url, content_hash) or redacted (content_hash) as in vCon core (6.1.10)")
        for k in as_list(e.get("attachment", [])):
            rep.need(index(k, n_att), "V4", where, "attachment index %r invalid (6.1.11)" % (k,))
    server = e.get("server")
    if isinstance(server, str) and server.startswith("!"):
        rep.need(server == "!host", "V4", where, "server %r starts with ! and is not !host (6.1.8)" % server)
    odd = sorted(set(e) - allowed)
    rep.need(not odd, "V4", where, "parameter(s) %s not defined for %s (tool-invocation-00 6.1.1)" % (odd, typ))


def one_party(v, n):
    """The one contributing party of a text Dialog Object: a valid index, or a list of exactly one valid
    index (vCon core 4.5.4 allows both); None for anything else, such as several parties or null."""
    if isinstance(v, list):
        return v[0] if len(v) == 1 and index(v[0], n) else None
    return v if index(v, n) else None


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
    headers = []
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
        headers.append(hdr)
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
    for i, hdr in enumerate(headers):
        if "uuid" in hdr:
            rep.need(hdr["uuid"] == v.get("uuid"), "V3", "JWS signatures[%d] header uuid" % i,
                     "header uuid differs (6.2.2)")
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
        rep.need(one_party(d.get("parties"), len(parties)) is not None, "V4", where,
                 "parties does not name one valid index")
        try:
            vp.when(d.get("start"))
        except ValueError as e:
            rep.fail("V4", where, str(e))
        for k in [k for k, s in enumerate(sessions) if i in s.get("dialog", [])]:
            if "entry_id" in d:
                rep.need((k, d["entry_id"]) not in seen, "V4", where, "entry_id repeated in session %d" % k)
                seen.add((k, d["entry_id"]))
    tools = {}
    for i, e in enumerate(events):
        where = "events[%d]" % i
        if e.get("type") not in AI_AGENT_TYPES and e.get("type") not in TI_TYPES:
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
        if e["type"] in TI_TYPES:
            check_ti_event(rep, where, e, len(att))
            if "operation_id" in e and "tool" in e:
                # the server and tool of an operation are the same in its policy-decision and its invocations
                ident = tools.setdefault(e["operation_id"], (e.get("server"), e.get("tool")))
                rep.need(ident == (e.get("server"), e.get("tool")), "V4", where,
                         "operation_id %s names another tool than before (6.1.2)" % e["operation_id"])
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
    for o in sorted({e["operation_id"] for e in events if e.get("type") in TI_TYPES and "operation_id" in e}):
        for typ in ("policy-decision", "tool-invocation"):
            per = [e.get("attempt") for e in events if e.get("type") == typ and e.get("operation_id") == o]
            rep.need(len(per) == len(set(per)), "V4", "operation %s" % o,
                     "more than one %s for the same attempt (6.1.2)" % typ)
        # the first attempt is 1, each later one is one more (5.1, 6.1.3); the example records every attempt
        seen_attempts = sorted({e.get("attempt") for e in events if e.get("type") in TI_TYPES
                                and e.get("operation_id") == o and attempt_ok(e.get("attempt"))})
        rep.need(seen_attempts == list(range(1, len(seen_attempts) + 1)), "V4", "operation %s" % o,
                 "attempts %s do not start at 1 and go up by one (5.1, 6.1.3)" % seen_attempts)
        # the example records a decision for every operation, each named by a receipt (C3)
        rep.need(any(e.get("type") == "policy-decision" and e.get("policy_life") == "once" and e.get("operation_id") == o
                     for e in events), "V4", "operation %s" % o, "has no policy-decision of its own; this example "
                 "records one for every operation")
        # every event of an operation names the same party, the agent and not a person (6.1)
        named = {e.get("party") for e in events if e.get("type") in TI_TYPES and e.get("operation_id") == o}
        rep.need(len(named) == 1 and all(index(n, len(parties)) and parties[n].get("type") != "person" for n in named),
                 "V4", "operation %s" % o, "its events name parties %s, not one agent party (6.1)" % sorted(
                     named, key=str))
        # a decision for one operation precedes the attempt it names (4.1, 6.1.3)
        for d in [e for e in events if e.get("type") == "policy-decision" and e.get("operation_id") == o]:
            for j, e in enumerate(events):
                if e.get("type") == "tool-invocation" and e.get("operation_id") == o and \
                        e.get("attempt") == d.get("attempt"):
                    rep.need(vp.when(d["time"]) <= vp.when(e["time"]), "V4", "events[%d]" % j, "tool-invocation of "
                             "operation %s at %s comes before its policy-decision %s (4.1)" % (o, e["time"], d["time"]))
        # the example records every attempt: a response belongs to an invocation of the same attempt (5.1, 6.1.3)
        sent = {e.get("attempt") for e in events if e.get("type") == "tool-invocation" and e.get("operation_id") == o}
        for j, e in enumerate(events):
            if e.get("type") in TOOL_TYPES - {"tool-invocation"} and e.get("operation_id") == o:
                rep.need(e.get("attempt") in sent, "V4", "events[%d]" % j, "%s of attempt %r of operation %s has no "
                         "tool-invocation of that attempt" % (e["type"], e.get("attempt"), o))
        # a disallowed operation is not performed (Section 4), with or without a receipt that names it
        if any(e.get("type") == "policy-decision" and e.get("operation_id") == o and e.get("decision") == "disallowed"
               for e in events):
            done = [j for j, e in enumerate(events) if e.get("type") in TOOL_TYPES and e.get("operation_id") == o]
            rep.need(not done, "V4", "operation %s" % o, "disallowed, but events %s are tool events of it "
                     "(Section 4)" % done)
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
        # R2 the operation (tool-invocation-00): the policy-decision it names, and its tool-invocation
        tc = pred.get("traceContext", {})
        ks = [k for k, s in enumerate(sessions) if s.get("agent_session_id") == tc.get("traceId")]
        rep.need(len(ks) == 1, "R2", where, "traceContext.traceId %r names no session" % tc.get("traceId"))
        k = ks[0]
        op = tc.get("parentId")
        pds = [j for j, e in enumerate(events) if e.get("type") == "policy-decision" and e.get("policy_life") == "once"
               and e.get("operation_id") == op and k in as_list(e.get("sessions", []))]
        rep.need(len(pds) == 1, "R2", where, "traceContext.parentId %r names no single policy-decision of the session"
                 % op)
        pd = events[pds[0]]
        rep.need(pd.get("operation") == "tool-invocation", "R2", where,
                 "policy-decision of operation %s is not for a tool-invocation" % op)
        verdict = pred["decision"]["verdict"]
        rep.need(pd.get("decision") in FITS.get(verdict, ()), "R2", where,
                 "policy-decision %r of operation %s does not fit the verdict %s" % (pd.get("decision"), op, verdict))
        agent = parties[pd["party"]]
        rep.need(agent.get("uuid") == pred["agent"]["id"] and "agent_meta" in agent, "R2", where,
                 "agent.id %r is not the party of the policy-decision" % pred["agent"]["id"])
        principal = pred.get("principal", {}).get("id")
        people = [p for p in parties if p.get("type") == "person" and p.get("uuid") == principal]
        rep.need(len(people) == 1, "R2", where, "principal.id %r is not the uuid of one person in the vCon" % principal)
        # the invocation and the results of the attempt the decision precedes (6.1.3), by the agent of the decision
        invs = [j for j, e in enumerate(events) if e.get("type") == "tool-invocation" and e.get("operation_id") == op
                and e.get("attempt") == pd.get("attempt") and k in as_list(e.get("sessions", []))]
        tool, action = None, None
        if pd.get("decision") == "disallowed":
            rep.need(vp.when(pd["time"]) == vp.when(pred["decidedAt"]), "R2", where,
                     "decidedAt %s is not the time of the policy-decision %s" % (pred["decidedAt"], pd["time"]))
            rep.ok("R2", where, "operation %s disallowed; its arguments are not in the vCon (tool-invocation-00 "
                   "6.1.1), parametersDigest is bound by the receipt alone" % op)
        else:
            rep.need(len(invs) == 1, "R2", where, "operation %s has no single tool-invocation of attempt %r in the "
                     "session" % (op, pd.get("attempt")))
            tool = events[invs[0]]
            rep.need(tool.get("encoding") == "json" and "body" in tool, "R2", where,
                     "the arguments of operation %s are not inline JSON" % op)
            action = vp.jcs(tool["body"]) if a.action_bytes == "jcs" else None
            if action is not None:
                rep.need(vp.sha256(action) == pred["proposedAction"]["parametersDigest"]["sha256"], "R2", where,
                         "SHA-256 of the RFC 8785 form of the arguments of events[%d] is not parametersDigest"
                         % invs[0], "events[%d] (operation %s), parametersDigest = SHA-256(JCS(arguments))"
                         % (invs[0], op))
            else:
                rep.ok("R2", where, "events[%d] (operation %s) bound by operation_id only; action bytes not checked"
                       % (invs[0], op))
        # R3 the case, from the vCon
        digest = pred["proposedAction"].get("parametersDigest", {}).get("sha256")
        cands = [f for f, (fb, fv) in approvals.items() if isinstance(fv, dict)
                 and fv.get("actionDigest", {}).get("sha256") == digest
                 and fv.get("session") == sessions[k]["agent_session_id"]]
        named = [s for s in pred.get("inputSnapshot", []) if s.get("name") == "approval record"]
        rep.need(cands or not named, "R3", where, "inputSnapshot names an approval record, but no approval record "
                 "in the vCon fits the action and the session")
        case = "approval" if cands else "declined"
        if verdict == "ALLOW":
            want = "permission-required" if cands else "allowed"
            rep.need(pd.get("decision") == want, "R3", where, "operation %s %s, but its policy-decision is %r, not %r"
                     % (op, "was approved by a person" if cands else "had no approval", pd.get("decision"), want))
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
            who = parties[one_party(d["parties"], len(parties))]
            rep.need(rec.get("approver") == who.get("uuid"), "R4a", where,
                     "approver %r is not the party of the answer (%r)" % (rec.get("approver"), who.get("uuid")))
            rep.need(who.get("type") == "person", "R4a", where, "answer not from a person")
            rep.need(rec.get("session") == sessions[k]["agent_session_id"], "R4a", where, "session differs")
            rep.need(vp.when(rec["approvedAt"]) == send_time(d), "R4a", where,
                     "approvedAt %s is not the send time of the answer %s" % (rec["approvedAt"], vp.iso(send_time(d))),
                     "approval record = dialog[%d] (entry_id %s, party %s)" % (fa["dialog"], d.get("entry_id"),
                                                                             who.get("uuid")))
            rep.need(tool is not None, "R4b", where, "approved operation %s was not invoked" % op)
            t = vp.when(tool["time"])
            # the order of Figure 1 of tool-invocation-00: decision, then the grant, then the invocation
            rep.need(vp.when(pd["time"]) <= vp.when(rec["approvedAt"]) <= vp.when(pred["decidedAt"]) <= t, "R4b",
                     where, "not in the order policy-decision %s, approval %s, decidedAt %s, tool-invocation %s" % (
                         pd["time"], rec["approvedAt"], pred["decidedAt"], tool["time"]),
                     "policy-decision <= approvedAt <= decidedAt <= tool-invocation (Figure 1)")
            # every attempt of the approved operation, not only the one the decision precedes
            for j, e in enumerate(events):
                if e.get("type") == "tool-invocation" and e.get("operation_id") == op:
                    rep.need(vp.when(rec["approvedAt"]) <= vp.when(e["time"]) <= vp.when(rec["validUntil"]), "R4b",
                             where, "events[%d], attempt %r of operation %s, at %s is not between the approval %s and "
                             "validUntil %s" % (j, e.get("attempt"), op, e["time"], rec["approvedAt"],
                                                rec["validUntil"]))
            rep.ok("R4b", where, "approvedAt <= every tool-invocation of the operation <= validUntil")
        if tool is not None:
            for j, e in enumerate(events):
                if e.get("type") == "tool-invocation" and e.get("operation_id") == op and action is not None:
                    rep.need(e.get("encoding") == "json" and "body" in e and vp.sha256(vp.jcs(e["body"])) ==
                             pred["proposedAction"]["parametersDigest"]["sha256"], "R2", where, "events[%d], attempt "
                             "%r of operation %s, has other arguments than the decision" % (j, e.get("attempt"), op))
                if e.get("type") == "tool-invocation" and e.get("operation_id") == op:
                    rep.need(vp.when(pd["time"]) <= vp.when(pred["decidedAt"]) <= vp.when(e["time"]), "R2", where,
                             "events[%d], attempt %r of operation %s, at %s comes before its policy-decision %s or "
                             "the decision %s" % (j, e.get("attempt"), op, e["time"], pd["time"], pred["decidedAt"]))
        results = [e for e in events if e.get("type") in RESULT_TYPES and e.get("operation_id") == op
                   and e.get("attempt") == pd.get("attempt") and k in as_list(e.get("sessions", []))]
        for j, e in enumerate(events):
            if e.get("type") in TOOL_TYPES and e.get("operation_id") == op:
                rep.need(k in as_list(e.get("sessions", [])), "R2", where, "events[%d] %s of operation %s is not in the "
                         "session %d of the receipt" % (j, e["type"], op, k))
                rep.need(e.get("party") == pd.get("party"), "R2", where, "events[%d] %s of operation %s names party %r, "
                         "not the agent %r of its policy-decision (6.1)" % (j, e["type"], op, e.get("party"),
                                                                           pd.get("party")))
        T = vp.iso(min(vp.when(e["time"]) for e in results)) if results else pred["decidedAt"]
        full_check(rep, "R5", where + ", T " + T, b, a, T, case, action, ap_b)
        found.append({"pred": pred, "root": root, "case": case, "approval": f, "op": op, "session": k, "bytes": b,
                      "attachment": i})
    return found, approvals


def walk(value, path):
    """Every JSON value under `value` with its path, the value itself first."""
    yield path, value
    if isinstance(value, dict):
        for k, x in value.items():
            yield "%s key %r" % (path, k[:40]), k
            yield from walk(x, "%s.%s" % (path, k))
    elif isinstance(value, list):
        for i, x in enumerate(value):
            yield from walk(x, "%s[%d]" % (path, i))


def candidates(v):
    """Every JSON value of the vCon with its path, and the decoded bytes of each base64url body as text, so an encoded
    copy is seen as well as a plain one."""
    for path, value in walk(v, "vCon"):
        yield path, value
        if isinstance(value, dict) and value.get("encoding") == "base64url" and isinstance(value.get("body"), str):
            try:
                yield path + ".body (base64url decoded)", vp.b64u_dec(value["body"]).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                pass


def embedded(text):
    """Every JSON object or array that a string holds, whole or inside surrounding text, as parsed values."""
    dec = json.JSONDecoder()
    for i, c in enumerate(text):
        if c in "{[":
            try:
                yield dec.raw_decode(text, i)[0]
            except ValueError:
                pass


def digests_of(value):
    """SHA-256 of the RFC 8785 form of an object or array, or of each one a string holds, whole or embedded."""
    found = [value] if isinstance(value, (dict, list)) else list(embedded(value)) if isinstance(value, str) else []
    out = set()
    for x in found:
        try:
            out.add(vp.sha256(vp.jcs(x)))
        except (TypeError, ValueError):
            pass
    return out


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
            where = "%s, operation %s" % (x["pred"]["decisionId"], x["op"])
            # operation_id names one operation in the whole vCon (6.1.2), whatever sessions an event names
            for j, e in enumerate(events):
                if e.get("type") in TOOL_TYPES and e.get("operation_id") == x["op"]:
                    rep.fail("C2", where, "events[%d] %s after %s: the operation was performed" % (
                        j, e["type"], x["pred"]["decision"]["verdict"]))
            # an exact copy of the denied arguments, as a JSON value or as JSON text, anywhere in the vCon
            # (tool-invocation-00 6.1.1); a paraphrase is not detectable from a digest
            denied = x["pred"]["proposedAction"]["parametersDigest"]["sha256"]
            hits = [path for path, value in candidates(v) if denied in digests_of(value)]
            rep.need(not hits, "C2", where, "%s holds the arguments of the denied operation (their SHA-256 is the "
                     "parametersDigest of the receipt)" % ", ".join(hits),
                     "no JSON value or JSON text in the vCon has the digest of the denied arguments")
    rep.ok("C2", "set", "no tool event and no exact copy of the arguments of an operation after its DENY or REFUSE")
    # every decision for one operation in this example is named by a receipt, so none escapes R2 to R5
    named = {x["op"] for x in found}
    for j, e in enumerate(events):
        if e.get("type") == "policy-decision" and e.get("policy_life") == "once":
            rep.need(e.get("operation_id") in named, "C3", "events[%d]" % j, "policy-decision of operation %s is named "
                     "by no receipt" % e.get("operation_id"))
    cited = {x["approval"] for x in found if x["approval"] is not None}
    for f in sorted(approvals):
        rep.need(f in cited, "C3", "attachments[%d] (approval record)" % f, "no receipt in the vCon cites it")
    rep.ok("C3", "set", "every approval record is cited, every receipt is bound to a policy-decision")
    rep.need(len(approvals) == 1 and len(found) == 2 and
             sorted(x["pred"]["decision"]["verdict"] for x in found) == ["ALLOW", "DENY"],
             "C3", "receipt inventory",
             "expected one approval record and exactly one ALLOW and one DENY decision receipt",
             "one approval record, one ALLOW and one DENY decision receipt")


def check_proposal(rep, d, rel, v, found, att, external):
    """E1, our proposal: the file is the vCon with one parameter added to each policy-decision that a receipt names,
    and that parameter references exactly the bytes of that receipt."""
    where = "proposal " + rel
    try:
        pv = vp.strict_json((Path(d) / rel).read_bytes())
    except (OSError, ValueError) as e:
        rep.fail("E1", where, "not readable: %s" % e)
    rep.need(isinstance(pv, dict) and isinstance(pv.get("events"), list) and len(pv["events"]) == len(v["events"]),
             "E1", where, "not the vCon with the same Event Objects")
    base = json.loads(json.dumps(pv))
    for e in base["events"]:
        if isinstance(e, dict) and e.get("type") == "policy-decision":
            e.pop(PROPOSAL_PARAMETER, None)
    rep.need(vp.jcs(base) == vp.jcs(v), "E1", where, "differs from the signed vCon in more than %s" % PROPOSAL_PARAMETER,
             "only %s added, the rest is the signed vCon" % PROPOSAL_PARAMETER)
    by_op = {x["op"]: x for x in found}
    for j, e in enumerate(pv["events"]):
        if e.get("type") != "policy-decision" or PROPOSAL_PARAMETER not in e:
            continue
        w = "%s events[%d]" % (where, j)
        check_ti_event(rep, w, e, len(att), extra=(PROPOSAL_PARAMETER,))
        ref = e[PROPOSAL_PARAMETER]
        rep.need(isinstance(ref, dict) and not set(ref) - {"url", "content_hash", "mediatype"} and "content_hash" in ref,
                 "E1", w, "%s is not an object of url, content_hash and mediatype" % PROPOSAL_PARAMETER)
        rep.need((("mediatype" not in ref) or (isinstance(ref["mediatype"], str) and MEDIA_RX.fullmatch(ref["mediatype"])))
                 and all(isinstance(t, str) and HASH_RX.fullmatch(t) for t in as_list(ref["content_hash"])),
                 "E1", w, "mediatype is not a media type, or a content_hash token is malformed")
        x = by_op.get(e.get("operation_id"))
        rep.need(x is not None, "E1", w, "no receipt names operation %s" % e.get("operation_id"))
        sha512 = [t[7:] for t in as_list(ref["content_hash"]) if isinstance(t, str) and t.startswith("sha512-")]
        rep.need(sha512 == [vp.b64u(hashlib.sha512(x["bytes"]).digest())], "E1", w,
                 "content_hash is not the sha512 of the receipt of operation %s" % e["operation_id"],
                 "references the receipt %s by sha512" % x["pred"]["decisionId"])
        for t in as_list(ref["content_hash"]):
            if t.startswith("sha256-"):
                rep.need(t[7:] == vp.b64u(hashlib.sha256(x["bytes"]).digest()), "E1", w,
                         "the sha256 token is not the sha256 of the receipt of operation %s" % e["operation_id"])
        if "url" in ref:
            rep.need(ref["url"] == att[x["attachment"]].get("url"), "E1", w, "url is not the url of the receipt")
    for x in found:
        if x["pred"]["decision"]["verdict"] in ("DENY", "REFUSE"):
            denied = x["pred"]["proposedAction"]["parametersDigest"]["sha256"]
            hits = [path for path, value in candidates(pv) if denied in digests_of(value)]
            rep.need(not hits, "E1", where, "%s holds the arguments of the denied operation %s" % (", ".join(hits),
                                                                                                x["op"]))
    named = {e.get("operation_id") for e in pv["events"] if e.get("type") == "policy-decision"
             and PROPOSAL_PARAMETER in e}
    rep.need(named == set(by_op), "E1", where, "not every receipt is referenced from its policy-decision")


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
    ap.add_argument("--proposal", help="the file in DIR with our proposed parameter on the policy-decision (E1)")
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
        if a.proposal:
            check_proposal(rep, a.dir, a.proposal, v, found, v.get("attachments", []), a.external)
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
