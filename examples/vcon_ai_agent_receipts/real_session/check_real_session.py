"""Offline check of the recorded-session example.

    python check_real_session.py [DIR] [--proofbundle CMD] [--report FILE]

DIR holds vcon.unsigned.json as make_real_session.py writes it (default: out/ next to this file). The check stops at
the first failure and names it. Check ids:

K1 each attachment with the purpose "decision receipt" verifies with `proofbundle decision verify --strict` against the
   guard's demonstration key in gate.pub.hex, pinned here by its SHA-256, for the audience b7vcon-demo-observer, at the
   first whole second after its decidedAt.
K2 its traceContext names the session (traceId is the agent_session_id) and one call (parentId is the tool_use id; the
   operation_id the converter derives from it names exactly one policy-decision of that session). Together the
   receipts name every policy-decision of the session, each once, so two receipts for the same call do not pass as the
   two receipts of the session.
K3 the verdict is ESCALATE or DENY and the policy-decision fits it (ESCALATE permission-required, DENY disallowed),
   agent.id is the agent party of
   that decision, principal.id the person, and decisionMaker.id the party that contributed the attachment.
K4 for ESCALATE, the call stands once, at or after its decision, and the SHA-256 of the --body argument of its gh
   command, read with shlex in POSIX mode, is parametersDigest; for DENY, no tool event of the operation stands in the
   vCon, and no JSON value in it equals the denied arguments the transcript holds.
K5 what the guard told the agent for each operation, next to the verdict it signed. This is reported as an observation,
   not as a pass or a fail: in this session the note to the agent begins with NOT MEASURED where the receipt says
   ESCALATE (finding GF-E001 of the guard).

Exit 0 PASS, 1 FAIL. The report has no clock time and no absolute path.
"""
from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import json
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import claude_jsonl_to_vcon as conv  # noqa: E402

GATE_KEY_FILE_SHA256 = "a200f5f1ee3da0d20144150df9dc1ba005926b7d948db7194aeeb411246eed96"
AUDIENCE = "b7vcon-demo-observer"
FITS = {"ESCALATE": "permission-required", "DENY": "disallowed"}
TOOL_TYPES = {"tool-invocation", "tool-result", "tool-failure", "tool-error", "tool-denied"}


class Stop(Exception):
    pass


class Report:
    def __init__(self):
        self.checks, self.first, self.observations = [], None, []

    def ok(self, cid, where, detail=""):
        self.checks.append({"id": cid, "where": where, "result": "PASS", "detail": detail})

    def need(self, cond, cid, where, failure, success=""):
        if not cond:
            self.first = {"id": cid, "where": where, "result": "FAIL", "detail": failure}
            self.checks.append(self.first)
            raise Stop()
        self.ok(cid, where, success)


def gate_key(rep) -> str:
    raw = (HERE / "gate.pub.hex").read_bytes()
    rep.need(hashlib.sha256(raw).hexdigest() == GATE_KEY_FILE_SHA256, "K1", "gate.pub.hex",
             "the key file is not the pinned demonstration key", "pinned demonstration key")
    return base64.b64encode(bytes.fromhex(raw.decode("ascii").strip())).decode("ascii")


def whole_second_after(t: str) -> str:
    d = datetime.datetime.fromisoformat(t.replace("Z", "+00:00"))
    return (d.replace(microsecond=0) + datetime.timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")


def verify(rep, where, env: dict, pub: str, cmd: str):
    p = json.loads(base64.b64decode(env["payload"]))["predicate"]
    t = whole_second_after(p["decidedAt"])
    with tempfile.TemporaryDirectory() as td:
        f = os.path.join(td, "receipt.json")
        Path(f).write_text(json.dumps(env), encoding="utf-8")
        r = subprocess.run(cmd.split() + ["decision", "verify", "--pub", pub, "--strict", "--aud", AUDIENCE,
                                          "--verification-time", t, "--json", f], capture_output=True, check=False)
    try:
        errors = json.loads(r.stdout).get("errors", [])
    except ValueError:
        errors = ["no JSON output"]
    rep.need(r.returncode == 0, "K1", where, "proofbundle decision verify exit %d: %s" % (r.returncode, errors),
             "proofbundle decision verify --strict --aud %s --verification-time %s, exit 0" % (AUDIENCE, t))
    return p


def check(v: dict, transcript_lines: list, cmd: str, rep: Report):
    pub = gate_key(rep)
    parties, sessions, events = v["parties"], v["sessions"], v["events"]
    rep.need(len(sessions) == 1, "K2", "sessions", "this example has one session")
    sid = sessions[0]["agent_session_id"]
    found = [(i, a) for i, a in enumerate(v.get("attachments", [])) if a.get("purpose") == "decision receipt"]
    rep.need(len(found) == 2, "K1", "attachments", "expected the two receipts of the session, found %d" % len(found))
    denied_inputs, named = [], []
    for i, a in found:
        where = "attachments[%d] %s" % (i, a.get("filename"))
        rep.need(a.get("encoding") == "json" and isinstance(a.get("body"), dict), "K1", where, "receipt not inline JSON")
        p = verify(rep, where, a["body"], pub, cmd)
        tc = p["traceContext"]
        rep.need(tc.get("traceId") == sid, "K2", where, "traceId %r is not the session %r" % (tc.get("traceId"), sid))
        op = conv.operation_id(sid, tc["parentId"])
        pds = [j for j, e in enumerate(events) if e.get("type") == "policy-decision" and e.get("operation_id") == op]
        rep.need(len(pds) == 1, "K2", where, "call %s names no single policy-decision" % tc["parentId"],
                 "call %s is operation %s" % (tc["parentId"], op))
        named.append(op)
        pd = events[pds[0]]
        verdict = p["decision"]["verdict"]
        rep.need(verdict in FITS, "K3", where, "verdict %r is neither ESCALATE nor DENY" % verdict)
        rep.need(pd.get("decision") == FITS[verdict], "K3", where,
                 "policy-decision %r does not fit the verdict %s" % (pd.get("decision"), verdict))
        rep.need(parties[pd["party"]].get("uuid") == p["agent"]["id"], "K3", where, "agent.id is not the agent party")
        rep.need([x.get("uuid") for x in parties if x.get("type") == "person"] == [p["principal"]["id"]], "K3", where,
                 "principal.id is not the one person of the vCon")
        rep.need(parties[a["party"]].get("uuid") == p["decisionMaker"]["id"], "K3", where,
                 "decisionMaker.id is not the party that contributed the receipt",
                 "verdict %s, decision %s, agent, person and guard as named" % (verdict, pd["decision"]))
        tools = [e for e in events if e.get("type") in TOOL_TYPES and e.get("operation_id") == op]
        if verdict == "ESCALATE":
            calls = [e for e in tools if e["type"] == "tool-invocation"]
            rep.need(len(calls) == 1, "K4", where, "the escalated call does not stand exactly once")
            rep.need(conv._when(calls[0]["time"]) >= conv._when(pd["time"]), "K4", where,
                     "the call stands before its decision")
            argv = shlex.split(calls[0]["body"]["command"], posix=True)
            rep.need(argv[:3] == ["gh", "pr", "comment"] and argv.count("--body") == 1, "K4", where,
                     "the call is not one gh pr comment with one --body")
            body = argv[argv.index("--body") + 1].encode("utf-8")
            rep.need(hashlib.sha256(body).hexdigest() == p["proposedAction"]["parametersDigest"]["sha256"], "K4", where,
                     "SHA-256 of the --body argument is not parametersDigest",
                     "parametersDigest = SHA-256 of the --body argument of the call")
        else:
            rep.need(not tools, "K4", where, "the denied operation has tool events %s" % [e["type"] for e in tools])
            for raw in transcript_lines:
                for blk in (json.loads(raw).get("message") or {}).get("content") or []:
                    if isinstance(blk, dict) and blk.get("type") == "tool_use" and blk.get("id") == tc["parentId"]:
                        denied_inputs.append(blk.get("input"))
            rep.ok("K4", where, "no tool event of the denied operation; the receipt names its arguments by %s, "
                   "not by a digest" % json.dumps(p["proposedAction"].get("parametersRef")))
        notes = [e for e in events if e.get("type") == "system-event" and e.get("event_type") == "hook_additional_context"
                 and (e.get("data") or {}).get("operation_id") == op]
        text = " ".join(str(x) for n in notes for x in conv_list(n["data"].get("content")))
        rep.observations.append({"id": "K5", "operation": op, "verdict": verdict,
                                 "note_to_agent_begins": text[:60]})
    decided = [e.get("operation_id") for e in events if e.get("type") == "policy-decision"]
    rep.need(sorted(named) == sorted(decided) and len(set(named)) == len(named), "K2", "receipts",
             "the receipts name the calls %s, the session decided the calls %s; each must be named by one receipt"
             % (sorted(named), sorted(decided)),
             "the %d receipts name the %d policy-decisions of the session, each once" % (len(named), len(decided)))
    keys = {conv.json_key(x) for x in denied_inputs if isinstance(x, dict)}
    rep.need(not (conv.json_keys(v)[1] & keys), "K4", "vCon", "a JSON value equals the denied arguments",
             "no JSON value in the vCon equals the denied arguments")


def conv_list(x):
    return x if isinstance(x, list) else [x]


def main(argv=None):
    ap = argparse.ArgumentParser(description="Offline check of the recorded-session example.")
    ap.add_argument("dir", nargs="?", default=str(HERE / "out"))
    ap.add_argument("--proofbundle", default="proofbundle", help="command that runs the proofbundle CLI")
    ap.add_argument("--report")
    a = ap.parse_args(argv)
    rep = Report()
    try:
        v = json.loads((Path(a.dir) / "vcon.unsigned.json").read_text(encoding="utf-8"))
        lines = (HERE / "session.jsonl").read_text(encoding="utf-8").splitlines()
        check(v, lines, a.proofbundle, rep)
    except Stop:
        pass
    except (KeyError, TypeError, IndexError, ValueError, OSError) as e:
        rep.first = {"id": "X", "where": "form", "result": "FAIL", "detail": "%s: %s" % (type(e).__name__, e)}
        rep.checks.append(rep.first)
    out = {"result": "FAIL" if rep.first else "PASS", "first_failure": rep.first, "checks": rep.checks,
           "observations": rep.observations}
    if a.report:
        Path(a.report).write_bytes((json.dumps(out, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))
    print(out["result"], "%s %s: %s" % (rep.first["id"], rep.first["where"], rep.first["detail"]) if rep.first else
          "(%d checks)" % len(rep.checks))
    for o in rep.observations:
        print("observation", o["verdict"], "note to the agent begins:", o["note_to_agent_begins"])
    return 1 if rep.first else 0


if __name__ == "__main__":
    sys.exit(main())
