"""Producer of the recorded-session example: a real Claude Code session behind the proofbundle guard, and the two
decision receipts the guard signed in it, into one unsigned vCon.

    python make_real_session.py [--out out]

Inputs, all in this folder and unchanged since the recording:

- session.jsonl, 12 lines derived from the transcript of the session (what was dropped is listed in README.md);
- receipts/*.json, the two decision receipts the guard signed in the session, a DSSE envelope each;
- gate.pub.hex, the public half of the guard's demonstration key, as the session wrote it.

1. The transcript holds no permission decision of its own; the guard's verdict is in its receipts. Each receipt names
   its call by traceContext.parentId, the tool_use id. Its verdict is handed to the converter of the synthetic example
   (../claude_jsonl_to_vcon.py) as the permissionDecision of that call's result line, in memory only: ESCALATE as a
   person's acceptance, because the call ran after the person approved it in the dialog, DENY as a rejection. The
   transcript file is not changed. Every receipt names one call with a result line, and every call the transcript
   names, by a tool_use, a tool_result or a hook message of the guard, is named by one receipt.
2. The converter writes the operations of tool-invocation-00: a policy-decision before each call, the call and its
   result for the escalated comment, and for the denied push neither its arguments nor its result.
3. The guard's hook messages to the person and to the agent are attachment lines in the transcript, which the converter
   does not read. They are added as system-event Event Objects of the ai_agent extension, contributed by the guard
   party and naming the operation they belong to, so the record shows what the agent was told next to what the
   guard signed.
4. The guard becomes a party, and both receipts are attached inline with the purpose "decision receipt".

Standard library and the helpers of the synthetic example. Deterministic: the same inputs give the same bytes.
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import claude_jsonl_to_vcon as conv  # noqa: E402

SESSION = HERE / "session.jsonl"
RECEIPTS = HERE / "receipts"
#: The verdict of a receipt as the permissionDecision the converter reads on the result line of that call.
DECISION_OF = {"ESCALATE": {"decision": "accept", "source": "user"}, "DENY": {"decision": "reject", "source": "hook"}}
HOOK_TYPES = ("hook_system_message", "hook_additional_context")
PARTIES = {"user_name": "operator", "agent_name": "coding agent", "model_provider": "anthropic"}


def predicate(env: dict) -> dict:
    return json.loads(base64.b64decode(env["payload"]))["predicate"]


def receipts() -> list[tuple[str, bytes, dict]]:
    """(file name, file bytes, predicate) of each receipt, in the order of decidedAt."""
    out = []
    for p in sorted(RECEIPTS.glob("*.json")):
        b = p.read_bytes()
        out.append((p.name, b, predicate(json.loads(b))))
    return sorted(out, key=lambda r: r[2]["decidedAt"])


def one(values: set, what: str):
    if len(values) != 1:
        raise ValueError("expected one %s across the receipts, found %s" % (what, sorted(values)))
    return next(iter(values))


def build():
    lines = SESSION.read_text(encoding="utf-8").splitlines()
    recs = receipts()
    verdict_of = {r[2]["traceContext"]["parentId"]: r[2]["decision"]["verdict"] for r in recs}
    if len(verdict_of) != len(recs):
        raise ValueError("two receipts name the same call")
    for v in verdict_of.values():
        if v not in DECISION_OF:
            raise ValueError("a verdict this example does not map: %r" % v)
    # 1. the verdict of each receipt as the permissionDecision of its call's result line, in memory only
    fed, hooks, seen = [], [], set()
    for raw in lines:
        e = json.loads(raw)
        if e.get("type") == "attachment" and (e.get("attachment") or {}).get("type") in HOOK_TYPES:
            hooks.append(e)
        content = (e.get("message") or {}).get("content")
        results = [b for b in content if isinstance(b, dict) and b.get("type") == "tool_result"] \
            if isinstance(content, list) else []
        named = [b["tool_use_id"] for b in results if b.get("tool_use_id") in verdict_of]
        if named:
            if len(results) != 1:
                raise ValueError("a result line with several tool results; the decision would be ambiguous")
            e = dict(e, permissionDecision=dict(DECISION_OF[verdict_of[named[0]]]))
            seen.add(named[0])
            raw = json.dumps(e, ensure_ascii=False)
        fed.append(raw)
    if seen != set(verdict_of):
        raise ValueError("a receipt names a call with no result line in the transcript: %s" % sorted(set(verdict_of) - seen))
    # and the other direction: every call the transcript names is named by a receipt, wherever it names one: a tool_use
    # by its id, a tool_result by its tool_use_id, a hook message of the guard by its toolUseID
    calls = set()
    for raw in lines:
        e = json.loads(raw)
        content = (e.get("message") or {}).get("content")
        for b in content if isinstance(content, list) else []:
            if isinstance(b, dict) and b.get("type") == "tool_use":
                calls.add(b.get("id"))
            elif isinstance(b, dict) and b.get("type") == "tool_result":
                calls.add(b.get("tool_use_id"))
        a = e.get("attachment")
        if isinstance(a, dict) and "toolUseID" in a:
            calls.add(a.get("toolUseID"))
    if calls != set(verdict_of):
        raise ValueError("a call of the transcript is named by no receipt: %s"
                         % sorted(str(c) for c in calls - set(verdict_of)))
    agent = one({r[2]["agent"]["id"] for r in recs}, "agent.id")
    person = one({r[2]["principal"]["id"] for r in recs}, "principal.id")
    gate = one({r[2]["decisionMaker"]["id"] for r in recs}, "decisionMaker.id")
    # 2. the conversion of the synthetic example, unchanged
    vcon, report = conv.convert(fed, user_id=person, agent_id=agent, **PARTIES)
    sid = vcon["sessions"][0]["agent_session_id"]
    # 3. the guard as a party, its hook messages as system-event Event Objects
    vcon["parties"].append({"name": "proofbundle guard, demonstration key", "type": "bot", "uuid": gate})
    g = len(vcon["parties"]) - 1
    for e in hooks:
        a = e["attachment"]
        ev = {"type": "system-event", "time": e["timestamp"], "sessions": 0, "party": g, "event_type": a["type"],
              "data": {"hook": a.get("hookName"), "content": a.get("content")}}
        if isinstance(a.get("toolUseID"), str):
            ev["data"]["operation_id"] = conv.operation_id(sid, a["toolUseID"])
        vcon["events"].append(ev)
    vcon["events"].sort(key=lambda ev: conv._when(ev["time"]))
    # 4. both receipts inline
    vcon["attachments"] = [
        {"purpose": "decision receipt", "start": p["decidedAt"], "party": g, "session": 0,
         "mediatype": "application/json", "filename": name, "encoding": "json", "body": json.loads(b)}
        for name, b, p in recs]
    # the last guard of the converter, again over the whole record: no JSON copy of the denied arguments
    denied = [blk["input"] for raw in lines for blk in ((json.loads(raw).get("message") or {}).get("content") or [])
              if isinstance(blk, dict) and blk.get("type") == "tool_use" and verdict_of.get(blk.get("id")) == "DENY"]
    if conv.json_keys(vcon)[1] & {conv.json_key(x) for x in denied}:
        raise ValueError("the vCon would hold the arguments of the denied call as a JSON value")
    report["receipts"] = {name: {"verdict": p["decision"]["verdict"], "call": p["traceContext"]["parentId"],
                                 "operation_id": conv.operation_id(sid, p["traceContext"]["parentId"])}
                          for name, _b, p in recs}
    report["hook_messages"] = len(hooks)
    return vcon, report


def pretty(v) -> bytes:
    return (json.dumps(v, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def files() -> dict:
    vcon, report = build()
    return {"vcon.unsigned.json": pretty(vcon), "conversion-report.json": pretty(report)}


def main():
    ap = argparse.ArgumentParser(description="Write the recorded-session example.")
    ap.add_argument("--out", default=str(HERE / "out"))
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    for rel, data in files().items():
        (out / rel).write_bytes(data)
    print("wrote", out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
