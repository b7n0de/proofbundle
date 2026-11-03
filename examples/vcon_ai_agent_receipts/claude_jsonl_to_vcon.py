"""Convert one Claude Code session transcript (JSONL) into an unsigned vCon with the tool-invocation extension.

    python claude_jsonl_to_vcon.py SESSION.jsonl OUT.json [--report REPORT.json]
        [--user-id ID] [--user-name NAME] [--agent-id ID] [--agent-name NAME] [--model-provider NAME]

Tool use follows draft-petrie-vcon-tool-invocation-00 on vCon core -05: a policy-decision Event Object
before an operation, a tool-invocation Event Object for the request sent to the tool, and the response
Event Objects, all linked by an operation_id. What tool-invocation-00 does not define is taken from the
ai_agent extension, draft-birkholz-vcon-ai-agent-extension-00: the agent party's agent_meta, the session's
agent_session_id, environment and format, model_id and token_usage of a Dialog Object, entry_id and
parent_id of Dialog Objects and of the reasoning and system-event Event Objects, and those two Event Object
types. Standard library only. The output is deterministic for a given input and options.

Mapping, per line of the transcript:

- "user" or "assistant" text (a string content or a "text" block) becomes a "text" Dialog Object. The
  user line is contributed by party 0, the assistant line by party 1 with model_id; parties is written
  as a list of that one index, [0] or [1] (vCon core 4.5.4 allows a number or a list). token_usage is
  set once per message id, on its first text Dialog Object.
- a "tool_use" block is one operation. Its operation_id is assigned here, derived from the session id and
  the block id, and is not the block id itself (tool-invocation-00 6.1.2). Every operation has attempt 1;
  a transcript line carries no retry of the same request.
- when the "tool_result" line of that block carries a permissionDecision, a "policy-decision" Event
  Object comes first, with policy_life "once", operation "tool-invocation", server "!host" (the tools of
  Claude Code are provided by the host) and tool = the block's name. Its decision is "disallowed" for
  decision "reject", "permission-required" for decision "accept" with source "user" (a person granted
  it), and "allowed" for any other "accept". For "disallowed", the text of the tool result, the host's
  refusal, becomes the reason.
- an operation that is not disallowed gets a "tool-invocation" Event Object with the block's input as
  JSON content, and its "tool_result" block becomes a "tool-result" Event Object, or "tool-failure" when
  is_error is true (tool-invocation-00 Appendix A). A disallowed operation gets neither: its arguments
  are not recorded anywhere in the vCon (tool-invocation-00 6.1.1), and its tool result is the host's
  refusal, not a response of the tool.
- the policy-decision carries the time of the tool_use line, when the agent asked for the operation. The
  tool-invocation carries the same time, unless the decision is "permission-required": then the request was
  sent only after the grant (tool-invocation-00 Figure 1), and it carries the time of the tool result's
  line, the latest time at which it was sent. The transcript has no time of its own for sending. The
  tool-result carries the time of its own line.
- a "thinking" block becomes a "reasoning" Event Object with its text; its signature is not carried.
  A "redacted_thinking" block becomes a "reasoning" Event Object with empty content and the data in
  encrypted.
- a "system" line becomes a "system-event" Event Object with event_type = its subtype.
- entry_id is the line uuid and parent_id its parentUuid, on Dialog Objects and on reasoning and
  system-event Event Objects. A line with several blocks keeps the uuid for its first block; block i > 0
  gets "<uuid>.<i>" with parent_id "<uuid>" (ai_agent Section 4.7.2). The Event Objects of
  tool-invocation-00 carry no entry_id; operation_id links them.
- every Event Object names party 1, the agent, and session 0 in "sessions".

Not converted, and counted in the report: lines of other types (for example attachment, summary,
last-prompt, queue-operation), lines without a timestamp (an Event Object needs time), sidechain lines of
subagents, meta lines, image and document blocks, lines that are not JSON, a tool_use block without an id,
a tool result whose tool_use is not in the transcript, a permissionDecision of another value, the
arguments and the tool result of a disallowed operation. Review the output before you publish it; a
transcript can hold anything that was typed or read.
"""
from __future__ import annotations

import argparse
import collections
import datetime
import hashlib
import json
import pathlib
import re
import sys

RECORDER = {"name": "claude_jsonl_to_vcon", "version": "0.2.0"}
DATE_RX = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?([Zz]|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])$")
HOST = "!host"


def _when(s: str) -> datetime.datetime:
    m = DATE_RX.match(s)
    if not m:
        raise ValueError("not an RFC 3339 date-time with at most six fraction digits: %r" % s)
    y, mo, d, h, mi, se, frac, tz = m.groups()
    t = datetime.datetime(int(y), int(mo), int(d), int(h), int(mi), int(se), int((frac or "0").ljust(6, "0")),
                          tzinfo=datetime.timezone.utc)
    if tz not in ("Z", "z"):
        sign = 1 if tz[0] == "+" else -1
        t -= sign * datetime.timedelta(hours=int(tz[1:3]), minutes=int(tz[4:6]))
    return t


def _uuid8(label: str) -> str:
    b = bytearray(hashlib.sha256(label.encode("utf-8")).digest()[:16])
    b[6] = (b[6] & 0x0F) | 0x80
    b[8] = (b[8] & 0x3F) | 0x80
    h = b.hex()
    return "%s-%s-%s-%s-%s" % (h[:8], h[8:12], h[12:16], h[16:20], h[20:])


def vcon_uuid(session_id: str) -> str:
    """A version 8 UUID derived from the session id, so a rerun gives the same vCon uuid."""
    return _uuid8("vcon:claude-jsonl:" + session_id)


def operation_id(session_id: str, tool_use_id: str) -> str:
    """The operation_id of one tool_use block: a version 8 UUID derived from the session id and the block id,
    so it is unique among the operations of the vCon and the same on every rerun."""
    return _uuid8("vcon:claude-jsonl:operation:" + session_id + ":" + tool_use_id)


def policy_decision_value(pd: dict):
    """The decision of tool-invocation-00 6.1.4 for a permissionDecision of the transcript, or None."""
    if pd.get("decision") == "reject":
        return "disallowed"
    if pd.get("decision") == "accept":
        return "permission-required" if pd.get("source") == "user" else "allowed"
    return None


def _content(value):
    """Inline content in the form of vCon core: a string as text, anything else as JSON."""
    if isinstance(value, str):
        return {"mediatype": "text/plain", "encoding": "none", "body": value}
    return {"mediatype": "application/json", "encoding": "json", "body": value}


def convert(lines, user_id="user", user_name="user", agent_id="agent", agent_name="coding agent",
            model_provider="anthropic"):
    skipped = collections.Counter()
    entries = []
    for n, raw in enumerate(lines, 1):
        if not raw.strip():
            continue
        try:
            e = json.loads(raw)
        except ValueError:
            skipped["line not JSON"] += 1
            continue
        if not isinstance(e, dict):
            skipped["line not an object"] += 1
            continue
        kind = e.get("type")
        if kind not in ("user", "assistant", "system"):
            skipped["type %s" % kind] += 1
            continue
        if e.get("isSidechain") is True:
            skipped["sidechain line"] += 1
            continue
        if e.get("isMeta") is True:
            skipped["meta line"] += 1
            continue
        if not isinstance(e.get("timestamp"), str):
            skipped["line without timestamp"] += 1
            continue
        entries.append(e)
    if not entries:
        raise ValueError("no convertible line")
    sids = sorted({e.get("sessionId") for e in entries if isinstance(e.get("sessionId"), str)})
    if len(sids) != 1:
        raise ValueError("expected exactly one sessionId, found %d" % len(sids))
    sid = sids[0]

    def blocks_of(e):
        msg = e.get("message") if isinstance(e.get("message"), dict) else {}
        content = msg.get("content")
        return [{"type": "text", "text": content}] if isinstance(content, str) else (
            content if isinstance(content, list) else [])

    # First pass: the operations and the permission decisions, which the transcript writes on the result line.
    operations, decisions = {}, {}
    for e in entries:
        blocks = blocks_of(e)
        for blk in blocks:
            if isinstance(blk, dict) and blk.get("type") == "tool_use" and isinstance(blk.get("id"), str):
                if blk["id"] in operations:
                    raise ValueError("tool_use id %r repeated, operation_id would not be unique" % blk["id"])
                operations[blk["id"]] = operation_id(sid, blk["id"])
        result_blocks = [b for b in blocks if isinstance(b, dict) and b.get("type") == "tool_result"]
        if isinstance(e.get("permissionDecision"), dict):
            if len(result_blocks) > 1:
                raise ValueError("permissionDecision is ambiguous across multiple tool_result blocks")
            if len(result_blocks) == 1 and isinstance(result_blocks[0].get("tool_use_id"), str):
                decisions[result_blocks[0]["tool_use_id"]] = (e["permissionDecision"], result_blocks[0],
                                                              e["timestamp"])

    dialog, events, models, usage_done = [], [], [], set()

    def ids(e, i):
        uuid, parent = e.get("uuid"), e.get("parentUuid")
        if i == 0:
            return uuid, parent
        return "%s.%d" % (uuid, i), uuid

    def agent_event(e, i, typ, **kw):
        eid, pid = ids(e, i)
        ev = {"type": typ, "time": e["timestamp"], "sessions": 0, "party": 1}
        ev.update(kw)
        if eid is not None:
            ev["entry_id"] = eid
        if pid is not None:
            ev["parent_id"] = pid
        events.append(ev)

    disallowed = set()
    for e in entries:
        kind = e["type"]
        msg = e.get("message") if isinstance(e.get("message"), dict) else {}
        if kind == "system":
            data = {k: e[k] for k in ("level", "content") if isinstance(e.get(k), str)}
            agent_event(e, 0, "system-event", event_type=e.get("subtype") if isinstance(e.get("subtype"), str)
                        else "system", **({"data": data} if data else {}))
            continue
        role_party = 0 if kind == "user" else 1
        blocks = blocks_of(e)
        model = msg.get("model") if kind == "assistant" and isinstance(msg.get("model"), str) else None
        if model and model not in models:
            models.append(model)
        for i, blk in enumerate(blocks):
            t = blk.get("type") if isinstance(blk, dict) else None
            if t == "text" and isinstance(blk.get("text"), str):
                eid, pid = ids(e, i)
                d = {"type": "text", "start": e["timestamp"], "parties": [role_party], "mediatype": "text/plain",
                     "encoding": "none", "body": blk["text"]}
                if model:
                    d["model_id"] = model
                mid = msg.get("id")
                if kind == "assistant" and isinstance(msg.get("usage"), dict) and mid not in usage_done:
                    u = msg["usage"]
                    tu = {k2: u[k1] for k1, k2 in (("input_tokens", "input"), ("output_tokens", "output"),
                                                   ("cache_read_input_tokens", "cached"))
                          if isinstance(u.get(k1), int) and not isinstance(u.get(k1), bool) and u[k1] >= 0}
                    if tu:
                        d["token_usage"] = tu
                    usage_done.add(mid)
                if eid is not None:
                    d["entry_id"] = eid
                if pid is not None:
                    d["parent_id"] = pid
                dialog.append(d)
            elif t == "tool_use" and isinstance(blk.get("name"), str):
                if not isinstance(blk.get("id"), str):
                    skipped["tool_use without id"] += 1
                    continue
                op = operations[blk["id"]]
                common = {"time": e["timestamp"], "sessions": 0, "party": 1}
                verdict, sent = None, e["timestamp"]
                if blk["id"] in decisions:
                    pd, res, result_time = decisions[blk["id"]]
                    verdict = policy_decision_value(pd)
                    if verdict is None:
                        skipped["permissionDecision %s" % pd.get("decision")] += 1
                    else:
                        ev = {"type": "policy-decision", **common, "decision": verdict}
                        if verdict == "disallowed" and isinstance(res.get("content"), str):
                            ev["reason"] = res["content"]
                        ev.update({"operation": "tool-invocation", "policy_life": "once", "operation_id": op,
                                   "attempt": 1, "server": HOST, "tool": blk["name"]})
                        events.append(ev)
                    if verdict == "permission-required":
                        sent = result_time
                if verdict == "disallowed":
                    disallowed.add(blk["id"])
                    skipped["arguments of a disallowed operation (tool-invocation-00 6.1.1)"] += 1
                    continue
                events.append({"type": "tool-invocation", **dict(common, time=sent), "operation_id": op, "attempt": 1,
                               "server": HOST, "tool": blk["name"], **_content(blk.get("input", {}))})
            elif t == "tool_result":
                cid = blk.get("tool_use_id")
                if cid in disallowed:
                    skipped["tool result of a disallowed operation"] += 1
                    continue
                if cid not in operations:
                    skipped["tool result without its tool_use"] += 1
                    continue
                typ = "tool-failure" if blk.get("is_error") is True else "tool-result"
                events.append({"type": typ, "time": e["timestamp"], "sessions": 0, "party": 1,
                               "operation_id": operations[cid], "attempt": 1, **_content(blk.get("content", ""))})
            elif t == "thinking" and isinstance(blk.get("thinking"), str):
                agent_event(e, i, "reasoning", content=blk["thinking"])
            elif t == "redacted_thinking" and isinstance(blk.get("data"), str):
                agent_event(e, i, "reasoning", content="", encrypted=blk["data"])
            else:
                skipped["block %s" % t] += 1
    times = [_when(e["timestamp"]) for e in entries]
    start, end = min(times), max(times)
    dur = (end - start).total_seconds()
    first = min(entries, key=lambda e: _when(e["timestamp"]))
    meta = {"model_id": models[0] if models else "unknown", "model_provider": model_provider}
    if len(models) > 1:
        meta["models"] = models
    meta["cli_name"] = "claude-code"
    versions = [e["version"] for e in entries if isinstance(e.get("version"), str)]
    if versions:
        meta["cli_version"] = versions[0]
    session = {"start": first["timestamp"], "duration": int(dur) if dur == int(dur) else round(dur, 6),
               "parties": [0, 1], "dialog": list(range(len(dialog))), "agent_session_id": sid,
               "format": "interactive"}
    cwd = next((e["cwd"] for e in entries if isinstance(e.get("cwd"), str)), None)
    branch = next((e["gitBranch"] for e in entries if isinstance(e.get("gitBranch"), str) and e["gitBranch"]), None)
    if cwd:
        session["environment"] = {"working_dir": cwd}
        if branch:
            session["environment"]["vcs"] = {"type": "git", "branch": branch}
    vcon = {"vcon": "0.5.0", "uuid": vcon_uuid(sid), "created_at": first["timestamp"],
            "extensions": ["tool-invocation", "ai_agent"], "recording_agent": dict(RECORDER)}
    if branch:
        vcon["vcs"] = {"type": "git", "branch": branch}
    vcon.update({
        "parties": [{"name": user_name, "type": "person", "uuid": user_id},
                    {"name": agent_name, "type": "bot", "uuid": agent_id, "agent_meta": meta}],
        "sessions": [session], "dialog": dialog, "events": events})
    report = {"session_id": sid, "lines_converted": len(entries), "dialog": len(dialog), "events": len(events),
              "events_by_type": dict(sorted(collections.Counter(x["type"] for x in events).items())),
              "operations": dict(sorted((op, cid) for cid, op in operations.items())),
              "not_converted": dict(sorted(skipped.items()))}
    return vcon, report


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("jsonl")
    ap.add_argument("out")
    ap.add_argument("--report")
    ap.add_argument("--user-id", default="user")
    ap.add_argument("--user-name", default="user")
    ap.add_argument("--agent-id", default="agent")
    ap.add_argument("--agent-name", default="coding agent")
    ap.add_argument("--model-provider", default="anthropic")
    a = ap.parse_args(argv)
    lines = pathlib.Path(a.jsonl).read_text(encoding="utf-8").splitlines()
    vcon, report = convert(lines, a.user_id, a.user_name, a.agent_id, a.agent_name, a.model_provider)
    pathlib.Path(a.out).write_text(json.dumps(vcon, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if a.report:
        pathlib.Path(a.report).write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("%d dialog, %d events, not converted %s" % (report["dialog"], report["events"],
                                                     report["not_converted"] or "nothing"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
