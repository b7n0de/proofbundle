"""Convert one Claude Code session transcript (JSONL) into an unsigned vCon with the ai_agent extension.

    python claude_jsonl_to_vcon.py SESSION.jsonl OUT.json [--report REPORT.json]
        [--user-id ID] [--user-name NAME] [--agent-id ID] [--agent-name NAME] [--model-provider NAME]

The mapping follows Appendix C and the example of Appendix D of draft-birkholz-vcon-ai-agent-extension-00
on vCon core -05. Standard library only. The output is deterministic for a given input and options.

Mapping, per line of the transcript:

- "user" or "assistant" text (a string content or a "text" block) becomes a "text" Dialog Object. The
  user line is contributed by party 0, the assistant line by party 1 with model_id. token_usage is set
  once per message id, on its first text Dialog Object.
- a "tool_use" block becomes a "tool-call" Event Object (tool_name, input, call_id = the block id).
- a "tool_result" block becomes a "tool-result" Event Object (output, call_id = tool_use_id, is_error,
  status "error" or "success" taken from is_error alone).
- a "thinking" block becomes a "reasoning" Event Object with its text; its signature is not carried.
  A "redacted_thinking" block becomes a "reasoning" Event Object with empty content and the data in
  encrypted.
- a permissionDecision on a tool result line becomes a "system-event" Event Object with event_type
  "permission-decision" and data {decision, source, call_id}; other members are not carried.
- a "system" line becomes a "system-event" Event Object with event_type = its subtype.
- entry_id is the line uuid and parent_id its parentUuid. A line with several blocks keeps the uuid for
  its first block; block i > 0 gets "<uuid>.<i>" with parent_id "<uuid>" (Section 4.7.2).
- every Event Object names party 1, the agent (Section 4.6), and session 0 in "sessions".

Not converted, and counted in the report: lines of other types (for example attachment, summary,
last-prompt, queue-operation), lines without a timestamp (the Event Object needs time, Appendix C),
sidechain lines of subagents, meta lines, image and document blocks, and lines that are not JSON.
Review the output before you publish it; a transcript can hold anything that was typed or read.
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

RECORDER = {"name": "claude_jsonl_to_vcon", "version": "0.1.0"}
DATE_RX = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?([Zz]|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])$")


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


def vcon_uuid(session_id: str) -> str:
    """A version 8 UUID derived from the session id, so a rerun gives the same vCon uuid."""
    b = bytearray(hashlib.sha256(("vcon:claude-jsonl:" + session_id).encode("utf-8")).digest()[:16])
    b[6] = (b[6] & 0x0F) | 0x80
    b[8] = (b[8] & 0x3F) | 0x80
    h = b.hex()
    return "%s-%s-%s-%s-%s" % (h[:8], h[8:12], h[12:16], h[16:20], h[20:])


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
    dialog, events, models, usage_done = [], [], [], set()

    def ids(e, i):
        uuid, parent = e.get("uuid"), e.get("parentUuid")
        if i == 0:
            return uuid, parent
        return "%s.%d" % (uuid, i), uuid

    def event(e, i, typ, **kw):
        eid, pid = ids(e, i)
        ev = {"type": typ, "time": e["timestamp"], "sessions": 0, "party": 1}
        ev.update(kw)
        if eid is not None:
            ev["entry_id"] = eid
        if pid is not None:
            ev["parent_id"] = pid
        events.append(ev)

    for e in entries:
        kind = e["type"]
        msg = e.get("message") if isinstance(e.get("message"), dict) else {}
        if kind == "system":
            data = {k: e[k] for k in ("level", "content") if isinstance(e.get(k), str)}
            event(e, 0, "system-event", event_type=e.get("subtype") if isinstance(e.get("subtype"), str)
                  else "system", **({"data": data} if data else {}))
            continue
        role_party = 0 if kind == "user" else 1
        content = msg.get("content")
        blocks = [{"type": "text", "text": content}] if isinstance(content, str) else (
            content if isinstance(content, list) else [])
        result_blocks = [b for b in blocks if isinstance(b, dict) and b.get("type") == "tool_result"]
        if isinstance(e.get("permissionDecision"), dict) and len(result_blocks) > 1:
            raise ValueError("permissionDecision is ambiguous across multiple tool_result blocks")
        model = msg.get("model") if kind == "assistant" and isinstance(msg.get("model"), str) else None
        if model and model not in models:
            models.append(model)
        for i, blk in enumerate(blocks):
            t = blk.get("type") if isinstance(blk, dict) else None
            if t == "text" and isinstance(blk.get("text"), str):
                eid, pid = ids(e, i)
                d = {"type": "text", "start": e["timestamp"], "parties": role_party, "mediatype": "text/plain",
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
                kw = {"tool_name": blk["name"], "input": blk.get("input", {})}
                if isinstance(blk.get("id"), str):
                    kw["call_id"] = blk["id"]
                event(e, i, "tool-call", **kw)
            elif t == "tool_result":
                err = blk.get("is_error") is True
                kw = {"output": blk.get("content", "")}
                if isinstance(blk.get("tool_use_id"), str):
                    kw["call_id"] = blk["tool_use_id"]
                kw.update({"status": "error" if err else "success", "is_error": err})
                event(e, i, "tool-result", **kw)
                pd = e.get("permissionDecision")
                if isinstance(pd, dict) and len(result_blocks) == 1:
                    data = {k: pd[k] for k in ("decision", "source") if isinstance(pd.get(k), str)}
                    if "call_id" in kw:
                        data["call_id"] = kw["call_id"]
                    ev = {"type": "system-event", "time": e["timestamp"], "sessions": 0, "party": 1,
                          "event_type": "permission-decision", "data": data}
                    if e.get("uuid") is not None:
                        ev["entry_id"] = e["uuid"] + ".permission"
                        ev["parent_id"] = e["uuid"]
                    events.append(ev)
            elif t == "thinking" and isinstance(blk.get("thinking"), str):
                event(e, i, "reasoning", content=blk["thinking"])
            elif t == "redacted_thinking" and isinstance(blk.get("data"), str):
                event(e, i, "reasoning", content="", encrypted=blk["data"])
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
    vcon = {"vcon": "0.5.0", "uuid": vcon_uuid(sid), "created_at": first["timestamp"], "extensions": ["ai_agent"],
            "recording_agent": dict(RECORDER)}
    if branch:
        vcon["vcs"] = {"type": "git", "branch": branch}
    vcon.update({
        "parties": [{"name": user_name, "type": "person", "uuid": user_id},
                    {"name": agent_name, "type": "bot", "uuid": agent_id, "agent_meta": meta}],
        "sessions": [session], "dialog": dialog, "events": events})
    report = {"session_id": sid, "lines_converted": len(entries), "dialog": len(dialog), "events": len(events),
              "events_by_type": dict(sorted(collections.Counter(x["type"] for x in events).items())),
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
