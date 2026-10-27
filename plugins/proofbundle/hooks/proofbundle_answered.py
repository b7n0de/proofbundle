"""proofbundle: the answer to an ask of the gate (DECISIONS.md D94).

Claude Code sends PostToolUse, or PostToolUseFailure where the call failed, with the tool_use_id of a call that ran.
Measured with Claude Code 2.1.302 on a pseudo terminal (n37/werkzeug/ask_answer_n37.py of the delivery): after a yes in
the dialog of an ask one of the two comes with the tool_use_id of the PreToolUse event; after a no (Escape) neither
comes, and no PermissionDenied either. The gate keeps the key of every ask it sends (the sha256 of the tool_use_id,
never the id) in the plugin data directory; this hook, given the event of a call whose key is kept there, removes the
key and appends one line to the gate log: that ask was answered yes. It reads nothing else, prints nothing, calls no
network, and never blocks or fails a call: every failure ends with exit 0.

It also counts the open pull requests each session opened (DECISIONS.md D110, follow-up note 33 point 6, owner choice O30-1
A): after a call that ran (PostToolUse), up by each address of a pull request the output names where the command opens
one, down where `gh pr merge` or `gh pr close` of one of them ran. The gate reads the count for house rule H3.

It is a file of its own, apart from proofbundle_gate.py, so that the hook after every gated call stays short: it loads
no more than the standard library and this file.
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import re
import shlex
import stat
import sys
import tempfile
import time

#: The names the gate uses (proofbundle_gate.py: LOG_NAME, LOG_DIR_VARIABLES["claude"], ASKS_PENDING, ASKS_SCHEMA).
LOG_NAME = "gate-log.jsonl"
DATA_VARIABLE = "CLAUDE_PLUGIN_DATA"
ASKS_PENDING = "asks-pending.json"
ASKS_SCHEMA = "proofbundle-plugin/asks-pending/v0.1"
MAX_ASKS_BYTES = 256 * 1024
MAX_EVENT_BYTES = 16 * 1024 * 1024
LOCK_SECONDS = 2.0
#: D110: the open pull requests of each session, {"schema", "sitzungen": {session id: ["owner/repo#number", …]}}, read
#: by the gate for house rule H3 (proofbundle_gate.py: OPEN_PRS, OPEN_PRS_SCHEMA). The sessions written last are kept.
OPEN_PRS = "open-prs.json"
OPEN_PRS_SCHEMA = "proofbundle-plugin/open-prs/v0.1"
MAX_OPEN_PRS_BYTES = 256 * 1024
OPEN_PRS_KEEP_SESSIONS = 64
PR_ADDRESS = re.compile(r"https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/pull/([0-9]+)(?![0-9])")
#: A command that opens a pull request, read wide on purpose (a count too high asks sooner, one too low frees): a gh
#: call of `pr create` or `pr new`, the GraphQL mutation createPullRequest, and `gh api` on a …/pulls endpoint that
#: writes (a method POST, a field or an input, the methods gh takes for a call with parameters) and names no GET.
_PR_CREATE = re.compile(r"\bgh\b[^\n]*?\bpr\s+(?:create|new)\b|createPullRequest")
_API_PULLS = re.compile(r"\bgh\s+api\b[^\n]*?(?:^|[\s'\"/])(?:/?repos/[^\s'\"/]+/[^\s'\"/]+/)?pulls(?=$|[\s'\"])")
_API_WRITES = re.compile(r"(?:^|\s)(?:-X\s*'?POST|--method[=\s]'?POST|-[fF]\b|-[fF]\S|--field\b|--raw-field\b|--input\b)")
_API_GET = re.compile(r"(?:^|\s)(?:-X\s*'?GET|--method[=\s]'?GET)")
#: Shell syntax beyond the words of one call: a merge or close is counted only as a whole command of its own.
_SHELL_SYNTAX = re.compile(r"[;&|<>`$()\n]")


def ask_key(tool_use_id: str) -> str:
    """The key of an ask: the first 32 hex digits of the sha256 of the tool_use_id."""
    return hashlib.sha256(tool_use_id.encode("utf-8", "surrogateescape")).hexdigest()[:32]


@contextlib.contextmanager
def asks_lock(directory: str, name: str = ASKS_PENDING):
    """An exclusive lock on the pending asks (or the file name names), given up after LOCK_SECONDS (then OSError:
    nothing is written)."""
    fd = os.open(os.path.join(directory, name + ".lock"), os.O_WRONLY | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        until = time.monotonic() + LOCK_SECONDS
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() > until:
                    raise OSError("the pending asks stay locked") from None
                time.sleep(0.02)
        yield
    finally:
        os.close(fd)


def read_asks(directory: str) -> dict:
    """The pending asks {key: {"ts", "gruende", "session_id"}}, empty where there are none or they cannot be read."""
    path = os.path.join(directory, ASKS_PENDING)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return {}
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            return {}
        raw = handle.read(MAX_ASKS_BYTES + 1)
    state = json.loads(raw) if len(raw) <= MAX_ASKS_BYTES else {}
    if not isinstance(state, dict) or state.get("schema") != ASKS_SCHEMA or not isinstance(state.get("asks"), dict):
        return {}
    return state["asks"]


def write_asks(directory: str, asks: dict) -> None:
    fd, tmp = tempfile.mkstemp(prefix=".asks-", dir=directory)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump({"schema": ASKS_SCHEMA, "asks": asks}, handle, sort_keys=False)
    os.replace(tmp, os.path.join(directory, ASKS_PENDING))


def append_log(directory: str, entry: dict) -> None:
    fd = os.open(os.path.join(directory, LOG_NAME), os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NONBLOCK
                 | os.O_CLOEXEC, 0o644)
    try:
        if stat.S_ISREG(os.fstat(fd).st_mode):
            os.write(fd, (json.dumps(entry, sort_keys=True) + "\n").encode("utf-8"))
    finally:
        os.close(fd)


def read_open_prs(directory: str) -> dict:
    """The open pull requests {session id: ["owner/repo#number", …]}, empty where there are none or they cannot be
    read."""
    path = os.path.join(directory, OPEN_PRS)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return {}
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            return {}
        raw = handle.read(MAX_OPEN_PRS_BYTES + 1)
    state = json.loads(raw) if len(raw) <= MAX_OPEN_PRS_BYTES else {}
    if not isinstance(state, dict) or state.get("schema") != OPEN_PRS_SCHEMA or \
            not isinstance(state.get("sitzungen"), dict):
        return {}
    return {k: [p for p in v if isinstance(p, str)] for k, v in state["sitzungen"].items() if isinstance(v, list)}


def write_open_prs(directory: str, sessions: dict) -> None:
    fd, tmp = tempfile.mkstemp(prefix=".open-prs-", dir=directory)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump({"schema": OPEN_PRS_SCHEMA, "sitzungen": sessions}, handle, sort_keys=False)
    os.replace(tmp, os.path.join(directory, OPEN_PRS))


def opens_pr(command: str) -> bool:
    """Whether the command may open a pull request (_PR_CREATE, or _API_PULLS with _API_WRITES and no _API_GET)."""
    if _PR_CREATE.search(command):
        return True
    return any(_API_PULLS.search(line) and _API_WRITES.search(line) and not _API_GET.search(line)
               for line in command.splitlines() or [""])


def pr_change(command: str, stdout: str, tool_use_id: str) -> tuple[str, list[str]] | None:
    """("auf", [pull requests]) for a command that may open one: each address its output names, else one entry of
    unknown number, so a count is never too low; ("zu", [target]) for `gh pr merge|close <target>` as a whole command
    of its own, the target "owner/repo#number", or "#number" where it names no repository; None for any other."""
    if opens_pr(command):
        opened = sorted({f"{o}/{r}#{n}" for o, r, n in PR_ADDRESS.findall(stdout or "")})
        return "auf", opened or [f"?{ask_key(tool_use_id)}"]
    if _SHELL_SYNTAX.search(command):
        return None
    try:
        words = shlex.split(command)
    except ValueError:
        return None
    if len(words) < 4 or words[:2] != ["gh", "pr"] or words[2] not in ("merge", "close"):
        return None
    repo, target, k = None, None, 3
    while k < len(words):
        w = words[k]
        if w in ("-R", "--repo") and k + 1 < len(words):
            repo, k = words[k + 1], k + 2
            continue
        if w.startswith("--repo="):
            repo = w.partition("=")[2]
        elif not w.startswith("-") and target is None:
            target = w
        k += 1
    address = PR_ADDRESS.fullmatch(target or "")
    if address:
        return "zu", [f"{address.group(1)}/{address.group(2)}#{address.group(3)}"]
    if target:   # a number; any other word names no entry
        return "zu", [f"{repo}#{target}" if repo else f"#{target}"]
    return None


def count_open_prs(event: dict, directory: str) -> None:
    """D110: count the open pull requests of the event's session after a Bash call that ran (PostToolUse; a call that
    failed counts nothing). A target "#number" takes off the one entry of that number, and none where two repositories
    hold it."""
    if event.get("hook_event_name") != "PostToolUse" or event.get("tool_name") != "Bash":
        return
    session = event.get("session_id")
    command = event["tool_input"].get("command") if isinstance(event.get("tool_input"), dict) else None
    response = event.get("tool_response") if isinstance(event.get("tool_response"), dict) else {}
    tool_use_id = event.get("tool_use_id") if isinstance(event.get("tool_use_id"), str) else ""
    if not isinstance(session, str) or not session or not isinstance(command, str):
        return
    stdout = response.get("stdout") if isinstance(response.get("stdout"), str) else ""
    change = pr_change(command, stdout, tool_use_id)
    if change is None:
        return
    kind, items = change
    with asks_lock(directory, OPEN_PRS):
        sessions = read_open_prs(directory)
        own = sessions.pop(session, [])
        if kind == "auf":
            own = own + [p for p in items if p not in own]
        else:
            for target in items:
                hits = [p for p in own if p == target or (target.startswith("#") and p.endswith(target))]
                if len(hits) == 1:
                    own.remove(hits[0])
        sessions[session] = own
        while len(sessions) > OPEN_PRS_KEEP_SESSIONS:
            sessions.pop(next(iter(sessions)))
        write_open_prs(directory, sessions)


def main() -> int:
    try:
        event = json.loads(sys.stdin.buffer.read(MAX_EVENT_BYTES))
        directory = os.environ.get(DATA_VARIABLE)
        if not isinstance(event, dict) or not directory or not os.path.isabs(directory) or not os.path.isdir(directory):
            return 0
        try:
            count_open_prs(event, directory)   # D110
        except Exception:  # noqa: BLE001 - the count never changes a call
            pass
        if not isinstance(event.get("tool_use_id"), str):
            return 0
        if event.get("hook_event_name") not in ("PostToolUse", "PostToolUseFailure"):
            return 0
        key = ask_key(event["tool_use_id"])
        with asks_lock(directory):
            asks = read_asks(directory)
            asked = asks.pop(key, None)
            if not isinstance(asked, dict):
                return 0
            write_asks(directory, asks)
        append_log(directory, {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "host": "claude",
                               "decision": "answered", "verdict": "answered", "antwort": "ja", "frage": key,
                               "frage_ts": asked.get("ts"), "reason_ids": asked.get("gruende") or [],
                               "session_id": event.get("session_id") if isinstance(event.get("session_id"), str)
                               else None, "ereignis": event["hook_event_name"]})
    except Exception:  # noqa: BLE001 - the answer hook never changes a call
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
