"""proofbundle: the answer to an ask of the gate (DECISIONS.md D94, Nachtrag 37, Ergänzung 4).

Claude Code sends PostToolUse, or PostToolUseFailure where the call failed, with the tool_use_id of a call that ran.
Measured with Claude Code 2.1.302 on a pseudo terminal (n37/werkzeug/ask_answer_n37.py of the delivery): after a yes in
the dialog of an ask one of the two comes with the tool_use_id of the PreToolUse event; after a no (Escape) neither
comes, and no PermissionDenied either. The gate keeps the key of every ask it sends (the sha256 of the tool_use_id,
never the id) in the plugin data directory; this hook, given the event of a call whose key is kept there, removes the
key and appends one line to the gate log: that ask was answered yes. It reads nothing else, prints nothing, calls no
network, and never blocks or fails a call: every failure ends with exit 0.

It is a file of its own, apart from proofbundle_gate.py, so that the hook after every gated call stays short: it loads
no more than the standard library and this file.
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
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


def ask_key(tool_use_id: str) -> str:
    """The key of an ask: the first 32 hex digits of the sha256 of the tool_use_id."""
    return hashlib.sha256(tool_use_id.encode("utf-8", "surrogateescape")).hexdigest()[:32]


@contextlib.contextmanager
def asks_lock(directory: str):
    """An exclusive lock on the pending asks, given up after LOCK_SECONDS (then OSError: nothing is written)."""
    fd = os.open(os.path.join(directory, ASKS_PENDING + ".lock"), os.O_WRONLY | os.O_CREAT | os.O_CLOEXEC, 0o600)
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


def main() -> int:
    try:
        event = json.loads(sys.stdin.buffer.read(MAX_EVENT_BYTES))
        directory = os.environ.get(DATA_VARIABLE)
        if not isinstance(event, dict) or not isinstance(event.get("tool_use_id"), str) or not directory or \
                not os.path.isabs(directory) or not os.path.isdir(directory):
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
