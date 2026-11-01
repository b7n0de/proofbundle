"""After a Codex update: does the installed Codex still load every hook of the gate? No model turn.

    python3 plugins/proofbundle/evals/corpus_codex_hooks.py [--codex PATH]   (from the repository root)

Installs the plugin from this repository's marketplace into a throwaway CODEX_HOME (`codex plugin
marketplace add`, `codex plugin add`), asks the local app-server (`hooks/list`) which hooks it loaded, and
prints one JSON object: the Codex version, the hooks with their matcher, command and source file, and
"ok" true only for exactly the hooks the Codex manifest registers, each starting the gate with --host codex as the
gate reads it. Nothing leaves the machine; the throwaway CODEX_HOME is removed afterwards. DECISIONS.md, D14 says
why this can fail.
"""
from __future__ import annotations

import collections
import json
import os
import pathlib
import re
import select
import shlex
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[3]
MANIFEST = ROOT / "plugins" / "proofbundle" / ".codex-plugin" / "plugin.json"
#: The programs that start the gate's script, and the options before the script that take no argument. Another program,
#: or an option such as -c or -m whose argument is the program, starts no gate (reading of G-4, Z4).
INTERPRETERS = ("python3", "python")
_NO_ARGUMENT_OPTION = re.compile(r"-[bBdEIOqsSu]+")


def expected_hooks(manifest: pathlib.Path = MANIFEST) -> list[tuple[str, str | None]]:
    """(event, matcher) of every hook the Codex manifest registers, in its order, the event named as the app server
    names it (PreToolUse as preToolUse, Stop as stop) and no matcher as None. The expectation is read from the
    manifest, so a hook added there is expected here too."""
    hooks = json.loads(manifest.read_text(encoding="utf-8"))["hooks"]["hooks"]   # the manifest nests them
    return [(event[:1].lower() + event[1:], entry.get("matcher") or None) for event, entries in hooks.items()
            for entry in entries]


#: The characters of a shell operator as shlex reads them; a token made of them alone, unquoted, is an operator.
_OPERATOR_CHARS = "();<>|&"


def _shell_reads(command: str) -> bool:
    """True where `sh -n` reads the command as a whole line. A line no shell runs (an operator at its end, an open
    brace) starts no gate (follow-up reading of G-4, rest of Z4)."""
    try:
        return subprocess.run(["sh", "-n", "-c", command], capture_output=True, timeout=10, check=False).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def passes_host_codex(command: object) -> bool:
    """True only when the hook's first command starts proofbundle_gate.py with the words the gate reads as host codex
    (its _host: exactly --host codex, after `stop` for the Stop hook, --autonomous aside). A substring such as
    --host codex-x, or the words in a later command after ||, does not count. The command starts the gate only where its
    first word is python3 or python and the first word after options that take no argument is the gate's script. The
    whole line must be one sh reads, a quoted operator is a word the gate gets, and after the gate's command only `||`
    and a command may follow: a pipe would take the gate's answer, and `&&` or `;` are no form of the manifest."""
    if not isinstance(command, str) or not _shell_reads(command):
        return False
    lexer = shlex.shlex(command, posix=False, punctuation_chars=True)   # keeps quotes, so '||' stays a word
    lexer.whitespace_split = True
    try:
        tokens = list(lexer)
        operator = [bool(token) and all(c in _OPERATOR_CHARS for c in token) for token in tokens]
        cut = operator.index(True) if True in operator else len(tokens)
        first = ["".join(shlex.split(token)) for token in tokens[:cut]]
    except ValueError:   # an unclosed quote: a line no shell runs
        return False
    rest = tokens[cut:]
    if rest and (rest[0] != "||" or len(rest) < 2 or operator[-1]):
        return False
    names = [word.replace("\\", "/").rsplit("/", 1)[-1] for word in first]
    if not names or names[0] not in INTERPRETERS:
        return False
    gate = 1
    while gate < len(first) and _NO_ARGUMENT_OPTION.fullmatch(first[gate]):
        gate += 1
    if gate >= len(first) or names[gate] != "proofbundle_gate.py":
        return False
    return [word for word in first[gate + 1:] if word != "--autonomous"] in (["--host", "codex"],
                                                                              ["stop", "--host", "codex"])


def judge(hooks: list[dict], expected: list[tuple[str, str | None]]) -> bool:
    """True only for exactly the expected hooks, each as often as expected and in any order of the answer, each
    started with --host codex. The order of hooks/list is NOT MEASURED, so a correct load in another order counts."""
    loaded = collections.Counter((h["event"], h["matcher"] or None) for h in hooks)
    return loaded == collections.Counter(expected) and all(h["host_codex"] for h in hooks)


def _ask(proc: subprocess.Popen, message: dict, timeout: float = 60) -> dict:
    proc.stdin.write(json.dumps(message) + "\n")
    proc.stdin.flush()
    end = time.time() + timeout
    while time.time() < end:
        ready, _, _ = select.select([proc.stdout], [], [], 1)
        if not ready:
            continue
        line = proc.stdout.readline()
        if not line:
            break
        try:
            reply = json.loads(line)
        except ValueError:
            continue
        if reply.get("id") == message["id"]:
            return reply
    return {"error": "no answer in time"}


def main(argv: list[str]) -> int:
    codex = argv[argv.index("--codex") + 1] if "--codex" in argv else shutil.which("codex")
    if not codex:
        print(json.dumps({"ok": None, "codex": "not installed", "result": "NOT MEASURED"}))
        return 2
    home = tempfile.mkdtemp(prefix="proofbundle-codex-home-")
    cwd = tempfile.mkdtemp(prefix="proofbundle-codex-cwd-")
    env = dict(os.environ, CODEX_HOME=home)
    try:
        version = subprocess.run([codex, "--version"], capture_output=True, text=True, env=env).stdout.strip()
        for args in (["plugin", "marketplace", "add", str(ROOT)], ["plugin", "add", "proofbundle@proofbundle"]):
            done = subprocess.run([codex, *args], capture_output=True, text=True, env=env, timeout=120)
            if done.returncode != 0:
                print(json.dumps({"ok": False, "codex": version, "failed": args, "stderr": done.stderr[-500:]}))
                return 1
        proc = subprocess.Popen([codex, "app-server"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True, env=env, cwd=cwd)
        try:
            _ask(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                        "params": {"clientInfo": {"name": "proofbundle-corpus", "version": "0"}}})
            proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "initialized"}) + "\n")
            reply = _ask(proc, {"jsonrpc": "2.0", "id": 2, "method": "hooks/list", "params": {"cwds": [cwd]}})
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        data = (reply.get("result") or {}).get("data") or [{}]
        hooks = [{"event": h.get("eventName"), "matcher": h.get("matcher"),
                  "host_codex": passes_host_codex(h.get("command")),
                  "source": pathlib.Path(h.get("sourcePath") or "").relative_to(home).as_posix()
                  if (h.get("sourcePath") or "").startswith(home) else h.get("sourcePath"),
                  "trust": h.get("trustStatus")}
                 for h in data[0].get("hooks", []) if h.get("pluginId") == "proofbundle@proofbundle"]
        ok = judge(hooks, expected_hooks())
        print(json.dumps({"ok": ok, "codex": version, "hooks": hooks, "errors": data[0].get("errors")}, indent=1))
        return 0 if ok else 1
    finally:
        shutil.rmtree(home, ignore_errors=True)
        shutil.rmtree(cwd, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
