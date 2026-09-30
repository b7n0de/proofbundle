"""After a Codex update: does the installed Codex still load both hooks of the gate? No model turn.

    python3 plugins/proofbundle/evals/corpus_codex_hooks.py [--codex PATH]   (from the repository root)

Installs the plugin from this repository's marketplace into a throwaway CODEX_HOME (`codex plugin
marketplace add`, `codex plugin add`), asks the local app-server (`hooks/list`) which hooks it loaded, and
prints one JSON object: the Codex version, the hooks with their matcher, command and source file, and
"ok" true only for exactly the two PreToolUse hooks of the gate with --host codex. Nothing leaves the
machine; the throwaway CODEX_HOME is removed afterwards. DECISIONS.md, D14 says why this can fail.
"""
from __future__ import annotations

import json
import os
import pathlib
import select
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[3]
MATCHERS = ["Bash", "^mcp__.+__(create_pull_request|create_merge_request|create_release|push_files|"
            "create_or_update_file|merge_pull_request)$"]


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
                  "host_codex": "--host codex" in (h.get("command") or ""),
                  "source": pathlib.Path(h.get("sourcePath") or "").relative_to(home).as_posix()
                  if (h.get("sourcePath") or "").startswith(home) else h.get("sourcePath"),
                  "trust": h.get("trustStatus")}
                 for h in data[0].get("hooks", []) if h.get("pluginId") == "proofbundle@proofbundle"]
        ok = ([h["matcher"] for h in hooks] == MATCHERS and all(h["event"] == "preToolUse" and h["host_codex"]
                                                               for h in hooks))
        print(json.dumps({"ok": ok, "codex": version, "hooks": hooks, "errors": data[0].get("errors")}, indent=1))
        return 0 if ok else 1
    finally:
        shutil.rmtree(home, ignore_errors=True)
        shutil.rmtree(cwd, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
