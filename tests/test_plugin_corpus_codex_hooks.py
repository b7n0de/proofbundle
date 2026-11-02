"""The corpus's Codex hook check says ok for exactly the hooks the Codex manifest names (finding 8, review package -1).

plugins/proofbundle/evals/corpus_codex_hooks.py installs the plugin into a throwaway CODEX_HOME, asks Codex's app-server
which hooks it loaded, and prints "ok". Read on 2026-10-26: it expected exactly two PreToolUse matchers (Bash and the
MCP writes) while .codex-plugin/plugin.json registers three PreToolUse groups and a Stop hook, so a correct load was
reported not ok, and a load that dropped the file-tool and Stop hooks was reported ok.

The property held here, with a stand-in for the codex program that answers `hooks/list` as Codex does: the check says
ok when the loaded hooks are exactly the manifest's, each event, matcher and command, in any order of the answer; and
not ok when one is missing, one is extra, one lacks --host codex or one starts another command (the external review of
-1, AUSWERTUNGEN finding 1 and A-6). How a real Codex words the command in hooks/list is NOT MEASURED: the check takes
the manifest's text, or that text with ${PLUGIN_ROOT} as the folder the hook was loaded from. No Codex runs here; what
a real Codex loads stays NOT MEASURED (RUNBOOK_CODEX.md).
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys

from _plugin_env import plugin_env

ROOT = pathlib.Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "plugins" / "proofbundle"
CHECK = PLUGIN / "evals" / "corpus_codex_hooks.py"
MANIFEST = PLUGIN / ".codex-plugin" / "plugin.json"

#: A stand-in for the codex program: version, the two install commands, and an app-server that answers initialize
#: and hooks/list with the hooks given in FAKE_HOOKS (a JSON file next to it), as Codex's app-server words them.
FAKE = r'''#!{python}
import json, pathlib, sys
args = sys.argv[1:]
if args == ["--version"]:
    print("codex-cli 0.0.0 (stand-in)")
    sys.exit(0)
if args[:1] == ["plugin"]:
    sys.exit(0)
if args == ["app-server"]:
    hooks = json.loads((pathlib.Path(__file__).parent / "hooks.json").read_text())
    for line in sys.stdin:
        message = json.loads(line)
        if message.get("id") == 1:
            print(json.dumps({{"jsonrpc": "2.0", "id": 1, "result": {{}}}}), flush=True)
        elif message.get("id") == 2:
            print(json.dumps({{"jsonrpc": "2.0", "id": 2,
                               "result": {{"data": [{{"hooks": hooks, "errors": []}}]}}}}), flush=True)
    sys.exit(0)
sys.exit(3)
'''


def _manifest_hooks() -> list[dict]:
    """The hooks a correct load of the Codex manifest gives, in the words of Codex's hooks/list."""
    groups = json.loads(MANIFEST.read_text(encoding="utf-8")).get("hooks", {}).get("hooks", {})
    loaded = []
    for event, entries in groups.items():
        for entry in entries:
            for hook in entry["hooks"]:
                loaded.append({"eventName": event[0].lower() + event[1:], "matcher": entry.get("matcher"),
                               "command": hook["command"], "sourcePath": str(MANIFEST),
                               "trustStatus": "trusted", "pluginId": "proofbundle@proofbundle"})
    return loaded


def _run(tmp_path: pathlib.Path, hooks: list[dict]) -> tuple[int, dict]:
    fake = tmp_path / "codex"
    fake.write_text(FAKE.format(python=sys.executable), encoding="utf-8")
    fake.chmod(0o755)
    (tmp_path / "hooks.json").write_text(json.dumps(hooks), encoding="utf-8")
    proc = subprocess.run([sys.executable, "-I", str(CHECK), "--codex", str(fake)], capture_output=True, text=True,
                          env=plugin_env(), cwd=ROOT, timeout=120, check=False)
    return proc.returncode, json.loads(proc.stdout)


def test_a_load_of_exactly_the_manifests_hooks_is_ok(tmp_path):
    hooks = _manifest_hooks()
    code, report = _run(tmp_path, hooks)
    assert (code, report["ok"]) == (0, True), report
    assert len(report["hooks"]) == len(hooks)


def test_a_load_that_misses_a_hook_of_the_manifest_is_not_ok(tmp_path):
    hooks = _manifest_hooks()
    if not hooks:
        return                                  # a manifest without hooks has no hook to miss
    for missing in range(len(hooks)):
        code, report = _run(tmp_path, hooks[:missing] + hooks[missing + 1:])
        assert (code, report["ok"]) == (1, False), (missing, report)


def test_a_hook_without_the_codex_host_is_not_ok(tmp_path):
    hooks = _manifest_hooks()
    if not hooks:
        return
    hooks[0] = dict(hooks[0], command=hooks[0]["command"].replace("--host codex", "--autonomous"))
    code, report = _run(tmp_path, hooks)
    assert (code, report["ok"]) == (1, False), report


def test_an_extra_hook_is_not_ok(tmp_path):
    hooks = _manifest_hooks()
    extra = dict(hooks[0], eventName="postToolUse") if hooks else {
        "eventName": "postToolUse", "matcher": "Bash", "command": "python3 x.py --host codex",
        "sourcePath": str(MANIFEST), "trustStatus": "trusted", "pluginId": "proofbundle@proofbundle"}
    code, report = _run(tmp_path, hooks + [extra])
    assert (code, report["ok"]) == (1, False), report


def test_a_hook_that_starts_another_command_is_not_ok(tmp_path):
    hooks = _manifest_hooks()
    if not hooks:
        return
    hooks[-1] = dict(hooks[-1], command=hooks[-1]["command"].replace("proofbundle_gate.py", "proofbundle_other.py"))
    code, report = _run(tmp_path, hooks)
    assert (code, report["ok"]) == (1, False), report


def test_the_order_of_the_answer_does_not_matter(tmp_path):
    hooks = list(reversed(_manifest_hooks()))
    code, report = _run(tmp_path, hooks)
    assert (code, report["ok"]) == (0, True), report


def test_a_command_with_the_plugin_root_written_out_is_ok(tmp_path):
    installed = tmp_path / "home" / "plugins" / "proofbundle"
    hooks = [dict(h, command=h["command"].replace("${PLUGIN_ROOT}", str(installed)),
                  sourcePath=str(installed / ".codex-plugin" / "plugin.json")) for h in _manifest_hooks()]
    code, report = _run(tmp_path, hooks)
    assert (code, report["ok"]) == (0, True), report
