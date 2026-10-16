"""D44, Nachtrag 19: the uploadpack keys git reads only in upload-pack do not hinder a read form of class a.

Measured by delta at ba65da56: `git log -3 --oneline` in a repository whose .git/config carries
uploadpack.allowanysha1inwant asked with "a configuration key the read profile does not know to start no program".
upload-pack, the serving side of a fetch from this repository, reads that key; no read form starts upload-pack.

Ground truth, measured with git 2.43.0 under strace -f with no network (truth_n19.py of the delivery): the 23 spellings
of the read forms (log, show, diff, grep and status first) with each of uploadpack.allowAnySHA1InWant,
allowTipSHA1InWant, allowReachableSHA1InWant, allowRefInWant and allowFilter set true, false, to an invalid value and
without a value started no program and opened no connection, with the exit code and output of the run without the key
(483 runs). A fetch from such a repository over file:// started git-upload-pack, which ended on the invalid value.

The five keys join the read profile one by one. Unchanged: uploadpack.packObjectsHook (it names a program) and every
other uploadpack.* or uploadpackfilter.* key ask; Codex; every other finding of the read profile; the state check of
add, commit -m and worktree add (K-NW-2 B, D3, D40), which this order does not touch (O19-1 of the report).

RED at 1db350a1 for each freed case and for the cases where another finding stands after the key (there the key was
named first); the controls answer the same at both heads.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time

import pytest

import _worktree_layout as w
import test_plugin_gate_n2c_push_done as n2c
from _plugin_env import plugin_env

pytestmark = w.d.pytestmark
gate = n2c.gate
#: delta's environment as Cowork measured it (D41, D42), with the bound host.
DELTA = {"GIT_OPTIONAL_LOCKS": "0", "GIT_EDITOR": "true", "AI_AGENT": "claude-code_2-1-301_harness", "CLAUDECODE": "1"}
#: The keys of D44 as git's documentation spells them.
KEYS = ["uploadpack.allowAnySHA1InWant", "uploadpack.allowTipSHA1InWant", "uploadpack.allowReachableSHA1InWant",
        "uploadpack.allowRefInWant", "uploadpack.allowFilter"]
VALUES = ["true", "false", "bogus"]
COMMANDS = {"log": "git log -3 --oneline", "show": "git show --stat HEAD", "diff": "git diff --stat",
            "grep": "git grep -n one", "status": "git status --short"}
#: The other read forms of the grammar (D34), each in a spelling the grammar frees.
OTHER_FORMS = ["git rev-list --count HEAD", "git ls-files", "git rev-parse HEAD", "git for-each-ref",
               "git branch --list", "git ls-tree HEAD", "git show-ref", "git merge-base HEAD HEAD",
               "git describe --always", "git worktree list", "git cat-file -t HEAD"]
#: Keys beside the five that keep the ask: real keys of upload-pack the profile does not name, and names that are no key.
NEIGHBOURS = ["uploadpack.keepAlive", "uploadpack.hideRefs", "uploadpack.blobPackfileUri", "uploadpackfilter.allow",
              "uploadpackfilter.blob:none.allow", "uploadpack.allowAnySHA1InWants", "uploadpack.allowSHA1InWant",
              "uploadpack.sub.allowAnySHA1InWant", "uploadpack.allowFilterX", "receivepack.allowAnySHA1InWant"]


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    w.clean(monkeypatch, tmp_path)


@pytest.fixture
def main(tmp_path):
    repo = w.main_repo(tmp_path)
    (repo / "README.md").write_text("one\ntwo\n")         # a change for git diff and git status
    return repo


def _answer(cwd, command: str, host: str = "claude", **values: str) -> tuple[int, str | None, str]:
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(cwd),
                        "tool_input": {"command": command}})
    args = [] if host == "claude" else ["--host", host]
    proc = subprocess.run([sys.executable, "-I", w.G, *args], input=event, capture_output=True, text=True,
                          env=plugin_env(**values), timeout=120, check=False)
    out = json.loads(proc.stdout).get("hookSpecificOutput", {}) if proc.stdout.strip() else {}
    return proc.returncode, out.get("permissionDecision"), out.get("permissionDecisionReason") or ""


def _append(repo, text: str) -> None:
    with open(repo / ".git" / "config", "a") as fh:
        fh.write(text)


@pytest.mark.parametrize("value", VALUES)
@pytest.mark.parametrize("key", KEYS)
@pytest.mark.parametrize("cmd", list(COMMANDS))
def test_N19_a_read_form_with_an_uploadpack_key_is_free(tmp_path, main, cmd, key, value):
    w.git(main, "config", key, value)
    assert _answer(main, COMMANDS[cmd], **DELTA) == (0, None, "")


def test_N19_the_case_delta_measured_is_free_and_the_pass_is_the_read_profiles(tmp_path, main, monkeypatch):
    w.git(main, "config", "uploadpack.allowanysha1inwant", "true")
    assert _answer(main, "git log -3 --oneline", **DELTA) == (0, None, "")
    for name, value in DELTA.items():
        monkeypatch.setenv(name, value)
    out = gate.decide("git log -3 --oneline", str(main), time.monotonic() + 120, "claude")
    assert [v.reason_id for v in out.verdicts] == ["free_after_read_profile"], out.verdicts


@pytest.mark.parametrize("key", KEYS)
def test_N19_a_key_without_a_value_is_free(tmp_path, main, key):
    section, var = key.split(".", 1)
    _append(main, f"[{section}]\n\t{var}\n")
    assert _answer(main, COMMANDS["log"], **DELTA) == (0, None, "")


def test_N19_the_spelling_of_the_section_does_not_matter(tmp_path, main):
    _append(main, "[UploadPack]\n\tALLOWANYSHA1INWANT = true\n\tallowFilter = false\n")
    assert _answer(main, COMMANDS["status"], **DELTA) == (0, None, "")


@pytest.mark.parametrize("command", OTHER_FORMS)
def test_N19_every_other_read_form_with_all_five_keys_is_free(tmp_path, main, command):
    for key in KEYS:
        w.git(main, "config", key, "true")
    assert _answer(main, command, **DELTA) == (0, None, "")


def test_N19_a_key_through_an_include_is_free(tmp_path, main):
    included = tmp_path / "uploadpack.inc"
    included.write_text("[uploadpack]\n\tallowReachableSHA1InWant = true\n")
    w.git(main, "config", "include.path", str(included))
    assert _answer(main, COMMANDS["grep"], **DELTA) == (0, None, "")


def test_N19_a_key_from_the_hooks_environment_is_free(tmp_path, main):
    """GIT_CONFIG_COUNT and its pairs put the entry into the list git and the profile read (D34)."""
    names = {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "uploadpack.allowTipSHA1InWant", "GIT_CONFIG_VALUE_0": "1"}
    assert _answer(main, COMMANDS["show"], **DELTA, **names) == (0, None, "")


def test_N19_a_key_in_the_global_configuration_is_free(tmp_path, main):
    glob = tmp_path / "global.gitconfig"
    glob.write_text("[uploadpack]\n\tallowRefInWant = true\n")
    assert _answer(main, COMMANDS["log"], **DELTA, GIT_CONFIG_GLOBAL=str(glob)) == (0, None, "")


@pytest.mark.parametrize("where", ["local", "global"])
def test_N19_control_pack_objects_hook_names_a_program_and_asks(tmp_path, main, where):
    hook = w.proxy(tmp_path, tmp_path / "pack-objects-hook.sh", "hook")
    values = dict(DELTA)
    if where == "local":
        w.git(main, "config", "uploadpack.packObjectsHook", hook)
    else:
        glob = tmp_path / "global.gitconfig"
        glob.write_text(f"[uploadpack]\n\tpackObjectsHook = {hook}\n")
        values["GIT_CONFIG_GLOBAL"] = str(glob)
    w.git(main, "config", "uploadpack.allowAnySHA1InWant", "true")
    code, decision, reason = _answer(main, COMMANDS["log"], **values)
    assert (code, decision) == (0, "ask") and "uploadpack.packobjectshook" in reason, reason
    assert w.started(tmp_path) == []


@pytest.mark.parametrize("key", NEIGHBOURS)
def test_N19_control_a_neighbouring_key_asks(tmp_path, main, key):
    section, _, var = key.rpartition(".")
    if section.count(".") == 1:
        head, sub = section.split(".", 1)
        _append(main, f'[{head} "{sub}"]\n\t{var} = true\n')
    else:
        _append(main, f"[{section}]\n\t{var} = true\n")
    code, decision, reason = _answer(main, COMMANDS["log"], **DELTA)
    assert (code, decision) == (0, "ask"), (key, reason)
    assert "a configuration key the read profile does not know to start no program" in reason, reason
    assert key.lower() in reason, reason          # git prints section and name in lower case, every subsection is


@pytest.mark.parametrize("cmd", ["log", "status"])
def test_N19_control_under_codex_the_answer_stays(tmp_path, main, cmd):
    without = _answer(main, COMMANDS[cmd], "codex", **DELTA)
    for key in KEYS:
        w.git(main, "config", key, "true")
    with_keys = _answer(main, COMMANDS[cmd], "codex", **DELTA)
    assert with_keys == without and with_keys[1] is not None, (with_keys, without)


@pytest.mark.parametrize("finding", ["unknown_key", "promisor", "pager_unbound", "fsmonitor", "hook", "filter",
                                     "foreign_env"])
def test_N19_an_uploadpack_key_hides_no_other_finding(tmp_path, main, finding):
    """The key is written first, the other finding after it: at 1db350a1 the key was named, at the head the finding."""
    w.git(main, "config", "uploadpack.allowAnySHA1InWant", "true")
    values, command = dict(DELTA), COMMANDS["log"]
    if finding == "unknown_key":
        w.git(main, "config", "probe.unknown", "x")
        named = "probe.unknown"
    elif finding == "promisor":
        w.git(main, "config", "remote.origin.promisor", "true")
        named = "promisor"
    elif finding == "pager_unbound":
        _append(main, "[core]\n\tpager = less\n")         # a section of its own after the key, not the first [core]
        values.pop("AI_AGENT")
        named = "a pager:"
    elif finding == "fsmonitor":
        _append(main, f"[core]\n\tfsmonitor = {w.proxy(tmp_path, tmp_path / 'fsm.sh', 'fsmonitor')}\n")
        command, named = COMMANDS["status"], "fsmonitor"
    elif finding == "hook":
        w.proxy(tmp_path, main / ".git" / "hooks" / "post-index-change", "hook")
        command, named = COMMANDS["diff"], "a hook"
    elif finding == "filter":
        w.git(main, "config", "filter.probe.clean", "cat")
        command, named = COMMANDS["diff"], "a filter"
    else:
        values["GIT_PROBE_FOREIGN"] = "1"
        named = "GIT_PROBE_FOREIGN"
    code, decision, reason = _answer(main, command, **values)
    assert (code, decision) == (0, "ask") and named in reason, (finding, reason)
    assert "uploadpack.allowanysha1inwant" not in reason, reason  # the key, not the test's own path


@pytest.mark.parametrize("command", ["git -c uploadpack.allowAnySHA1InWant=true log -3 --oneline",
                                     "GIT_CONFIG_PARAMETERS=\"'uploadpack.allowanysha1inwant'='true'\" git log -3",
                                     "git -c uploadpack.packObjectsHook=true log -3 --oneline"])
def test_N19_control_a_key_set_by_the_command_keeps_its_ask(tmp_path, main, command):
    code, decision, reason = _answer(main, command, **DELTA)
    assert (code, decision) == (0, "ask"), (command, reason)


@pytest.mark.parametrize("command", ["git add README.md", "git commit -m one-more"])
def test_N19_control_the_state_check_is_not_changed(tmp_path, main, command):
    """K-NW-2 B (D3) keeps its own list; whether the five keys join it is O19-1 of the report."""
    if command.startswith("git commit"):
        w.git(main, "add", "README.md")
    assert _answer(main, command, **DELTA) == (0, None, "")
    w.git(main, "config", "uploadpack.allowAnySHA1InWant", "true")
    code, decision, reason = _answer(main, command, **DELTA)
    assert (code, decision) == (0, "ask") and "uploadpack.allowanysha1inwant" in reason, reason
