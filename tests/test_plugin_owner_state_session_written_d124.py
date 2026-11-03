"""D124 (Nachtrag 4, point 1; external review of -1, KERN finding 2 and K-6): owner state a session wrote frees nothing.

The gate reads files in its directory that only a person is to write (D25): the approval mode and the rules (D25),
the recorded hooks (D106), the pinned clone state (D114, D115), the owner's releases (D111, D119) and the declared work
folders (D104). Measured in review package -1 (messung/protection/k6_repro.txt) and again by the reviewer: the gate
gives `cd <gate directory> && echo with-approvals > mode` no answer under either host, the command runs, and the gate
then reads with-approvals. The same holds for every file of that directory written through a changed working directory,
and for the clone's hooks and .git/config (cd .git/hooks, cd .git; siblings_A.json of -1).

The property held here, for each of those files: a session runs the write in a form the gate does not answer (the
measured gap stays, it is asserted as the precondition of each case), and the gate's answer to the command the file
would free is the answer it gave before the write. The two siblings .git/hooks and .git/config count where the gate
consumes them: through a pin or a hook record the session wrote beside them. Without a protected channel, Guard Preview
consumes none of this state (PROOFBUNDLE_OWNER_STATE unset); the cases where a person's file frees a command keep their
tests with the explicit opt-in.

RED before D124: every case below, each with the free answer of its decision record after the session's write.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shlex
import subprocess
import sys
import time

import pytest
from _plugin_env import plugin_env

import test_plugin_n29_work_profile_d71 as d71
import test_plugin_n37_local_class_d91 as d91

gate = d71.gate
pytestmark = d71.pytestmark
_clean = d71._clean
GATE = pathlib.Path(gate.__file__).resolve()
SESSION = "operator-session-1"
HOOK_FORMS = {"claude": [], "claude --autonomous": ["--autonomous"], "codex": ["--host", "codex"]}
PRE_COMMIT = b"#!/bin/sh\n# the house's pre-commit\nexit 0\n"
SESSION_HOOK = "#!/bin/sh\n# a pre-commit the session wrote\nexit 0\n"


@pytest.fixture(autouse=True)
def _no_opt_in(monkeypatch, tmp_path):
    """Guard Preview's default: no protected channel, so no opt-in; the gate directory exists."""
    monkeypatch.delenv("PROOFBUNDLE_OWNER_STATE", raising=False)
    (tmp_path / "gatedir").mkdir(exist_ok=True)


def _gate_dir() -> pathlib.Path:
    return pathlib.Path(os.environ["PROOFBUNDLE_GATE_DIR"])


def _hook_answers(command: str, cwd: pathlib.Path, data: pathlib.Path) -> dict:
    """The decision of the shipped hook forms for the session's Bash call; None where the gate gives no answer."""
    answers = {}
    for name, flags in HOOK_FORMS.items():
        event = json.dumps({"hook_event_name": "PreToolUse", "session_id": SESSION, "tool_name": "Bash",
                            "cwd": str(cwd), "tool_input": {"command": command}})
        proc = subprocess.run([sys.executable, "-I", str(GATE), *flags], input=event, capture_output=True, text=True,
                              env=plugin_env(CLAUDE_PLUGIN_DATA=str(data), PLUGIN_DATA=str(data)), timeout=120,
                              check=False)
        assert proc.returncode == 0, proc.stderr
        answer = json.loads(proc.stdout) if proc.stdout.strip() else {}
        answers[name] = (answer.get("hookSpecificOutput") or {}).get("permissionDecision")
    return answers


def _session_writes(command: str, cwd: pathlib.Path, tmp_path: pathlib.Path) -> None:
    """The session's write: the gate gives it no answer on any host form (the measured gap of -1), and it runs."""
    data = tmp_path / "hookdata"
    data.mkdir(exist_ok=True)
    answers = _hook_answers(command, cwd, data)
    assert set(answers.values()) <= {None, "allow"}, (command, answers)
    subprocess.run(["bash", "-c", command], cwd=cwd, env=plugin_env(), check=True, timeout=60)


def _json_write(folder: pathlib.Path, name: str, data: object) -> str:
    return f"cd {shlex.quote(str(folder))} && printf '%s\\n' {shlex.quote(json.dumps(data))} > {name}"


def _decide(repo: pathlib.Path, command: str, host: str = "claude"):
    out = gate.decide(command, str(repo), time.monotonic() + 60, host)
    return None if out is None else (out.decision, [v.reason_id for v in out.verdicts])


# --- D25: the approval mode and a rule (the reproduction of k6_repro.txt) -------------------------------------------

def test_D124_a_mode_and_a_rule_the_session_wrote_free_nothing(tmp_path):
    repo = d71._repo(tmp_path, url=None, declaration=None, name="o")
    command = "git stash list"
    before = _decide(repo, command)
    assert before is not None and before[0] == "ask", before
    _session_writes(f"cd {shlex.quote(str(_gate_dir()))} && echo with-approvals > mode", repo, tmp_path)
    assert (_gate_dir() / "mode").read_text().strip() == "with-approvals"
    digest = gate._bound_state_digest(str(repo), time.monotonic() + 60, plugin_env())
    assert digest is not None
    common = os.path.realpath(d71._git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir").strip())
    rule = [{"repo": common, "form": command, "effect": "free", "state_digest": digest}]
    _session_writes(_json_write(_gate_dir(), "rules.json", rule), repo, tmp_path)
    assert _decide(repo, command) == before
    assert gate._read_mode(plugin_env()) == "strict"


def test_D124_a_transport_approval_the_session_wrote_is_not_read(tmp_path):
    """The hand-over of D35 needs with-approvals and a person's approval of the transport in transports.json; the
    approval a session wrote is not read, so no hand-over rests on it (the full hand-over path is not built here)."""
    repo = d71._repo(tmp_path, name="o")
    approval = [{"repo": str(repo / ".git"), "remote": "origin", "url": "https://github.com/b7n0de/proofbundle",
                 "transport_digest": "0" * 64}]
    _session_writes(_json_write(_gate_dir(), gate.TRANSPORTS_FILE, approval), repo, tmp_path)
    assert gate._read_transports(plugin_env()) == []


# --- D106 and D114: the clone's hooks and .git/config, consumed through a record or a pin the session wrote ----------

def _own_clone(tmp_path: pathlib.Path, pinned: bool = True) -> pathlib.Path:
    """A clone of D71 with the repository's own pre-commit hook and a change to add; for the pin of D114 on its own
    claude/ branch with a configuration key the profiles do not know, for the record of D106 on topic without one."""
    repo = d71._repo(tmp_path, url="https://github.com/someone/x.git", name="f")
    if pinned:
        d71._git(repo, "checkout", "-q", "-b", "claude/work", "topic")
        d71._git(repo, "config", "frob.knob", "1")
    else:
        d71._git(repo, "checkout", "-q", "topic")
    hooks = repo / ".git" / "hooks"
    hooks.mkdir(exist_ok=True)
    (hooks / "pre-commit").write_bytes(PRE_COMMIT)
    (hooks / "pre-commit").chmod(0o755)
    (repo / "notes.md").write_text("changed\n")
    return repo


def _sha_file(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_D124_a_hook_and_config_the_session_changed_and_pinned_free_no_commit(tmp_path):
    repo = _own_clone(tmp_path)
    command = "git commit -m work"
    before = d91.answered(repo, command)
    assert before[0] in ("ask", "deny") and "free_pinned_state" not in before[1], before
    _session_writes(f"cd .git/hooks && printf '%s' {shlex.quote(SESSION_HOOK)} > pre-commit", repo, tmp_path)
    _session_writes("cd .git && printf '[frob]\\n\\tknob2 = 2\\n' >> config", repo, tmp_path)
    assert (repo / ".git" / "hooks" / "pre-commit").read_text() == SESSION_HOOK
    hooks = repo / ".git" / "hooks"
    pin = {"schema": gate.PIN_STATE_SCHEMA, "klone": [{
        "pfad": str(repo), "hakenordner": str(hooks),
        "haken": {p.name: _sha_file(p) for p in sorted(hooks.iterdir()) if p.is_file() and not p.name.endswith(".sample")},
        "konfig": _sha_file(repo / ".git" / "config")}]}
    _session_writes(_json_write(_gate_dir(), gate.PIN_STATE_FILE, pin), repo, tmp_path)
    after = d91.answered(repo, command)
    assert "free_pinned_state" not in after[1] and after[0] == before[0], after


def test_D124_a_hook_record_the_session_wrote_frees_no_commit(tmp_path):
    repo = _own_clone(tmp_path, pinned=False)
    command = "git commit -m work"
    before = d91.answered(repo, command)
    assert before[0] in ("ask", "deny") and "free_recorded_hooks" not in before[1], before
    _session_writes(f"cd .git/hooks && printf '%s' {shlex.quote(SESSION_HOOK)} > pre-commit", repo, tmp_path)
    record = {"schema": gate.HOOK_STATE_SCHEMA,
              "klone": [{"pfad": str(repo), "haken": {"pre-commit": _sha_file(repo / ".git" / "hooks" / "pre-commit")}}]}
    _session_writes(_json_write(_gate_dir(), gate.HOOK_STATE_FILE, record), repo, tmp_path)
    after = d91.answered(repo, command)
    assert "free_recorded_hooks" not in after[1] and after[0] == before[0], after


# --- D111: an owner's release the session wrote -----------------------------------------------------------------------

def test_D124_a_release_the_session_wrote_frees_no_pull_request(tmp_path, monkeypatch):
    monkeypatch.setenv("CLAUDE_CODE_SESSION_ID", SESSION)
    data = tmp_path / "data"
    data.mkdir()
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(data))
    repo = d71._repo(tmp_path)
    command = "gh pr create -R b7n0de/proofbundle --base main --head topic --title t --body b"
    before = d91.answered(repo, command)
    assert before[0] in ("ask", "deny"), before
    release = {"schema": gate.RELEASE_SCHEMA, "karte": "OA-0123456789", "sitzung": SESSION,
               "sha256": hashlib.sha256(command.encode("utf-8")).hexdigest(),
               "antwort": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 30))}
    _session_writes(f"cd {shlex.quote(str(_gate_dir()))} && mkdir {gate.RELEASES_DIR}", repo, tmp_path)
    _session_writes(_json_write(_gate_dir() / gate.RELEASES_DIR, "OA-0123456789-0.json", release), repo, tmp_path)
    after = d91.answered(repo, command)
    assert "released_by_owner" not in after[1] and after[0] == before[0], after


# --- D104: a work folder the session declared ---------------------------------------------------------------------------

@pytest.mark.parametrize("host", ("claude", "codex"))
def test_D124_a_work_folder_the_session_declared_widens_nothing(tmp_path, host):
    repo = d71._repo(tmp_path, url=None, declaration=None, name="o")
    outside = tmp_path / "outside"
    outside.mkdir()
    command = f"echo x >> {outside}/a.log"
    before = _decide(repo, command, host)
    assert before is not None and "append_outside_work" in before[1], before
    folders = {"schema": "proofbundle-plugin/work-folders/v0.1", "ordner": [{"name": "cache", "pfad": str(outside)}]}
    _session_writes(_json_write(_gate_dir(), gate.WORK_FOLDERS_FILE, folders), repo, tmp_path)
    assert _decide(repo, command, host) == before
