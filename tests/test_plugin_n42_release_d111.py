"""D111, Nachtrag 42: an owner's release on a card frees exactly one command once.

The order (owner word of 2026-10-19, 16:32 Berlin, way A: work from the phone, not in the terminal): today the owner
typed lines with `!` into delta's terminal twice, though he had answered A on the card in the Leitstand (the bundle
fetch, card OA-aab72ad709; `git add` and `git commit` for PR 328, card OA-bd5cf3ae01). D93 makes an external effect a
card, D94 counts yes and no; what was missing is the way back from the answer to the gate. A release of the owner frees
exactly one command once: bound to the sha256 of the command as written, to the session that put the card and to 15
minutes from the answer. Its source is a file only the fetcher at the farmer writes, never the session; a write of the
session into it or its folder is denied with the weight of _D72_WRITES. A second call, another command, another
session or an expired release stay blocked. The log names the card and the sha256, the bilanz counts the release.

The rule: the fetcher leaves one file per release in the folder freigaben of the gate's directory (D25: only a person,
or the fetcher in the person's place, writes there; a write of the session there is write_to_gate_dir), `{"schema":
"proofbundle-plugin/freigabe/v0.1", "karte": "OA-<10 hex>", "sitzung": <session id>, "sha256": <64 hex>, "antwort":
"<YYYY-MM-DDTHH:MM:SSZ>"}`. In autonomous operation, for a Bash call decide() asked about and the autonomous answer
does not let run (a card, a block, a detour, the owner's ask), a release whose sha256 is that of the command's words,
whose session is the hook's (CLAUDE_CODE_SESSION_ID) and whose answer lies at most 15 minutes back lets it run once
(released_by_owner, klasse freigabe): the use is written to the plugin data directory first, under a lock. A deny of
decide() stays a deny.

RED at the head of Nachtrag 41: every release. The catch cases and the controls are green at both.
"""
from __future__ import annotations

import calendar
import hashlib
import json
import os
import pathlib
import sys
import time

import pytest

import _gate_answer as ga
import test_plugin_n29_work_profile_d71 as d71

gate = d71.gate
pytestmark = d71.pytestmark
_clean = d71._clean
SESSION = "kraxo-session-1"
SCHEMA = "proofbundle-plugin/freigabe/v0.1"
CARD = "OA-bd5cf3ae01"


@pytest.fixture
def env(tmp_path, monkeypatch):
    data = tmp_path / "data"
    data.mkdir()
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(data))
    monkeypatch.setenv("CLAUDE_CODE_SESSION_ID", SESSION)
    (tmp_path / "gatedir").mkdir(exist_ok=True)
    return tmp_path


def _sha(command: str) -> str:
    return hashlib.sha256(command.encode("utf-8")).hexdigest()


def _stamp(seconds_ago: float = 30) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - seconds_ago))


def _release(tmp_path, command, card=CARD, session=SESSION, ago=30.0, name=None, text=None, **extra):
    folder = tmp_path / "gatedir" / "freigaben"
    folder.mkdir(parents=True, exist_ok=True)
    body = {"schema": SCHEMA, "karte": card, "sitzung": session, "sha256": _sha(command), "antwort": _stamp(ago),
            **extra}
    if card is None:
        del body["karte"]
    path = folder / (name or f"{card or 'ohne'}-{len(list(folder.iterdir()))}.json")
    path.write_text(json.dumps(body) if text is None else text)
    return path


def _repo(tmp_path, kind="fremd", hook=True):
    repo = {"b7n0de": lambda: d71._repo(tmp_path),
            "fremd": lambda: d71._repo(tmp_path, url="https://github.com/someone/x.git", name="f")}[kind]()
    if hook:
        h = repo / ".git" / "hooks" / "pre-commit"
        h.write_text("#!/bin/sh\nexit 0\n")
        h.chmod(0o755)
    (repo / "notes.md").write_text("changed\n")
    return repo


def answered(repo, command, host="claude"):
    deadline = time.monotonic() + 60
    out = gate.decide(command, str(repo), deadline, host)
    if host == "claude" and out is not None and out.decision == "ask":
        out = gate.autonomous_outcome(out, command, str(repo), deadline, host)
    if out is None:
        return None, [], None
    return out.decision, [v.reason_id for v in out.verdicts], (getattr(out, "autonomy", None) or {}).get("klasse")


#: Commands the gate does not let run under --autonomous today, each an ask of decide(): delta's commit of PR 328 with
#: a pre-commit hook (blocked), a reset that discards work (blocked), in the profile of b7n0de a pull request (a card
#: of D93), and a forced push, which the autonomous answer blocks for its target (D86) and the dialog of the terminal
#: could let run: a release is the owner's yes to exactly that call, as that dialog's is (owner question in the
#: report).
BLOCKED = [("fremd", "git add -A && git commit -m 'PR 328'"), ("fremd", "git reset --hard HEAD~1"),
           ("b7n0de", "gh pr create -R b7n0de/proofbundle --base main --head topic --title t --body b"),
           ("fremd", "git push --force origin main")]


@pytest.mark.parametrize("kind, command", BLOCKED)
def test_D111_a_release_frees_exactly_that_command_once(env, kind, command):
    repo = _repo(env, kind)
    before = answered(repo, command)
    assert before[0] in ("ask", "deny") and before[0] != "pass", before
    _release(env, command)
    decision, reasons, klasse = answered(repo, command)
    assert (decision, klasse) == ("pass", "freigabe") and "released_by_owner" in reasons, (decision, reasons, klasse)
    again = answered(repo, command)
    assert again[0] == before[0] and "released_by_owner" not in again[1], again


def test_D111_two_releases_free_the_command_twice_and_no_more(env):
    repo = _repo(env)
    command = BLOCKED[0][1]
    _release(env, command, card="OA-0000000001")
    _release(env, command, card="OA-0000000002")
    assert answered(repo, command)[0] == "pass"
    assert answered(repo, command)[0] == "pass"
    assert answered(repo, command)[0] != "pass"


# --- the catch cases of the order: each stays as it is without a release ------------------------------------------

COMMAND = "git add -A && git commit -m 'PR 328'"
OTHERS = [COMMAND + "x", "git add -A && git commit -m 'PR 328' ", "git add -A  && git commit -m 'PR 328'",
          COMMAND + " && git push origin topic", COMMAND + " > out.txt", COMMAND + " && echo done",
          "git add -A && git commit -m 'PR 329'"]


@pytest.mark.parametrize("other", OTHERS)
def test_D111_another_spelling_of_the_command_stays_blocked(env, other):
    repo = _repo(env)
    _release(env, COMMAND)
    before = gate.decide(other, str(repo), time.monotonic() + 60, "claude")
    decision, reasons, _klasse = answered(repo, other)
    assert "released_by_owner" not in reasons and (before is None or decision != "pass" or before.decision != "ask"), \
        (other, decision, reasons)


@pytest.mark.parametrize("how", ["delta in the session of kraxo", "yesterday", "16 minutes ago", "no card id",
                                 "a card id of another shape", "an answer in the future", "an upper-case sha256",
                                 "a key more", "a repeated key", "another schema", "not json", "a link",
                                 "a folder", "too big", "a time of another shape", "a time without leading zeros",
                                 "not a .json file"])
def test_D111_a_release_that_does_not_bind_frees_nothing(env, how):
    repo = _repo(env)
    before = answered(repo, COMMAND)
    body = {"schema": SCHEMA, "karte": CARD, "sitzung": SESSION, "sha256": _sha(COMMAND), "antwort": _stamp()}
    if how == "delta in the session of kraxo":
        _release(env, COMMAND, session="delta-session-7")
    elif how == "yesterday":
        _release(env, COMMAND, ago=24 * 3600)
    elif how == "16 minutes ago":
        _release(env, COMMAND, ago=16 * 60)
    elif how == "no card id":
        _release(env, COMMAND, card=None)
    elif how == "a card id of another shape":
        _release(env, COMMAND, card="OA-XYZ")
    elif how == "an answer in the future":
        _release(env, COMMAND, ago=-5 * 60)
    elif how == "an upper-case sha256":
        _release(env, COMMAND, text=json.dumps(dict(body, sha256=_sha(COMMAND).upper())))
    elif how == "a key more":
        _release(env, COMMAND, notiz="x")
    elif how == "a repeated key":
        _release(env, COMMAND, text=json.dumps(body)[:-1] + ', "sitzung": "%s"}' % SESSION)
    elif how == "another schema":
        _release(env, COMMAND, text=json.dumps(dict(body, schema="proofbundle-plugin/freigabe/v0.2")))
    elif how == "not json":
        _release(env, COMMAND, text="{")
    elif how == "a link":
        target = env / "elsewhere.json"
        target.write_text(json.dumps(body))
        folder = env / "gatedir" / "freigaben"
        folder.mkdir(parents=True)
        (folder / "link.json").symlink_to(target)
    elif how == "a folder":
        (env / "gatedir" / "freigaben" / "x.json").mkdir(parents=True)
    elif how == "too big":
        _release(env, COMMAND, text=json.dumps(body) + " " * 5000)
    elif how == "a time of another shape":
        _release(env, COMMAND, text=json.dumps(dict(body, antwort=str(int(time.time())))))
    elif how == "a time without leading zeros":
        moment = int(time.time()) // 60 * 60 - 55   # about a minute ago, its second a single digit (5)
        t = time.gmtime(moment)
        _release(env, COMMAND, text=json.dumps(dict(body, antwort=time.strftime("%Y-%m-%dT%H:%M:", t) + f"{t.tm_sec}Z")))
    else:
        _release(env, COMMAND, name="release.txt")
    after = answered(repo, COMMAND)
    assert after[0] == before[0] and "released_by_owner" not in after[1], (how, after)


def test_D111_a_release_frees_no_deny_of_decide(env):
    repo = _repo(env)
    for command in ("git push --no-verify origin topic", "echo x > ~/.ssh/config", "gh pr merge 12 --admin --merge",
                    f"echo x > {env / 'gatedir' / 'mode'}"):
        _release(env, command)
        out = gate.decide(command, str(repo), time.monotonic() + 60, "claude")
        assert out.decision == "deny", command
        answer = gate.autonomous_outcome(out, command, str(repo), time.monotonic() + 60, "claude")
        assert answer.decision == "deny" and "released_by_owner" not in [v.reason_id for v in answer.verdicts], command
        decision, reasons, _klasse = answered(repo, command)
        assert decision == "deny" and "released_by_owner" not in reasons, (command, reasons)


def test_D111_without_the_data_folder_no_release_can_be_counted_and_none_frees(env, monkeypatch):
    repo = _repo(env)
    _release(env, COMMAND)
    monkeypatch.delenv("CLAUDE_PLUGIN_DATA")
    assert answered(repo, COMMAND)[0] != "pass"
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(env / "nowhere"))
    assert answered(repo, COMMAND)[0] != "pass"


def test_D111_control_under_codex_and_without_the_flag_nothing_is_released(env):
    repo = _repo(env)
    _release(env, COMMAND)
    out = gate.decide(COMMAND, str(repo), time.monotonic() + 60, "codex")
    assert out is not None and out.decision in ("ask", "deny")
    assert answered(repo, COMMAND, "codex")[0] in ("ask", "deny")
    out = gate.decide(COMMAND, str(repo), time.monotonic() + 60, "claude")
    assert out.decision == "ask" and "released_by_owner" not in [v.reason_id for v in out.verdicts]


@pytest.mark.parametrize("form", ["echo '{{}}' > {G}/freigaben/x.json", "cp {T}/x.json {G}/freigaben/x.json",
                                  "tee {G}/freigaben/x.json < {T}/x.json", "mkdir -p {G}/freigaben",
                                  "rm -rf {G}/freigaben", "mv {T}/x.json {G}/freigaben/"])
def test_D111_the_session_cannot_write_a_release_or_its_folder(env, form):
    repo = _repo(env)
    command = form.replace("{G}", str(env / "gatedir")).replace("{T}", str(env))
    out = gate.decide(command, str(repo), time.monotonic() + 60, "claude")
    assert out is not None and out.decision == "deny" and "write_to_gate_dir" in [v.reason_id for v in out.verdicts], \
        (form, out and [v.reason_id for v in out.verdicts])
    for tool in ("Write", "Edit"):
        out = gate.decide_write(tool, {"file_path": str(env / "gatedir" / "freigaben" / "x.json"), "content": "{}",
                                       "old_string": "a", "new_string": "b"}, str(repo), time.monotonic() + 60, "claude")
        assert out is not None and out.decision == "deny"


def _hook(repo, env, command, flag=True):
    event = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(repo), "session_id": SESSION,
             "tool_use_id": "toolu_d111", "tool_input": {"command": command}}
    keep = ("PATH", "HOME", "LC_ALL", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "PROOFBUNDLE_GATE_DIR",
            "CLAUDE_PLUGIN_DATA", "CLAUDE_CODE_SESSION_ID")
    proc, entry = ga.run_hook([sys.executable, "-I", gate.__file__, "--host", "claude",
                               *([gate.AUTONOMOUS_FLAG] if flag else [])], json.dumps(event),
                              {k: os.environ[k] for k in keep}, cwd=str(repo))
    assert proc.returncode == 0, proc.stderr
    return proc, entry


def test_D111_the_hook_lets_it_run_with_a_line_and_the_log_names_card_and_sha256(env):
    repo = _repo(env)
    _release(env, COMMAND)
    proc, entry = _hook(repo, env, COMMAND)
    printed = json.loads(proc.stdout)
    assert "permissionDecision" not in printed["hookSpecificOutput"], printed
    assert CARD in printed["systemMessage"], printed
    assert entry["autonomy"]["klasse"] == "freigabe" and "released_by_owner" in entry["reason_ids"], entry
    assert entry["quittung"] == {"art": "freigabe", "karte": CARD, "sha256": _sha(COMMAND),
                                 "antwort": entry["quittung"]["antwort"]}, entry
    proc, entry = _hook(repo, env, COMMAND)
    assert json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
    log = pathlib.Path(os.environ["CLAUDE_PLUGIN_DATA"]) / "gate-log.jsonl"
    lines = [json.loads(line) for line in log.read_text().splitlines()]
    totals = gate.bilanz(lines, period="gesamt")["zeitraeume"][0]
    assert totals["freigaben"] == 1, totals


def test_D111_control_without_the_flag_the_hook_asks_and_uses_no_release(env):
    repo = _repo(env)
    _release(env, COMMAND)
    proc, entry = _hook(repo, env, COMMAND, flag=False)
    assert json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert answered(repo, COMMAND)[0] == "pass"   # the release is still there, unused


def test_D111_the_reason_and_the_sha256_of_the_words():
    assert gate._SHORT_REASONS["released_by_owner"][0] == "D111" and "released_by_owner" not in gate.FANG_REASONS
    assert gate.command_sha256("git status") == hashlib.sha256(b"git status").hexdigest()
    assert calendar.timegm(time.gmtime(0)) == 0
