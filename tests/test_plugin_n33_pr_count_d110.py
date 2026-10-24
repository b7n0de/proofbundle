"""D110, Nachtrag 33 point 6 (owner choice O30-1 A, fallbook C2): the open pull requests of a session are counted.

The order: a counter of open pull requests per session in the plugin data directory, kept by the hook after a call
(PostToolUse), taken down at `gh pr merge` and `gh pr close` of the session; house rule H3 (D73, at most 8) reads it.
C2 of the fallbook: the gate asks at `gh pr create` because the session already holds 8 open pull requests.

Measured with Claude Code 2.1.303 and the stand-in API (n41/werkzeug/truth_post_n41.sh): PostToolUse of a Bash call
carries tool_response.stdout with what the call printed; PostToolUseFailure carries no tool_response, only error;
CLAUDE_CODE_SESSION_ID in the environment of each hook equals the session_id of its event.

The rule: proofbundle_answered.py, after a Bash call that ran, adds to the session's list each address of a pull
request the output names where the command may open one (gh pr create or new, createPullRequest, gh api on …/pulls that
writes), else one entry of unknown number, so the count is never too low; it takes off the entry `gh pr merge|close
<number or address>` names, as a whole command of its own. H3 drops its ask where the count of the session is below 8,
asks with the count where it is 8 or more (house_pr_limit_reached), and asks as before where it cannot read the count.

RED at 63b88d07: the count and the rule that reads it. The controls (no session, a count it cannot read) are green at
both.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

import pytest

from test_plugin_n30_short_line_d72 import _clean, _line, _outcome, _repo, gate, pytestmark  # noqa: F401

ANSWER_HOOK = pathlib.Path(gate.__file__).parent / "proofbundle_answered.py"
SESSION = "sess-d110"
CREATE = "gh pr create -R b7n0de/proofbundle --base main --head topic --title t --body-file notes.md"
URL = "https://github.com/b7n0de/proofbundle/pull/{n}"


@pytest.fixture
def data(tmp_path, monkeypatch):
    folder = tmp_path / "data"
    folder.mkdir()
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(folder))
    monkeypatch.setenv("CLAUDE_CODE_SESSION_ID", SESSION)
    return folder


def _post(folder, command, stdout="", event="PostToolUse", session=SESSION, tool_use_id="toolu_1"):
    body = {"hook_event_name": event, "tool_name": "Bash", "session_id": session, "tool_use_id": tool_use_id,
            "tool_input": {"command": command}}
    if event == "PostToolUse":
        body["tool_response"] = {"stdout": stdout, "stderr": "", "interrupted": False, "isImage": False}
    else:
        body["error"] = "Exit code 1\n" + stdout
    proc = subprocess.run([sys.executable, "-I", str(ANSWER_HOOK)], input=json.dumps(body), text=True,
                          capture_output=True, timeout=60, env={"PATH": os.environ["PATH"], "CLAUDE_PLUGIN_DATA": str(folder)})
    assert proc.returncode == 0 and proc.stdout == "", proc


def _open(folder, session=SESSION):
    path = folder / "open-prs.json"
    if not path.exists():
        return []
    data = json.loads(path.read_text())
    assert data["schema"] == "proofbundle-plugin/open-prs/v0.1"
    return data["sitzungen"].get(session, [])


# --- the counter ---------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("command, stdout, expected", [
    (CREATE, URL.format(n=101) + "\n", ["b7n0de/proofbundle#101"]),
    ("gh pr create --title t --body \"$(cat <<'EOF'\nText.\nEOF\n)\"", URL.format(n=102), ["b7n0de/proofbundle#102"]),
    ("cd /w && gh pr create --fill", URL.format(n=103), ["b7n0de/proofbundle#103"]),
    ("gh -R b7n0de/proofbundle pr new --title t --body b", URL.format(n=104), ["b7n0de/proofbundle#104"]),
    ("gh api repos/b7n0de/proofbundle/pulls -f title=t -f head=topic -f base=main",
     json.dumps({"html_url": URL.format(n=105), "diff_url": URL.format(n=105) + ".diff"}), ["b7n0de/proofbundle#105"]),
    ("gh api -X POST /repos/b7n0de/proofbundle/pulls --input pr.json", json.dumps({"html_url": URL.format(n=106)}),
     ["b7n0de/proofbundle#106"]),
    ("gh api graphql -f query='mutation { createPullRequest(input: {}) { pullRequest { url } } }'",
     json.dumps({"data": {"createPullRequest": {"pullRequest": {"url": URL.format(n=107)}}}}), ["b7n0de/proofbundle#107"]),
])
def test_D110_a_call_that_opens_a_pull_request_counts_it(data, command, stdout, expected):
    _post(data, command, stdout)
    assert _open(data) == expected


def test_D110_without_an_address_in_the_output_the_count_still_goes_up(data):
    _post(data, CREATE + " > out.txt", "", tool_use_id="toolu_a")
    _post(data, CREATE + " | tail -1", "something else", tool_use_id="toolu_b")
    entries = _open(data)
    assert len(entries) == 2 and all(e.startswith("?") for e in entries), entries


@pytest.mark.parametrize("command, stdout", [
    ("gh api repos/b7n0de/proofbundle/pulls", json.dumps([{"html_url": URL.format(n=k)} for k in range(1, 30)])),
    ("gh api -X GET repos/b7n0de/proofbundle/pulls -f state=open", json.dumps([{"html_url": URL.format(n=5)}])),
    ("gh pr list", URL.format(n=7)), ("gh pr view 7 --json url", json.dumps({"url": URL.format(n=7)})),
    ("git log --oneline", URL.format(n=8)),
])
def test_D110_control_a_read_counts_nothing(data, command, stdout):
    _post(data, command, stdout)
    assert _open(data) == [], command


def test_D110_a_text_that_only_names_the_form_counts_too_the_count_errs_high_never_low(data):
    _post(data, "echo gh pr create", "gh pr create")
    assert len(_open(data)) == 1


def test_D110_a_call_that_failed_counts_nothing(data):
    _post(data, CREATE, URL.format(n=101), event="PostToolUseFailure")
    assert _open(data) == []


@pytest.mark.parametrize("command", ["gh pr merge 101 --squash", "gh pr merge 101 -R b7n0de/proofbundle --auto --merge",
                                     "gh pr close 101", f"gh pr close {URL.format(n=101)}",
                                     "gh pr merge --repo=b7n0de/proofbundle 101 --rebase"])
def test_D110_merge_and_close_of_one_of_them_take_it_off(data, command):
    _post(data, CREATE, URL.format(n=101), tool_use_id="toolu_c1")
    _post(data, CREATE, URL.format(n=102), tool_use_id="toolu_c2")
    _post(data, command)
    assert _open(data) == ["b7n0de/proofbundle#102"], command


@pytest.mark.parametrize("command", ["gh pr merge 101 && echo done", "gh pr merge", "gh pr merge topic",
                                     "gh pr merge 101 -R someone/else", "gh pr merge 0101", "echo gh pr close 101",
                                     "gh pr merge 101 $(echo)"])
def test_D110_control_a_merge_the_counter_cannot_bind_takes_nothing_off(data, command):
    _post(data, CREATE, URL.format(n=101))
    _post(data, command)
    assert _open(data) == ["b7n0de/proofbundle#101"], command


def test_D110_a_number_two_repositories_hold_takes_nothing_off_and_other_sessions_stay(data):
    _post(data, CREATE, URL.format(n=5), tool_use_id="t1")
    _post(data, "gh pr create -R b7n0de/other --fill", "https://github.com/b7n0de/other/pull/5", tool_use_id="t2")
    _post(data, CREATE, URL.format(n=9), session="other-session", tool_use_id="t3")
    _post(data, "gh pr merge 5")
    assert sorted(_open(data)) == ["b7n0de/other#5", "b7n0de/proofbundle#5"]
    _post(data, "gh pr merge 9")
    assert _open(data, "other-session") == ["b7n0de/proofbundle#9"]
    _post(data, "gh pr merge 5 -R b7n0de/other")
    assert _open(data) == ["b7n0de/proofbundle#5"]


def test_D110_the_count_keeps_the_sessions_written_last(data):
    for k in range(70):
        _post(data, CREATE, URL.format(n=k + 1), session=f"s{k}", tool_use_id=f"t{k}")
    sessions = json.loads((data / "open-prs.json").read_text())["sitzungen"]
    assert len(sessions) == 64 and "s0" not in sessions and "s69" in sessions


def test_D110_the_count_never_changes_the_answer_of_an_ask(data):
    """D94 goes on as before: a pending ask of the same call is answered and logged."""
    key = __import__("hashlib").sha256(b"toolu_ask").hexdigest()[:32]
    (data / "asks-pending.json").write_text(json.dumps({"schema": "proofbundle-plugin/asks-pending/v0.1", "asks": {
        key: {"ts": "2026-10-19T10:00:00Z", "gruende": ["house_pr_limit"], "session_id": SESSION}}}))
    _post(data, CREATE, URL.format(n=101), tool_use_id="toolu_ask")
    log = [json.loads(line) for line in (data / "gate-log.jsonl").read_text().splitlines()]
    assert log[-1]["antwort"] == "ja" and _open(data) == ["b7n0de/proofbundle#101"]
    (data / "open-prs.json").write_text("{not json")
    _post(data, CREATE, URL.format(n=102), tool_use_id="toolu_x")   # an unreadable count: exit 0, no output


# --- house rule H3 reads it ----------------------------------------------------------------------------------------

def _count(folder, n, session=SESSION):
    entries = [f"b7n0de/proofbundle#{k}" for k in range(1, n + 1)]
    (folder / "open-prs.json").write_text(json.dumps({"schema": "proofbundle-plugin/open-prs/v0.1",
                                                      "sitzungen": {session: entries}}))


def _ids(out):
    return [v.reason_id for v in out.verdicts]


@pytest.mark.parametrize("n", [0, 1, 7])
def test_D110_below_the_limit_h3_asks_no_more(tmp_path, data, n):
    if n:
        _count(data, n)
    out = _outcome(_repo(tmp_path), CREATE, "claude")
    assert out is None or not {"house_pr_limit", "house_pr_limit_reached"} & set(_ids(out)), _ids(out)


@pytest.mark.parametrize("n", [8, 9, 20])
def test_D110_at_the_limit_h3_asks_and_the_line_names_the_count(tmp_path, data, n):
    _count(data, n)
    out = _outcome(_repo(tmp_path), CREATE, "claude")
    assert out.decision == "ask" and "house_pr_limit_reached" in _ids(out) and "house_pr_limit" not in _ids(out)
    reached = next(v for v in out.verdicts if v.reason_id == "house_pr_limit_reached")
    assert f"this session holds {n}" in reached.detail
    assert "already holds 8 or more open PRs" in _line(out, "claude")
    assert "schon 8 oder mehr offene PRs" in _line(out, "claude", "de")


@pytest.mark.parametrize("form", ["gh pr new --title t --body b", "gh api repos/b7n0de/proofbundle/pulls -f title=t -f head=x -f base=main",
                                  "gh api graphql -f query='mutation { createPullRequest(input: {}) { clientMutationId } }'"])
def test_D110_every_form_of_h3_reads_the_count(tmp_path, data, form):
    repo = _repo(tmp_path)
    _count(data, 8)
    assert "house_pr_limit_reached" in _ids(_outcome(repo, form, "claude"))
    _count(data, 2)
    out = _outcome(repo, form, "claude")
    assert out is None or "house_pr_limit_reached" not in _ids(out) and "house_pr_limit" not in _ids(out)


def test_D110_the_pull_requests_of_another_session_do_not_count(tmp_path, data):
    _count(data, 12, session="another")
    out = _outcome(_repo(tmp_path), CREATE, "claude")
    assert out is None or not {"house_pr_limit", "house_pr_limit_reached"} & set(_ids(out))


@pytest.mark.parametrize("how", ["no session", "no data folder", "relative folder", "not json", "repeated key",
                                 "other schema", "a folder", "too big"])
def test_D110_control_where_the_count_cannot_be_read_h3_asks_as_before(tmp_path, data, monkeypatch, how):
    path = data / "open-prs.json"
    if how == "no session":
        monkeypatch.delenv("CLAUDE_CODE_SESSION_ID")
    elif how == "no data folder":
        monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(tmp_path / "nowhere"))
    elif how == "relative folder":
        monkeypatch.setenv("CLAUDE_PLUGIN_DATA", "data")
    elif how == "not json":
        path.write_text("{")
    elif how == "repeated key":
        path.write_text('{"schema": "proofbundle-plugin/open-prs/v0.1", "sitzungen": {"%s": ["a#1"] , "%s": []}}'
                        % (SESSION, SESSION))
    elif how == "other schema":
        path.write_text(json.dumps({"schema": "x", "sitzungen": {SESSION: []}}))
    elif how == "a folder":
        path.mkdir()
    else:
        path.write_text(json.dumps({"schema": "proofbundle-plugin/open-prs/v0.1", "sitzungen": {SESSION: []},
                                    "pad": "x" * (256 * 1024)}))
    out = _outcome(_repo(tmp_path), CREATE, "claude")
    assert out.decision == "ask" and "house_pr_limit" in _ids(out), (how, _ids(out))


def test_D110_under_codex_h3_stays(tmp_path, data):
    out = _outcome(_repo(tmp_path), CREATE, "codex")
    assert out.decision in ("ask", "deny")


def test_D110_the_count_from_the_hook_reaches_h3(tmp_path, data):
    repo = _repo(tmp_path)
    for k in range(8):
        _post(data, CREATE, URL.format(n=200 + k), tool_use_id=f"toolu_{k}")
    assert "house_pr_limit_reached" in _ids(_outcome(repo, CREATE, "claude"))
    _post(data, "gh pr merge 203 --squash")
    out = _outcome(repo, CREATE, "claude")
    assert out is None or not {"house_pr_limit", "house_pr_limit_reached"} & set(_ids(out))


def test_D110_the_reasons():
    assert gate._SHORT_REASONS["house_pr_limit_reached"][0] == "D110" and "house_pr_limit_reached" in gate.FANG_REASONS
    assert "house_pr_limit" not in gate.FANG_REASONS
