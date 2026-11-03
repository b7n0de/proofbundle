"""D105, follow-up note 33 (fallbook S6, S8): a hint, a pass with a line and a context for the model, never an ask.

The order: S6, S8 and S10 are hints in reading 2 of the review session (go on with a message to the agent, no ask); measure which
way brings the message into the context of the agent without an ask. Found by account A's fallbook: `mv <manifest> <path>`
took the manifest out of the package (meant was cp), `cat > /tmp/<file> <<…` wrote outside the scratch of the session.

Measured with Claude Code 2.1.303 and the stand-in API (truth_host_n33.sh hint, one hook per variant): the
additionalContext of a PreToolUse hook without a permission decision reached the model, as a system message after the
tool's result, and the call ran; a systemMessage, plain stdout and stderr did not reach the model; the additionalContext
of a PostToolUse hook did too, after the call.

The rule: _guard_hints gives a pass with hint_move_out where mv takes a file of the repository out of it, and, in a
session of Claude Code (CLAUDE_CODE_SESSION_ID), hint_tmp_not_scratch where a step writes into /tmp or the temp folder
outside the folder of the session; the hook prints the short line (systemMessage) and the long reason as context, no
permissionDecision. S10 is no rule: the fallbook's form carries no redirection (owner question O33-4).

RED at 63b88d07: S6 and S8 got no output at all. The controls get no hint.
"""
from __future__ import annotations

import os
import time

import pytest

import test_plugin_n30_short_line_d72 as d72

gate = d72.gate
pytestmark = d72.pytestmark
_clean = d72._clean
SESSION = "sess-hint"


@pytest.fixture
def repo(tmp_path, monkeypatch):
    r = d72._repo(tmp_path)
    (r / "MANIFEST.json").write_text("{}\n")
    temp = tmp_path / "temp"
    (temp / f"claude-{os.getuid()}" / "-proj" / SESSION / "scratchpad").mkdir(parents=True)
    monkeypatch.setenv("TMPDIR", str(temp))
    monkeypatch.setenv("CLAUDE_CODE_SESSION_ID", SESSION)
    (tmp_path / "away").mkdir()
    return r


def _ids(out):
    return [] if out is None else [v.reason_id for v in out.verdicts]


def _fill(form, repo):
    temp = repo.parent / "temp"
    scratch = temp / f"claude-{os.getuid()}" / "-proj" / SESSION / "scratchpad"
    return form.replace("{A}", str(repo.parent / "away")).replace("{T}", str(temp)).replace("{S}", str(scratch))


def _out(repo, form, host="claude"):
    return gate.decide(_fill(form, repo), str(repo), time.monotonic() + 60, host)


@pytest.mark.parametrize("form", ["mv MANIFEST.json /tmp/x-n33", "mv MANIFEST.json {A}/", "mv -f MANIFEST.json {A}/m",
                                  "mv -t {A} MANIFEST.json", "mv --target-directory={A} MANIFEST.json"])
def test_D105_mv_out_of_the_repository_gives_a_hint_and_runs(repo, form):
    out = _out(repo, form)
    assert out is not None and out.decision == "pass" and "hint_move_out" in _ids(out), (form, _ids(out))


@pytest.mark.parametrize("form", ["cat > /tmp/x-n33.txt <<'EOF'\neins\nzwei\ndrei\nEOF", "echo x > {T}/other.txt",
                                  "cp README.md /tmp/x-n33", "sort -o /tmp/s-n33 README.md"])
def test_D105_a_write_into_the_temp_folder_outside_the_session_gives_a_hint(repo, form):
    out = _out(repo, form)
    assert out is not None and "hint_tmp_not_scratch" in _ids(out), (form, _ids(out))
    assert out.decision == "pass", out.decision


@pytest.mark.parametrize("form", ["mv README.md docs.md", "mv {A}/x {A}/y", "cp MANIFEST.json {A}/", "mv -n x.txt y.txt"])
def test_D105_control_no_move_hint(repo, form):
    assert "hint_move_out" not in _ids(_out(repo, form)), form


@pytest.mark.parametrize("form", ["echo x > out.txt", "echo x > {S}/a.txt", "cat > {S}/b.txt <<'EOF'\nx\nEOF",
                                  "echo x > /dev/null", "ls /tmp", "cat /tmp/x", "mv README.md docs.md"])
def test_D105_control_no_hint_inside_the_work_folder_or_for_a_read(repo, form):
    assert not set(_ids(_out(repo, form))) & gate.HINT_REASONS, form


def test_D105_without_a_session_there_is_no_scratch_hint(repo, monkeypatch):
    monkeypatch.delenv("CLAUDE_CODE_SESSION_ID")
    assert "hint_tmp_not_scratch" not in _ids(_out(repo, "echo x > /tmp/x-n33"))


def test_D105_the_hook_prints_a_line_and_a_context_and_no_permission_decision(repo):
    out = _out(repo, "mv MANIFEST.json /tmp/x-n33")
    printed = gate.pre_tool_answer(out, "claude", {"session_id": "s"}, "mv")
    assert "permissionDecision" not in printed["hookSpecificOutput"], printed
    assert "mv takes" in printed["hookSpecificOutput"]["additionalContext"]
    assert printed["systemMessage"].startswith("Gate notes at mv that ") and "(D105)" in printed["systemMessage"]


def test_D105_a_hint_never_makes_an_answer_weaker(repo):
    out = _out(repo, "mv MANIFEST.json /tmp/x-n33 && rm -rf /tmp/elsewhere-n33")
    assert out.decision == "deny" and "hint_move_out" in _ids(out) and "delete_outside_work" in _ids(out)


def test_D105_the_reasons():
    for reason in gate.HINT_REASONS:
        assert gate._SHORT_REASONS[reason][0] == "D105"
        assert reason not in gate.FANG_REASONS
