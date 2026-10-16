"""D41, part 3 of Nachtrag 16: git fetch, git ls-remote and git worktree add ask with their own reason, not a push's.

Measured in the pilot after Nachtrag 15: `git ls-remote`, `git fetch` and every `git worktree add` but the form D40
frees asked with the text for unresolved push forms ("Evidence: the commits and refs this command might send. Failed:
the command is not one strict push form the gate resolves"). They stay asks (denied under Codex); the answer now names
what the form may start. Measured with git 2.43.0 from a remote given as a local path (measure/fetch_starts.sh):
ls-remote started the upload-pack remote.<name>.uploadpack names; fetch started it, fsmonitor and, where a ref changed,
the reference-transaction hook. The checkout of worktree add runs post-checkout, post-index-change and
reference-transaction, a smudge or process filter an attribute assigns, and fsmonitor (D40). The network ways (a
credential helper, a transport helper, core.sshCommand or GIT_SSH, a proxy command) are named after git's
documentation and D40, not measured here (no network).

RED at fa134694 for every form's reason id and text under both hosts, and for a fetch as the first step of a chain under
Claude Code; the decisions, the free form of D40, a fetch after another step and a worktree add in a chain (directory_unresolved,
which was never the push text) and the forms that keep the push text answer the same at both heads.
"""
from __future__ import annotations

import time

import pytest

import _worktree_layout as w
import test_plugin_gate_n2c_push_done as n2c

pytestmark = w.d.pytestmark
gate = n2c.gate
PUSH_TEXT = "the commits and refs this command might send"


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    w.clean(monkeypatch, tmp_path)


@pytest.fixture
def main(tmp_path):
    return w.main_repo(tmp_path)


def _reasons(cwd, command: str, host: str = "claude") -> list[str]:
    out = gate.decide(command, str(cwd), time.monotonic() + 120, host)
    return [] if out is None else [v.reason_id for v in out.verdicts]


def _remote_reads(main) -> dict[str, str]:
    return {"fetch": "git fetch", "fetch_origin": f"git -C {main} fetch origin", "fetch_all": "git fetch --all -q",
            "fetch_c": f"git -c core.sshCommand=ssh -C {main} fetch origin", "ls_remote": "git ls-remote origin",
            "ls_remote_c": f"git -C {main} ls-remote --heads origin"}


@pytest.mark.parametrize("form", ["fetch", "fetch_origin", "fetch_all", "fetch_c", "ls_remote", "ls_remote_c"])
@pytest.mark.parametrize("host, expected", [("claude", "ask"), ("codex", "deny")])
def test_P3_fetch_and_ls_remote_name_the_network_and_the_helpers(tmp_path, main, form, host, expected):
    command = _remote_reads(main)[form]
    code, decision, reason = w.answer(main, command, host)
    assert (code, decision) == (0, expected), reason
    assert PUSH_TEXT not in reason and "reaches a remote through a transport, helpers and hooks" in reason, reason
    assert "remote_read_not_modeled" in _reasons(main, command, host)


def test_P3_a_fetch_as_the_first_step_of_a_chain_names_its_reason_under_claude_code(tmp_path, main):
    """Corpus B211 (`git fetch origin && git log …`): Claude Code judges the steps (D33), and the fetch step had the push
    text; under Codex the chain's steps are not resolved (directory_unresolved), before and after."""
    command = f"git -C {main} fetch -q origin && git -C {main} log --oneline -1"
    code, decision, reason = w.answer(main, command)
    assert (code, decision) == (0, "ask") and PUSH_TEXT not in reason, reason
    assert _reasons(main, command) == ["remote_read_not_modeled", "step_after_state_change"]
    assert _reasons(main, command, "codex") == ["directory_unresolved", "git_form_not_free"]


def test_P3_the_full_text_of_fetch_names_the_ways(tmp_path, main):
    out = gate.decide("git fetch origin", str(main), time.monotonic() + 120, "claude")
    detail = out.verdicts[0].detail
    for way in ("credential helper", "transport helper", "core.sshCommand", "GIT_SSH", "upload-pack", "fsmonitor",
                "reference-transaction", "sends no commits"):
        assert way in detail, (way, detail)
    detail = gate.decide("git ls-remote origin", str(main), time.monotonic() + 120, "claude").verdicts[0].detail
    assert "upload-pack" in detail and "reference-transaction" not in detail, detail


def _worktree_forms(main, target) -> dict[str, str]:
    return {"force": f"git -C {main} worktree add --force -b x {target} origin/main",
            "detach": f"git -C {main} worktree add --detach {target} origin/main",
            "lock": f"git -C {main} worktree add --lock -b x {target} origin/main",
            "big_b": f"git -C {main} worktree add -B x {target} origin/main",
            "relative": f"git -C {main} worktree add -b x scope_631 origin/main",
            "no_dash_c": f"git worktree add {target}",
            "two_dash_c": f"git -C {main} -C {main} worktree add -b x {target} origin/main"}


@pytest.mark.parametrize("form", ["force", "detach", "lock", "big_b", "relative", "no_dash_c", "two_dash_c"])
@pytest.mark.parametrize("host, expected", [("claude", "ask"), ("codex", "deny")])
def test_P3_worktree_add_names_the_checkout(tmp_path, main, form, host, expected):
    command = _worktree_forms(main, w.worktree_target(tmp_path))[form]
    code, decision, reason = w.answer(main, command, host)
    assert (code, decision) == (0, expected), reason
    assert PUSH_TEXT not in reason and "the checkout of git worktree add" in reason, reason
    assert "checkout_not_modeled" in _reasons(main, command, host)
    # under Claude Code the next step names the one form D40 checks; under Codex that form is not free either
    assert ("Next step: run it as `git -C <absolute path> worktree add" in reason) == (host == "claude"), reason


def test_P3_control_the_form_of_D40_stays_free(tmp_path, main):
    command = f"git -C {main} worktree add -q -b docs/release-scope-6-3-1 {w.worktree_target(tmp_path)} origin/main"
    assert w.answer(main, command) == (0, None, "")


@pytest.mark.parametrize("form", ["fetch", "worktree_add"])
@pytest.mark.parametrize("host, expected", [("claude", "ask"), ("codex", "deny")])
def test_P3_control_a_later_step_of_a_chain_keeps_its_answer(tmp_path, main, form, host, expected):
    """After another step of a chain the step's repository is not resolved, and worktree add is free only as the whole
    command (D40); that answer (directory_unresolved) was not the push text and stays as it is. The chain of the pilot
    named in D40 is such a form."""
    command = {"fetch": f"test -e {main.parent / 'scope_631'} || git -C {main} fetch -q origin",
               "worktree_add": f"git -C {main} worktree add -q -b x {w.worktree_target(tmp_path)} origin/main "
                               "&& echo added"}[form]
    code, decision, reason = w.answer(main, command, host)
    assert (code, decision) == (0, expected), reason
    assert "directory_unresolved" in _reasons(main, command, host)


@pytest.mark.parametrize("command", ["git send-pack origin main", "git -c alias.p=push p origin main",
                                     "git pull origin main", "git clone /x /y", "git remote update"])
@pytest.mark.parametrize("host, expected", [("claude", "ask"), ("codex", "deny")])
def test_P3_control_other_unresolved_forms_keep_the_push_text(tmp_path, main, command, host, expected):
    code, decision, reason = w.answer(main, command, host)
    assert (code, decision) == (0, expected) and PUSH_TEXT in reason, reason
    assert "possible_unmodeled_push" in _reasons(main, command, host)
