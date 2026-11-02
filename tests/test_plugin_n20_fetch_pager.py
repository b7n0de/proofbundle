"""D48, follow-up note 20 part 2 (O19-2): a pager of git does not count for the fetch form of D45 under any host.

Measured in addendum 1 to follow-up note 19 (truth_fetch_e1.jsonl, git 2.43.0 under strace -f, no network, a stand-in for
github.com): git fetch started no pager with PAGER, GIT_PAGER or core.pager set, also on a terminal of script(1). Until
now the fetch profile let a pager pass only under a bound host whose Bash tool gives the command no terminal (D42), as in
class a. The owner chose O19-2: for this form, under no host.

Only the fetch form of D45 and only what was measured: core.pager, PAGER and GIT_PAGER. A pager.<command> key and the
pager of gh in the gh helper's gh profile keep the rule of D42; every read form of class a keeps D34 and D42; a fetch
under Codex keeps its ask (D41).

RED at a8ca017a for each freed case (the profile named the pager); the controls answer the same at both heads.
"""
from __future__ import annotations

import pytest

import _worktree_layout as w
import test_plugin_fetch_github_profile as f
pytestmark = w.d.pytestmark


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    """The environment of D45's tests: account A's names, a fake gh on PATH, a fresh HOME."""
    f._clean.__wrapped__(monkeypatch, tmp_path)


@pytest.fixture
def repo(tmp_path):
    """D45's clone under an absolute path with origin on https://github.com/o/r."""
    return f.repo.__wrapped__(tmp_path)
HOSTS = {"unbound": None, "another host": "claude-code_9-9-9_harness", "bound": f.BOUND}
PAGERS = {"PAGER": ("env", "PAGER"), "GIT_PAGER": ("env", "GIT_PAGER"), "core.pager local": ("local", "core.pager"),
          "core.pager global": ("global", "core.pager")}


def _set(repo, tmp_path, monkeypatch, host, pager):
    monkeypatch.delenv("PAGER", raising=False)
    if HOSTS[host] is None:
        monkeypatch.delenv("AI_AGENT", raising=False)
    else:
        monkeypatch.setenv("AI_AGENT", HOSTS[host])
    where, name = PAGERS[pager]
    if where == "env":
        monkeypatch.setenv(name, "less")
    elif where == "local":
        w.git(repo, "config", name, "less")
    else:
        # a global file of the test's own: the fixtures point GIT_CONFIG_GLOBAL at /dev/null, and git writes a
        # configuration by renaming a lock file onto its path, so `git config --global` would replace /dev/null
        glob = tmp_path / "global.gitconfig"
        glob.write_text("[core]\n\tpager = less\n")
        monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(glob))


@pytest.mark.parametrize("pager", sorted(PAGERS))
@pytest.mark.parametrize("host", sorted(HOSTS))
def test_N20_a_pager_does_not_count_for_the_fetch_form_under_any_host(tmp_path, repo, monkeypatch, host, pager):
    _set(repo, tmp_path, monkeypatch, host, pager)
    out = f._decide(repo, "git -C {a} fetch -q origin main")
    assert f._fetch_free(out), (host, pager, out and out.text)
    assert "git fetch starts no pager" in out.text and "D48" in out.text, out.text


def test_N20_in_a_chain_without_the_bound_host_only_the_read_step_counts_its_pager(tmp_path, repo, monkeypatch):
    monkeypatch.delenv("AI_AGENT")
    monkeypatch.setenv("PAGER", "less")
    a = repo
    out = f._decide(repo, f"git -C {a} status; git -C {a} fetch -q origin main; git -C {a} rev-parse origin/main")
    assert out is not None and out.decision == "ask", out and out.text   # status is a read form: its pager counts (D42)
    assert "git status" in out.text and "fetch" not in out.text.split("On their own", 1)[0], out.text


@pytest.mark.parametrize("command", ["git -C {a} log -1", "git -C {a} status"])
def test_N20_control_a_read_form_keeps_its_pager_rule(tmp_path, repo, monkeypatch, command):
    monkeypatch.delenv("AI_AGENT")
    monkeypatch.setenv("PAGER", "less")
    out = f._decide(repo, command)
    assert f._asked(out) or (out is not None and out.decision == "ask"), out and out.text


def test_N20_control_a_pager_command_key_keeps_the_rule_of_D42(tmp_path, repo, monkeypatch):
    monkeypatch.delenv("AI_AGENT")
    w.git(repo, "config", "pager.fetch", "true")
    assert f._asked(f._decide(repo, "git -C {a} fetch -q origin main"))


def test_N20_control_under_codex_the_fetch_keeps_its_ask(tmp_path, repo, monkeypatch):
    monkeypatch.delenv("AI_AGENT")
    assert f._asked(f._decide(repo, "git -C {a} fetch -q origin main", host="codex"))

