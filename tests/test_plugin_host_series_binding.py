"""D41 and D42, addendum 1 to follow-up note 18: the host binding holds for the series 2.1.x of Claude Code.

Claude Code updates itself on account A's machine (2.1.299 and 2.1.301 between 2026-10-14 and 2026-10-16); bound to exactly
claude-code_2-1-301_harness, the binding fell away with every update. Owner choice of 2026-10-16: it holds for every
version of the series 2.1.x, and account A probes on each run of its plugin balance whether a command of the Bash tool has
a terminal. _NO_TERMINAL_HOSTS is now a pattern: exactly claude-code_2-1-<ASCII digits>_harness, nothing before or after
it. It serves the gh reads of class b (D41) and git's pagers of class a (D42) alike, only under Claude Code.

RED at ba65da56 (and at 471f3c97) for 2.1.302 and the other new versions of the series, for both classes; the values
that keep asking answer the same at every head.
"""
from __future__ import annotations

import os
import time

import pytest

import test_plugin_ask_load_b_gh as b

pytestmark = b.pytestmark
gate = b.gate
SERIES = ["claude-code_2-1-301_harness", "claude-code_2-1-302_harness", "claude-code_2-1-299_harness",
          "claude-code_2-1-0_harness", "claude-code_2-1-1000_harness"]
#: Each keeps the ask: the command's own value, other series, a line end or space around it, a prefix or suffix, no
#: number, a letter in it, digits that are not ASCII, and other forms of the name.
OTHERS = ["claude-code_2-1-301_agent", "claude-code_2-2-0_harness", "claude-code_3-0-0_harness",
          "claude-code_2-0-301_harness", "claude-code_2-1-301_harness\n", "claude-code_2-1-301_harness ",
          " claude-code_2-1-301_harness", "xclaude-code_2-1-301_harness", "claude-code_2-1-301_harnessx",
          "claude-code_2-1-_harness", "claude-code_2-1-3a1_harness", "claude-code_2-1-٣٠١_harness",
          "claude-code_2.1.302_harness", "CLAUDE-CODE_2-1-301_HARNESS", ""]


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    """The hook's environment of tests/test_plugin_ask_load_b_gh.py (the stand-in gh 2.89.0 first on PATH), and no
    AI_AGENT of the caller."""
    for key in [k for k in os.environ if k.startswith(("GH_", "GIT_")) or k in ("PAGER", "GITHUB_ENTERPRISE_TOKEN",
                                                                               "XDG_CONFIG_HOME", "AI_AGENT")]:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("LC_ALL", "C")
    (tmp_path / "home" / ".config" / "gh").mkdir(parents=True)
    (tmp_path / "bin").mkdir()
    b._fake_gh(tmp_path / "bin")
    monkeypatch.setenv("PATH", os.pathsep.join([str(tmp_path / "bin"), "/usr/local/bin", "/usr/bin", "/bin"]))


def _decide(tmp_path, command: str, host: str = "claude"):
    out = gate.decide(command, str(b._repo(tmp_path)), time.monotonic() + 120, host)
    return (None, []) if out is None else (out.decision, [v.reason_id for v in out.verdicts])


@pytest.mark.parametrize("agent", SERIES)
@pytest.mark.parametrize("kind", ["gh", "git"])
def test_E1_a_version_of_the_series_is_bound(tmp_path, monkeypatch, agent, kind):
    monkeypatch.setenv("PAGER", "less")
    monkeypatch.setenv("AI_AGENT", agent)
    command = "gh pr view 41" if kind == "gh" else "git log -3 --oneline"
    decision, reasons = _decide(tmp_path, command)
    expected = "free_after_gh_profile" if kind == "gh" else "free_after_read_profile"
    assert decision in b.FREE and reasons == [expected], (agent, decision, reasons)


@pytest.mark.parametrize("agent", OTHERS)
@pytest.mark.parametrize("kind", ["gh", "git"])
def test_E1_every_other_value_keeps_the_ask(tmp_path, monkeypatch, agent, kind):
    monkeypatch.setenv("PAGER", "less")
    monkeypatch.setenv("AI_AGENT", agent)
    command = "gh pr view 41" if kind == "gh" else "git log -3 --oneline"
    out = gate.decide(command, str(b._repo(tmp_path)), time.monotonic() + 120, "claude")
    assert out.decision == "ask" and "a pager: PAGER" in out.text, (repr(agent), out.text)


@pytest.mark.parametrize("kind", ["gh", "git"])
def test_E1_under_codex_a_version_of_the_series_binds_nothing(tmp_path, monkeypatch, kind):
    monkeypatch.setenv("PAGER", "less")
    command = "gh pr view 41" if kind == "gh" else "git log -3 --oneline"
    repo = str(b._repo(tmp_path))

    def codex():
        out = gate.decide(command, repo, time.monotonic() + 120, "codex")
        return out.decision, [v.reason_id for v in out.verdicts]
    before = codex()
    monkeypatch.setenv("AI_AGENT", "claude-code_2-1-302_harness")
    assert codex() == before and before[0] == "ask", before


def test_E1_the_pass_names_the_binding_not_the_value_it_saw(tmp_path, monkeypatch):
    """D49 as sharpened by follow-up note 21: the pass names AI_AGENT, never its value."""
    monkeypatch.setenv("PAGER", "less")
    monkeypatch.setenv("AI_AGENT", "claude-code_2-1-302_harness")
    out = gate.decide("git log -3 --oneline", str(b._repo(tmp_path)), time.monotonic() + 120, "claude")
    detail = out.verdicts[0].detail
    assert "AI_AGENT in the hook's environment names a host" in detail and "2-1-302" not in detail, detail
