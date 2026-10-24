"""D41, part 2 of Nachtrag 16: a pager does not hinder a gh read form under a host whose Bash tool gives no terminal.

Pilot class: a gh read form asked with "a pager: PAGER in the hook's environment" (class b, D36: owner answer 3 counts a
pager because no host adapter was bound). Nachtrag 16 named two ways: the gate sets GH_PAGER=cat through updatedInput,
or the gate shows that gh starts no pager without a terminal on standard output. Both were measured under Claude Code
2.1.301, run with no network against a stand-in for the API (host/host_cases.py of Nachtrag 16):
- (a) Claude Code ran the command a hook gave back in updatedInput, from the user's settings and from a plugin. With a
  permission rule `Bash(gh pr view:*)` the rewritten `GH_PAGER=cat gh pr view …` ran only when the hook also said
  allow; without a decision it asked for approval. Way (a) frees the form only by making the gate approve it.
- (b) In the print and the interactive form, and for a background command, the command got a pipe on standard output,
  no terminal on standard input and error and no controlling terminal. gh 2.89.0 with PAGER, GH_PAGER or a configured
  pager started no pager there; on a terminal of script(1), and with GH_FORCE_TTY, it started it. A hook got
  AI_AGENT=claude-code_2-1-301_harness.
Way (b) is built: under Claude Code, when the hook's AI_AGENT names a measured host (_NO_TERMINAL_HOSTS), a pager PAGER,
GH_PAGER or gh's configuration names does not count, and the pass names it. GH_FORCE_TTY, every other finding of the gh
profile, Codex, and every form that is not a class b read form keep today's answer.

RED at dabd4684 for the read forms with PAGER, GH_PAGER or a configured pager under the bound host, alone and as a step
whose output is the tool's or a pipe, for the pass text, and for the socket after a noted pager; the controls answer the
same at both heads. Cases run the gate in-process with the stand-in gh of
tests/test_plugin_ask_load_b_gh.py (`--version` as 2.89.0, every other start recorded).
"""
from __future__ import annotations

import os
import time

import pytest

import test_plugin_ask_load_b_gh as b

pytestmark = b.pytestmark
gate = b.gate
BOUND = "claude-code_2-1-301_harness"
FORMS = ["gh pr view 41", "gh pr view 41 -R o/r --comments", "gh pr list --limit 10 --state all",
         "gh run view 1 --log", "gh issue view 7 --comments", "gh api repos/o/r --jq .full_name",
         "gh pr diff 41 --name-only"]


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    """As tests/test_plugin_ask_load_b_gh.py: no GH_*, GIT_*, PAGER or AI_AGENT of the caller, a home and a gh
    configuration folder of its own, the stand-in gh first on PATH."""
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


def _out(tmp_path, command: str, host: str = "claude"):
    return gate.decide(command, str(b._repo(tmp_path)), time.monotonic() + 120, host)


@pytest.mark.parametrize("command", FORMS)
def test_P2_a_gh_read_form_with_PAGER_is_free_under_the_bound_host(tmp_path, monkeypatch, command):
    monkeypatch.setenv("PAGER", "less")
    monkeypatch.setenv("AI_AGENT", BOUND)
    decision, reasons = b._decide(b._repo(tmp_path), command)
    assert decision in b.FREE and reasons == ["free_after_gh_profile"], (decision, reasons)
    assert not (tmp_path / "gh_started.log").exists()      # the gate started gh for --version only


@pytest.mark.parametrize("kind", ["GH_PAGER", "config", "hosts_block", "all_three"])
def test_P2_GH_PAGER_and_a_configured_pager_are_free_under_the_bound_host(tmp_path, monkeypatch, kind):
    monkeypatch.setenv("AI_AGENT", BOUND)
    if kind in ("GH_PAGER", "all_three"):
        monkeypatch.setenv("GH_PAGER", "less")
    if kind in ("config", "all_three"):
        b._config(tmp_path, "config.yml", "pager: less\n")
    if kind == "hosts_block":
        b._config(tmp_path, "hosts.yml", "github.com:\n    pager: less\n")
    if kind == "all_three":
        monkeypatch.setenv("PAGER", "more")
    decision, reasons = b._decide(b._repo(tmp_path), "gh pr view 41")
    assert decision in b.FREE and reasons == ["free_after_gh_profile"], (kind, decision, reasons)


def test_P2_the_pass_names_the_pager_and_the_host(tmp_path, monkeypatch):
    monkeypatch.setenv("PAGER", "less")
    monkeypatch.setenv("AI_AGENT", BOUND)
    out = _out(tmp_path, "gh pr view 41")
    assert out.verdicts and out.verdicts[0].reason_id == "free_after_gh_profile"
    text = out.verdicts[0].detail
    # D49 as sharpened by Nachtrag 21: the pass names AI_AGENT, never its value
    assert "A pager is named (PAGER)" in text and "AI_AGENT in the hook's environment names a host" in text, text
    assert BOUND not in text and "D41" in text, text
    assert "no pager, forced terminal" not in text, text


@pytest.mark.parametrize("agent", [None, "", "claude-code_2-1-301_agent", "claude-code_2-0-301_harness",
                                   "claude-code_2-2-0_harness", "claude-code_2-1-301_harness ", "codex"])
def test_P2_control_without_the_bound_host_the_pager_asks(tmp_path, monkeypatch, agent):
    """No AI_AGENT, the value the command gets (_agent), another version and any other value: today's answer."""
    monkeypatch.setenv("PAGER", "less")
    if agent is not None:
        monkeypatch.setenv("AI_AGENT", agent)
    out = _out(tmp_path, "gh pr view 41")
    assert out.decision == "ask" and [v.reason_id for v in out.verdicts] == ["gh_form_not_free"], out.verdicts
    assert "a pager: PAGER" in out.text, out.text


@pytest.mark.parametrize("name, value, named", [("GH_FORCE_TTY", "1", "GH_FORCE_TTY"),
                                                ("GH_HOST", "evil.example", "GH_HOST"),
                                                ("GH_ENTERPRISE_TOKEN", "x", "GH_ENTERPRISE_TOKEN"),
                                                ("GH_SOMETHING_NEW", "1", "GH_SOMETHING_NEW")])
def test_P2_control_every_other_finding_of_the_gh_profile_still_counts(tmp_path, monkeypatch, name, value, named):
    monkeypatch.setenv("PAGER", "less")
    monkeypatch.setenv("AI_AGENT", BOUND)
    monkeypatch.setenv(name, value)
    out = _out(tmp_path, "gh pr view 41")
    assert out.decision == "ask" and named in out.text, out.text


def test_P2_a_noted_pager_does_not_hide_a_later_unix_socket(tmp_path, monkeypatch):
    """The pager is noted and the reading goes on: the socket after it is named (at dabd4684 the pager was named
    first, so this case is red there by its text)."""
    monkeypatch.setenv("AI_AGENT", BOUND)
    b._config(tmp_path, "config.yml", "pager: less\nhttp_unix_socket: /tmp/gh.sock\n")
    out = _out(tmp_path, "gh pr view 41")
    assert out.decision == "ask" and "a unix socket for HTTP" in out.text, out.text


def test_P2_control_under_codex_the_answer_stays(tmp_path, monkeypatch):
    monkeypatch.setenv("PAGER", "less")
    repo = b._repo(tmp_path)
    before = b._decide(repo, "gh pr view 41", "codex")
    monkeypatch.setenv("AI_AGENT", BOUND)
    after = b._decide(repo, "gh pr view 41", "codex")
    assert after == before and b._asked(*after), (before, after)


@pytest.mark.parametrize("command", ["exec > /dev/pts/0; gh pr view 41", "exec 1>/dev/pts/0 && gh pr view 41",
                                     "{ gh pr view 41; } > /dev/pts/0", "( gh pr view 41 ) > /dev/pts/0",
                                     "gh pr view 41 > /dev/pts/0", "script -qec 'gh pr view 41' /dev/null",
                                     "unbuffer gh pr view 41", "GH_PAGER=less gh pr view 41"])
def test_P2_control_a_form_that_may_give_gh_a_terminal_keeps_its_ask(tmp_path, monkeypatch, command):
    """A step that points standard output elsewhere, a redirection, a program that opens a terminal of its own and a
    prefix assignment: none is a class b read form whose standard output is the tool's, so the pager rule does not
    apply and the answer is today's."""
    monkeypatch.setenv("PAGER", "less")
    monkeypatch.setenv("AI_AGENT", BOUND)
    decision, reasons = b._decide(b._repo(tmp_path), command)
    assert b._asked(decision, reasons), (command, decision, reasons)


@pytest.mark.parametrize("command", ["true && gh pr view 41", "gh pr view 41 | cat"])
def test_P2_a_step_whose_output_is_the_tools_or_a_pipe_is_free(tmp_path, monkeypatch, command):
    """Class c judges the gh step on its own (D33): its standard output is the tool's or a pipe, no terminal."""
    monkeypatch.setenv("PAGER", "less")
    monkeypatch.setenv("AI_AGENT", BOUND)
    decision, reasons = b._decide(b._repo(tmp_path), command)
    assert decision in b.FREE and "free_after_gh_profile" in reasons, (decision, reasons)
