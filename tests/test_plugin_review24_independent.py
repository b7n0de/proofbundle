"""The three probes of the reviewer of round 24 at 6459ff53, switched to the safe behaviour (Nachtrag 21, part 5).

The reviewer measured, without a patch to the gate:
- R24-1: a folder named `` `touch review24_marker` `` holding the stand-in gh, first on PATH, and the helper
  `!"<tmp>/`touch review24_marker`/gh" auth git-credential` made `git -C <repo> fetch origin` free
  (pass / free_after_fetch_profile), and `git credential fill` then made the marker. The gate of 14a5feb1 asked in the
  same state (ask / possible_unmodeled_push); that comparison is measured once in the delivery
  (redgreen of Nachtrag 21), not here, as a test cannot count on the history being there.
- the control: the same path in single quotes stayed free, and git started the stand-in alone.
- R24-2: a hook under core.hooksPath at `<tmp>/review24_secret_path/reference-transaction`; the reason of the fetch
  profile named that path.

Switched (D54, D49 as sharpened by Nachtrag 21): the backtick form asks, and git still makes the marker, which is why;
the hooksPath case asks and names no path; the literal form stays free, and git starts the stand-in alone. RED at
6459ff53: the backtick case and the hooksPath case; the literal control is green at both.
"""
from __future__ import annotations

import os
import pathlib
import subprocess

import pytest

import _worktree_layout as w
import test_plugin_ask_load_b_gh as b
import test_plugin_fetch_github_profile as f
from _plugin_env import plugin_env

pytestmark = w.d.pytestmark
COMMAND = "git -C {a} fetch origin"


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    f._clean.__wrapped__(monkeypatch, tmp_path)


@pytest.fixture
def repo(tmp_path):
    return f.repo.__wrapped__(tmp_path)


def _gh_first_on_path(monkeypatch, folder: pathlib.Path) -> pathlib.Path:
    folder.mkdir(parents=True, exist_ok=True)
    b._fake_gh(folder)
    monkeypatch.setenv("PATH", os.pathsep.join([str(folder), "/usr/local/bin", "/usr/bin", "/bin"]))
    return folder / "gh"


def _credential_fill(repo: pathlib.Path) -> subprocess.CompletedProcess:
    """What git does with the helper on a request for github.com; no terminal prompt, nothing reaches a network."""
    return subprocess.run(["git", "-C", str(repo), "credential", "fill"], input="protocol=https\nhost=github.com\n\n",
                          capture_output=True, text=True, timeout=60, check=False,
                          env=plugin_env(GIT_TERMINAL_PROMPT="0", PATH=os.environ["PATH"]))


def test_R24_1_the_backtick_form_asks(tmp_path, repo, monkeypatch):
    folder = tmp_path / "`touch review24_marker`"
    _gh_first_on_path(monkeypatch, folder)
    w.git(repo, "config", "credential.helper", f'!"{folder}/gh" auth git-credential')
    out = f._decide(repo, COMMAND)
    assert f._asked(out), out and (out.decision, [v.reason_id for v in out.verdicts])
    assert "touch" not in out.text and "review24" not in out.text, out.text
    assert not (repo / "review24_marker").exists(), "the gate judged the value and ran nothing"
    _credential_fill(repo)
    assert (repo / "review24_marker").exists(), "git hands the value to a shell, which ran the backtick: why it asks"


def test_R24_2_the_hookspath_case_names_no_path(tmp_path, repo):
    hooks = tmp_path / "review24_secret_path"
    w.proxy(tmp_path, hooks / "reference-transaction", "hook")
    w.git(repo, "config", "core.hooksPath", str(hooks))
    out = f._decide(repo, COMMAND)
    assert f._asked(out), out and out.text
    assert "a hook the fetch or its maintenance may start: reference-transaction in the hook directory core.hooksPath " \
           "names" in out.text, out.text
    assert "review24_secret_path" not in out.text, out.text
    code, decision, reason = f._hook(tmp_path, COMMAND.format(a=repo))
    assert (code, decision) == (0, "ask") and "review24_secret_path" not in reason, reason


def test_R24_control_the_literal_form_stays_free_and_git_starts_the_stand_in_alone(tmp_path, repo, monkeypatch):
    gh = _gh_first_on_path(monkeypatch, tmp_path / "bin")
    w.git(repo, "config", "credential.helper", f"!{gh} auth git-credential")
    assert f._fetch_free(f._decide(repo, COMMAND))
    _credential_fill(repo)
    assert (tmp_path / "gh_started.log").read_text().splitlines() == ["auth git-credential get"]
    assert not list(tmp_path.rglob("review24_*"))
