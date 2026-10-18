"""D72, Nachtrag 30: the short line names the step that decides.

Owner choice of 2026-10-18 ("die Zeile nennt die Gefahr"): an ask, a deny and a warning name the simple command whose
answer decides and the word that carries it, the heaviest step where several do (deny before ask, then the weight of the
step), never the first git or gh step by its place; the reason ids in the log stay, and the line gives the reason of
that step. The repository and the environment here are also those of the test of the house rules of D73
(test_plugin_n30_house_rules_d73.py), which imports them.

RED at ffa7d39a (the head of Nachtrag 29): the step and the line of each row; the reason ids of each row are the same at
both. The gh the gate checks is a script that answers `--version` as gh 2.89.0 does and records any other start; no case
reaches a network.
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import time

import pytest

import test_plugin_gate_n2c_push_done as n2c

gate = n2c.gate
pytestmark = n2c.pytestmark
URL = "https://github.com/b7n0de/proofbundle.git"
DECLARATION = '{"schema": "proofbundle-plugin/evidence/v0.2", "evidence": []}\n'
HOSTS = ("claude", "codex")


def _git(repo: pathlib.Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True,
                          timeout=60).stdout.strip()


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    """The hook's environment: no GH_* or GIT_* name but the two empty configuration files, no PAGER, a home and a gh
    configuration folder of its own, the gate directory outside every repository, and the stand-in gh first on PATH."""
    for key in [k for k in os.environ if k.startswith(("GH_", "GIT_")) or k in ("PAGER", "GITHUB_ENTERPRISE_TOKEN",
                                                                               "XDG_CONFIG_HOME", "AI_AGENT")]:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("LC_ALL", "C")
    monkeypatch.setenv("PROOFBUNDLE_GATE_DIR", str(tmp_path / "gatedir"))
    (tmp_path / "home" / ".config" / "gh").mkdir(parents=True)
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "gh").write_text(
        '#!/bin/sh\nif [ "$1" = "--version" ]; then echo "gh version 2.89.0 (2026-03-26)"; '
        'echo "https://github.com/cli/cli/releases/tag/v2.89.0"; exit 0; fi\n'
        f'echo "$*" >> {tmp_path / "gh_started.log"}\nexit 0\n')
    (tmp_path / "bin" / "gh").chmod(0o755)
    monkeypatch.setenv("PATH", os.pathsep.join([str(tmp_path / "bin"), "/usr/local/bin", "/usr/bin", "/bin"]))


def _repo(tmp_path: pathlib.Path) -> pathlib.Path:
    """main with commits A and C, topic from A with commit B, the tags v0 and release-candidate on A, the branch
    candidate-branch, twin as a branch and a tag, a declaration at HEAD and origin at the repository of b7n0de: a
    repository D71 applies to."""
    repo = tmp_path / "r"
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True, timeout=60)
    _git(repo, "config", "user.name", "t")
    _git(repo, "config", "user.email", "t@example.invalid")
    (repo / "README.md").write_text("readme\n")
    (repo / "notes.md").write_text("notes\n")
    (repo / ".proofbundle").mkdir()
    (repo / ".proofbundle" / "evidence.json").write_text(DECLARATION)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "A")
    _git(repo, "tag", "v0")
    _git(repo, "tag", "release-candidate")
    _git(repo, "branch", "candidate-branch")
    _git(repo, "branch", "twin")
    _git(repo, "tag", "twin")
    _git(repo, "checkout", "-q", "-b", "topic")
    (repo / "t.txt").write_text("t\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "B")
    _git(repo, "checkout", "-q", "main")
    (repo / "c.txt").write_text("c\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "C")
    _git(repo, "remote", "add", "origin", URL)
    return repo


def _outcome(repo: pathlib.Path, form: str, host: str = "claude"):
    command = form.replace("{R}", str(repo))
    return gate.decide(command, str(repo), time.monotonic() + 60, host)


def _answer(repo, form, host="claude"):
    out = _outcome(repo, form, host)
    return (None, []) if out is None else (out.decision, [v.reason_id for v in out.verdicts])


def _line(out, host: str = "claude", language: str = "en") -> str:
    name = out.step
    if out.decision == "ask" and host == "codex":
        return gate.short_line("ask", out, name, language, form="deny", suffix=gate._SHORT_CODEX_DENY[language])
    return gate.short_line(out.decision, out, name, language)


# --- D72: the line names the heaviest step, with the reason of that step ----------------------------------------------

D72 = [
    # form, host, step, reason ids as at ffa7d39a, the D number of the line
    ("git log -1 && git reset --hard HEAD~1", "claude", "git reset", ["git_form_not_free", "git_form_not_free"], "D3"),
    ("git log -1 && git reset --hard HEAD~1", "codex", "git reset", ["git_form_not_free", "git_form_not_free"], "D3"),
    ("gh pr checks 12 -R b7n0de/proofbundle && gh pr merge 12 -R b7n0de/proofbundle --merge", "claude",
     "gh pr merge", ["free_after_gh_profile", "net_unmodeled_git"], "D27"),
    ("gh pr checks 12 -R b7n0de/proofbundle && gh pr merge 12 -R b7n0de/proofbundle --merge", "codex",
     "gh pr merge", ["free_after_gh_profile", "net_unmodeled_git"], "D27"),
    ("git status && git push origin main", "claude", "git push", ["git_form_not_free", "directory_unresolved"], "D33"),
    ("git status && git push origin main", "codex", "git push", ["git_form_not_free", "codex_push_not_plain"], "D12"),
]


@pytest.mark.parametrize("form, host, step, reasons, number", D72)
def test_D72_the_line_names_the_heaviest_step_not_the_first(tmp_path, form, host, step, reasons, number):
    repo = _repo(tmp_path)
    out = _outcome(repo, form, host)
    assert [v.reason_id for v in out.verdicts] == reasons      # the reason ids in the log stay
    assert out.step == step, out.step
    line = _line(out, host)
    assert f" {step} " in line and f"({number})." in line, line


@pytest.mark.parametrize("first", ["log -1", "tag -l"])
def test_D72_class_c_names_the_heaviest_step_whose_own_answer_decides(tmp_path, first):
    """Class c judges each step on its own: with a pager in the configuration the read asks on its own as the reset
    does, and the line names the reset, the heavier, with its own reason; a tag list is a read (D71)."""
    repo = _repo(tmp_path)
    _git(repo, "config", "core.pager", "less")
    out = _outcome(repo, f"git -C {repo} {first} && git -C {repo} reset --hard topic")   # literal words: class c
    asking = [v.failed for v in out.verdicts if v.decision == "ask"]
    assert len(asking) == 2 and asking[0].startswith(f"git {first.split()[0]}"), asking   # both steps ask
    assert f"the step `git -C {repo} {first}` of this command asks on its own" in out.text, out.text[:200]
    assert out.decision == "ask" and out.step == "git reset", (out.decision, out.step)
    assert out.cause is not None and out.cause.failed.startswith("git reset"), out.cause and out.cause.failed


def test_D72_a_kept_answer_names_the_heaviest_step_not_the_kept_one(tmp_path):
    """A fetch that its profile does not free (a proxy) is a gated step that is not the first, so class c keeps the
    whole command's answer for it; the line names the reset after it, which weighs more than a transfer."""
    repo = _repo(tmp_path)
    _git(repo, "config", "http.proxy", "http://127.0.0.1:9")
    out = _outcome(repo, "git status && git fetch origin && git reset --hard HEAD~1")
    assert out.decision == "ask" and "directory_unresolved" in [v.reason_id for v in out.verdicts]
    assert out.step == "git reset", out.step


def test_D72_the_heaviest_of_steps_that_weigh_the_same_is_the_first(tmp_path):
    steps: list = []
    gate._sh_walk(gate._sh_parse("git tag v1 && git reset --hard && git status"), str(tmp_path), steps)
    assert gate._sh_short_name(gate._sh_heaviest(steps)) == "git tag"
    assert [gate._d72_step_weight(s) for s in steps] == [3, 3, 1]
    assert gate._short_step_name("git status; git -c core.hooksPath=/dev/null commit -m x; git push origin main",
                                 str(tmp_path)) == "git commit"
    assert gate._short_step_name("for x in 1; do git status; git push origin main; done", str(tmp_path)) == "git push"


@pytest.mark.parametrize("words, name", [
    (["pr", "merge", "12"], "gh pr merge"), (["-R", "b7n0de/x", "pr", "checks", "12"], "gh pr checks"),
    (["api", "repos/b7n0de/x/pulls"], "gh api"), (["pr", "create", "--fill"], "gh pr create"),
    (["run", "view", "123"], "gh run view"), (["--version"], "gh")])
def test_D72_a_gh_step_is_named_by_its_command_words(words, name):
    assert gate._gh_short_name(words) == name
