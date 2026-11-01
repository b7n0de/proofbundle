"""Review of 2026-10-09, F2: a word the shell may rewrite is not the word the gate read.

Measured by the reviewer at 91a52faa: in a repository with a file named `--edit`, `git commit -m msg *` was free after
the state check, and bash turns `*` into `--edit`, which starts an editor; under Codex `git push --no-verif? origin
main` with a file named `--no-verify` warned as the plain push, and bash turns it into `--no-verify`, which turns the
pre-push hook off. `git commit -m msg -- *` stays free: after the `--` that ends the options a word is a pathspec.

The class: every place that positively frees a form, or reads its words to resolve a target, now asks the same
question of each word as written (_shell_rewrites): an unquoted, unescaped glob (`*`, `?`, `[`), a brace expansion
(`{`), zsh's extended glob (`^`, `#`), a leading `~` (except the plain forms the gate models in a `-C` value), a `~`
right after `=` or `:`, or zsh's leading `=`. A `(` already ends the word for the lexer, so an extglob or a glob
qualifier was NOT MEASURED before; zsh's `~` inside a word excludes only together with another glob character
(measured with zsh 5.9), so alone it stays literal. The places:
- `git add` and `git commit -m` (K-NW-2 B): such a word before the `--` that ends the options, a message included,
  leaves the form not free; after it the form stays free;
- the plain push under Codex (K5-1 C): such a word among the push's options leaves the form not plain, so it is denied;
- a push or gh call Level 1 resolves under Claude Code: such a word anywhere leaves the repository and target NOT
  MEASURED;
- a human rule (N24, with-approvals): a command with such a word is no candidate, because the approved text is not
  the command git gets.

Each case is shown non-vacuous: the shell named in it really turns the word into an option in the test directory.
Red against 91a52faa.
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
import time

import _git_version as _gv
import pytest
from _owner_state import owner_state_protected  # noqa: F401 - D124: a person's mode and rules are read
from _plugin_env import plugin_env

ROOT = pathlib.Path(__file__).resolve().parent.parent
GATE = ROOT / "plugins" / "proofbundle" / "hooks" / "proofbundle_gate.py"

_bytecode, sys.dont_write_bytecode = sys.dont_write_bytecode, True
sys.path.insert(0, str(GATE.parent))
from _gate_answer import skip_where_the_gate_is_not_shipped  # noqa: E402
skip_where_the_gate_is_not_shipped(pathlib.Path(__file__).resolve().parent.parent / "plugins" / "proofbundle" / "hooks" / "proofbundle_gate.py",
                                   pathlib.Path(__file__).resolve().parent.parent)
import proofbundle_gate as gate  # noqa: E402

sys.path.pop(0)
sys.dont_write_bytecode = _bytecode

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")

HOME = os.environ.get("HOME", "/")
#: Files in the test directory whose names are options.
OPTION_FILES = ("--edit", "--no-verify", "-p")

#: (command, shell, what the shell makes of it): one per kind of rewrite, each free at 91a52faa. The third field is an
#: option the shell puts before the end of the options, or, for the two kinds of zsh's extended glob that cannot start
#: a word with a dash on their own, the word list the shell gives instead of the one the gate read.
FREE_FORM_CASES = {
    "star": ("git commit -m msg *", "bash", "--edit"),
    "star in add": ("git add *", "bash", "--edit"),
    "question marks": ("git commit -m msg ??????", "bash", "--edit"),
    "bracket": ("git commit -m msg [-]-edit", "bash", "--edit"),
    "brace": ("git commit -m msg {--edit,a.txt}", "bash", "--edit"),
    "glob as the message": ("git commit -m * a.txt", "bash", "-p"),
    "a -- that is the message": ("git commit -m -- *", "bash", "--edit"),
    "zsh caret": ("git add ^a.txt", "zsh", "--edit"),
    "zsh hash": ("git add a.tx#t", "zsh", ["add", "a.txt"]),
    "leading tilde": ("git add ~", "bash", ["add", HOME]),
    "tilde after an equals sign": ("git add a=~", "bash", ["add", f"a={HOME}"]),
}
#: Forms that stay free: a quoted or escaped character is literal, a word after the `--` that ends the options is a
#: pathspec, and a leading `~` is a home directory.
STAYS_FREE = ["git commit -m msg -- *", "git add -- *.txt", "git commit -m 'a*b'", "git add 'x*'", 'git add "x*"',
              "git add x\\*", "git commit -m 'msg' a.txt", "git add a.txt", "git add a.txt~b", "git add 'a=~'"]

#: Push forms under Codex: (command, shell, the option the shell makes). Each warned at 91a52faa.
CODEX_PUSH_CASES = {
    "question mark in an option": ("git push --no-verif? origin main", "bash", "--no-verify"),
    "star among the options": ("git push * origin main", "bash", "--no-verify"),
    "glob after a value option's --": ("git push -o -- * origin main", "bash", "--no-verify"),
    "glob refspec": ("git push origin mai*", "bash", None),
}
CODEX_PUSH_STAYS_PLAIN = ["git push origin main", "git push origin -- *", "git push origin 'mai*'",
                          "git push -o x -- *", "git push -q -- *"]


@pytest.fixture(autouse=True)
def _clean_git_environment(monkeypatch):
    for key in [k for k in os.environ if k.startswith("GIT_")]:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)


def _git(path: pathlib.Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(path), "-c", "user.name=t", "-c", "user.email=t@example.org",
                    "-c", "commit.gpgsign=false", *args], check=True, capture_output=True, timeout=60)


@pytest.fixture
def repo(tmp_path: pathlib.Path) -> pathlib.Path:
    """A repository with a.txt committed and pushed to a bare remote, and untracked files named like options."""
    bare = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--bare", "-q", str(bare)], check=True, timeout=60)
    path = tmp_path / "r"
    path.mkdir()
    _git(path, "init", "-q", "-b", "main")
    _git(path, "remote", "add", "origin", str(bare))
    (path / "a.txt").write_text("a\n", encoding="utf-8")
    _git(path, "add", "a.txt")
    _git(path, "commit", "-q", "-m", "base")
    _git(path, "push", "-q", "-u", "origin", "main")
    for name in OPTION_FILES:
        (path / name).write_text("x\n", encoding="utf-8")
    return path


def _expand(shell: str, command: str, cwd: pathlib.Path) -> list[str]:
    """The words `shell` gives the command in cwd, measured by running it with printf in place of git."""
    if shutil.which(shell) is None:
        pytest.skip(f"{shell} is not installed")
    setup = "setopt extendedglob; " if shell == "zsh" else ""
    script = setup + "printf '%s\\n' " + command.removeprefix("git ")
    proc = subprocess.run([shell, "-c", script], cwd=cwd, capture_output=True, text=True, timeout=30, check=False)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.splitlines()


def _decide(command: str, repo: pathlib.Path, host: str) -> gate.Outcome:
    outcome = gate.decide(command, str(repo), time.monotonic() + 60, host=host)
    assert outcome is not None, command
    return outcome


def _host_answer(outcome: gate.Outcome, host: str) -> str | None:
    answer = gate.answer(outcome.decision, outcome.text, host=host)
    return None if answer is None else answer["hookSpecificOutput"].get("permissionDecision")   # D53: a pass is None


# --- git add and git commit -m ------------------------------------------------------------------------------------

@pytest.mark.parametrize("command,shell,option", FREE_FORM_CASES.values(), ids=FREE_FORM_CASES.keys())
def test_a_word_the_shell_rewrites_before_the_options_end_leaves_the_form_not_free(repo, command, shell, option):
    words = _expand(shell, command, repo)
    if isinstance(option, list):
        assert words == option and words != command.split()[1:], f"{shell} gives {words}: the case would be vacuous"
    else:
        end = next((k for k, w in enumerate(words) if w == "--" and words[k - 1] not in ("-m", "--message")),
                   len(words))                                      # the -- of `-m --` is the message
        assert option in words[:end], f"{shell} gives {words}: the case would be vacuous"
    for host in ("claude", "codex"):
        outcome = _decide(command, repo, host)
        assert outcome.decision != "pass", (host, command)
        assert {v.reason_id for v in outcome.verdicts} == {"git_form_not_free"}, (host, outcome.verdicts)
        assert _host_answer(outcome, host) == ("ask" if host == "claude" else "deny")


@pytest.mark.parametrize("command", STAYS_FREE)
def test_a_literal_word_or_a_word_after_the_options_keeps_the_form_free(repo, command):
    for host in ("claude", "codex"):
        outcome = _decide(command, repo, host)
        assert outcome.decision == "pass", (host, command, [v.reason_id for v in outcome.verdicts])
        assert {v.reason_id for v in outcome.verdicts} == {"free_after_state_check"}


def test_after_the_dashdash_the_rewritten_words_are_pathspecs(repo):
    """The control is non-vacuous too: bash gives `--edit` after the `--`, where git reads it as a pathspec."""
    words = _expand("bash", "git commit -m msg -- *", repo)
    assert words.index("--") < words.index("--edit")


# --- the plain push under Codex ---------------------------------------------------------------------------------

@pytest.mark.parametrize("command,shell,option", CODEX_PUSH_CASES.values(), ids=CODEX_PUSH_CASES.keys())
def test_under_codex_a_push_with_a_rewritten_option_word_is_denied(repo, command, shell, option):
    if option is not None:
        words = _expand(shell, command, repo)
        assert option in words, f"{shell} gives {words}: the case would be vacuous"
    assert not gate._codex_plain_push(command), command
    outcome = _decide(command, repo, "codex")
    assert "codex_push_not_plain" in {v.reason_id for v in outcome.verdicts}, outcome.verdicts
    assert "warn" not in {v.decision for v in outcome.verdicts}
    assert _host_answer(outcome, "codex") == "deny"


@pytest.mark.parametrize("command", CODEX_PUSH_STAYS_PLAIN)
def test_under_codex_the_plain_push_with_literal_options_still_warns(repo, command):
    assert gate._codex_plain_push(command), command
    outcome = _decide(command, repo, "codex")
    assert outcome.decision == "warn" and {v.reason_id for v in outcome.verdicts} == {"codex_context_unbound"}


# --- what Level 1 resolves under Claude Code ----------------------------------------------------------------------

@pytest.mark.parametrize("command", ["git push origin mai*", "git push --no-verif? origin main", "git push origin -- *",
                                     "git -C r* push origin main", "gh pr create --title *", "git push ~/remote.git main",
                                     "git -C ~+ push origin main", "git -C ~- push origin main"])
def test_a_rewritten_word_leaves_the_repository_and_target_not_measured(command):
    calls = gate.gated_calls(command, "/repo")
    assert calls and all(directory is gate.UNKNOWN for _name, directory, _detail in calls), calls


@pytest.mark.parametrize("command", ["git push origin main", "git push origin 'mai*'", "gh pr create --title 'a*'"])
def test_literal_words_still_resolve(command):
    calls = gate.gated_calls(command, "/repo")
    assert calls and all(directory == "/repo" for _name, directory, _detail in calls), calls


def test_the_tilde_the_gate_models_in_a_c_value_still_resolves():
    (_name, directory, _detail), = gate.gated_calls("git -C ~/r push origin main", "/repo")
    assert directory == os.path.join("/repo", os.path.expanduser("~/r"))


def test_under_claude_code_a_push_with_a_rewritten_word_asks(repo):
    outcome = _decide("git push --no-verif? origin main", repo, "claude")
    assert {v.reason_id for v in outcome.verdicts} == {"directory_unresolved"}
    assert "a word the shell may rewrite, such as a glob" in outcome.verdicts[0].detail
    assert _host_answer(outcome, "claude") == "ask"


# --- a human rule (N24) ---------------------------------------------------------------------------------------------

def _hook(env: dict, repo: pathlib.Path, command: str) -> str | None:
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(repo),
                        "tool_input": {"command": command}})
    proc = subprocess.run([sys.executable, "-I", str(GATE), "--host", "claude"], input=event, capture_output=True,
                          text=True, env=env, timeout=120, check=False)
    assert proc.returncode == 0, proc.stderr
    answer = json.loads(proc.stdout) if proc.stdout.strip() else {}
    return answer.get("hookSpecificOutput", {}).get("permissionDecision")


@_gv.needs_git(2, 42, "git var names the configuration and attribute files git reads")
@pytest.mark.parametrize("form,frees", [("git blame *", False), ("git blame -- *", False), ("git blame 'a*'", True),
                                        ("git blame a.txt", True)])
def test_a_rule_frees_no_form_with_a_word_the_shell_rewrites(tmp_path, repo, form, frees):
    """The forms are blame forms, which ask without a rule. Until review fix 18 part B they were log forms; class a (D34) frees
    `git log` and `git log -- *` (a glob after `--` is a path) after the read profile without any rule."""
    gate_dir = tmp_path / "gatehome" / ".config" / "proofbundle"
    gate_dir.mkdir(parents=True)
    env = plugin_env(CLAUDE_PLUGIN_DATA=str(tmp_path / "logs"), PLUGIN_DATA=str(tmp_path / "logs"),
                     PROOFBUNDLE_GATE_DIR=str(gate_dir))
    (gate_dir / "mode").write_text("with-approvals\n", encoding="utf-8")
    common = os.path.realpath(subprocess.run(["git", "-C", str(repo), "rev-parse", "--path-format=absolute",
                                              "--git-common-dir"], capture_output=True, text=True,
                                             check=True).stdout.strip())
    digest = gate._bound_state_digest(str(repo), time.monotonic() + 30, env)
    (gate_dir / "rules.json").write_text(json.dumps([{"repo": common, "form": form, "effect": "free",
                                                      "state_digest": digest}]), encoding="utf-8")
    decision = _hook(env, repo, form)
    assert (decision is None) is frees, (form, decision)


# --- the predicate ------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("raw", ["*", "a?", "[ab]", "{a,b}", "^a", "a#", "=git", "-{-edit,m}", "x'y'*", '"a"?',
                                 "--no-verif?", "~", "~/x", "~+", "~-", "a=~", "a:~/x", "--file=~/x", "a.tx#t~b"])
def test_the_predicate_names_every_kind_of_rewrite(raw):
    assert gate._shell_rewrites(raw), raw


@pytest.mark.parametrize("raw", ["a.txt", "'*'", '"*"', "\\*", "a=b", "--message=x", "'a~b'", '"{a,b}"', "x\\?", "",
                                 "a~b", "a.txt~b", "x~", "'~'", "\\~"])
def test_the_predicate_leaves_literal_words(raw):
    assert not gate._shell_rewrites(raw), raw


@pytest.mark.parametrize("raw,rewrites", [("~", False), ("~/x", False), ("~root/x", True), ("~+", True),
                                          ("~-/x", True), ("~1", True), ("~/x*", True)])
def test_in_a_c_value_only_the_tilde_forms_expanduser_reads_like_the_shell_are_modelled(raw, rewrites):
    """`~root/x` is not modelled since review round 3 (R3-2): zsh reads `~name` from its named directories first."""
    assert gate._shell_rewrites(raw, tilde_modelled=True) is rewrites, raw
