"""The mutant guard and the language gate read `git diff` in a form they name, not in the form a
configuration or an attribute gives it.

THE CLASS, from the counter-reading of pull request 415 (merge 89db1696): both gates parse a patch,
and the shape of that patch came from settings of the session that runs them.

- F1 (P2, new with 415): with `diff.interHunkContext` and `diff.suppressBlankEmpty` set together, git
  writes an empty context line between two changes as an empty line. The hunk count lost its step
  there, the header of the next file was read as hunk content, and the guard reported clean over a
  staged `if False:`, the language gate green over a German line. `GIT_DIFF_OPTS` brings context
  lines back past `-U0` and meets the same empty line.
- F2 (P2, older): an external diff program (`GIT_EXTERNAL_DIFF`, `diff.external`, the command of a
  diff driver), the text conversion of a driver, or a `-diff` attribute made git print no hunk at
  all, and both gates reported clean over a diff they had not read. A `-diff` line in a tracked
  `.gitattributes` is enough for that.
- The sweep of the class found one more: the language gate asked without `--no-color`, and
  `color.ui=always` made it green over a German line. The guard had the switch.

Each case below plants one of these settings beside a change the gate must see, and each setting
was red in at least one of the two gates before they named their form. A line the hunk count cannot hold now ends the reading as NOT
MEASURABLE, exit 2, instead of being passed over; the last cases hold that rule directly.
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "scripts" / "mutant_signature_guard.py"
GATE = ROOT / "scripts" / "neue_zeilen_sind_englisch.py"

GERMAN = "Diese Zeile ist deutsch und die Pruefung muss sie sehen."

#: Two changes with one plain and one empty line between them: under `diff.interHunkContext` they
#: join into one hunk, and the empty line becomes its context.
NEIGHBOUR_BEFORE = "a\nb\nc\n\ne\n"
NEIGHBOUR_AFTER = "a\nb2\nc\n\ne2\n"

#: (id, repository configuration, environment, .gitattributes line or None)
SETTINGS = [
    ("interHunkContext-and-suppressBlankEmpty",
     {"diff.interHunkContext": "3", "diff.suppressBlankEmpty": "true"}, {}, None),
    ("GIT_DIFF_OPTS-and-suppressBlankEmpty",
     {"diff.suppressBlankEmpty": "true"}, {"GIT_DIFF_OPTS": "--unified=3"}, None),
    ("GIT_EXTERNAL_DIFF", {}, {"GIT_EXTERNAL_DIFF": "true"}, None),
    ("diff.external", {"diff.external": "true"}, {}, None),
    ("attribute-minus-diff", {}, {}, "-diff"),
    ("attribute-driver-command", {"diff.blind.command": "true"}, {}, "diff=blind"),
    ("attribute-driver-textconv", {"diff.blind.textconv": "true"}, {}, "diff=blind"),
    # the neighbours found in the sweep of the class: the guard asked without colour, the language
    # gate did not; and a setting from the environment must not win over the pinned form
    ("color.ui-always", {"color.ui": "always"}, {}, None),
    ("color.diff-always", {"color.diff": "always"}, {}, None),
    ("GIT_CONFIG_COUNT-and-suppressBlankEmpty", {},
     {"GIT_CONFIG_COUNT": "2", "GIT_CONFIG_KEY_0": "diff.suppressBlankEmpty", "GIT_CONFIG_VALUE_0": "true",
      "GIT_CONFIG_KEY_1": "diff.interHunkContext", "GIT_CONFIG_VALUE_1": "3"}, None),
]


@pytest.fixture(autouse=True)
def _git_defaults(tmp_path, monkeypatch):
    """git as it ships: no global or system configuration, so each case sets only what it plants."""
    empty = tmp_path / "empty-gitconfig"
    empty.write_text("", encoding="utf-8")
    for key, value in {"GIT_CONFIG_GLOBAL": str(empty), "GIT_CONFIG_NOSYSTEM": "1",
                       "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
                       "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}.items():
        monkeypatch.setenv(key, value)
    for key in ("GIT_EXTERNAL_DIFF", "GIT_DIFF_OPTS"):
        monkeypatch.delenv(key, raising=False)


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                          check=True).stdout


def _write(repo: Path, rel: str, text: str) -> None:
    (repo / rel).parent.mkdir(parents=True, exist_ok=True)
    (repo / rel).write_text(text, encoding="utf-8")


def _plant(repo: Path, config: dict, attribute: str | None, pattern: str) -> None:
    for key, value in config.items():
        _git(repo, "config", key, value)
    if attribute:
        _write(repo, ".gitattributes", f"{pattern} {attribute}\n")


def _base_repo(tmp_path: Path, files: dict[str, str]) -> Path:
    repo = tmp_path / "r"
    repo.mkdir()
    _git(repo, "init", "-q")
    for rel, text in files.items():
        _write(repo, rel, text)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    return repo


def _guard(repo: Path, env: dict, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-B", str(GUARD), *args], cwd=str(repo), capture_output=True,
                          text=True, timeout=120, env=dict(os.environ, **env))


def _guard_repo(tmp_path: Path) -> Path:
    return _base_repo(tmp_path, {"src/proofbundle/notes.txt": NEIGHBOUR_BEFORE,
                                 "src/proofbundle/z.py": "y = 1\n"})


def _change_for_the_guard(repo: Path) -> None:
    _write(repo, "src/proofbundle/notes.txt", NEIGHBOUR_AFTER)
    _write(repo, "src/proofbundle/z.py", "y = 1\nif False:\n    pass\n")


@pytest.mark.parametrize("name,config,env,attribute", SETTINGS, ids=[s[0] for s in SETTINGS])
def test_the_guard_sees_a_staged_mutant_under_the_setting(tmp_path, name, config, env, attribute):
    repo = _guard_repo(tmp_path)
    _plant(repo, config, attribute, "*")
    _change_for_the_guard(repo)
    _git(repo, "add", "-A")
    r = _guard(repo, env, "--staged")
    assert r.returncode == 1, r.stdout + r.stderr
    assert "src/proofbundle/z.py:2: trivial-truth branch" in r.stdout, r.stdout


@pytest.mark.parametrize("name,config,env,attribute", SETTINGS, ids=[s[0] for s in SETTINGS])
def test_the_guard_sees_a_committed_mutant_under_the_setting(tmp_path, name, config, env, attribute):
    repo = _guard_repo(tmp_path)
    base = _git(repo, "rev-parse", "HEAD").strip()
    _plant(repo, config, attribute, "*")
    _change_for_the_guard(repo)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "a mutant slips in")
    r = _guard(repo, env, "--base", base)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "src/proofbundle/z.py:2: trivial-truth branch" in r.stdout, r.stdout


@pytest.mark.parametrize("name,config,env,attribute", SETTINGS, ids=[s[0] for s in SETTINGS])
def test_the_language_gate_sees_a_german_line_under_the_setting(tmp_path, name, config, env, attribute):
    repo = _base_repo(tmp_path, {"docs/a.md": NEIGHBOUR_BEFORE, "docs/z.md": "An English line.\n"})
    base = _git(repo, "rev-parse", "HEAD").strip()
    _plant(repo, config, attribute, "*")
    _write(repo, "docs/a.md", NEIGHBOUR_AFTER)
    _write(repo, "docs/z.md", f"An English line.\n{GERMAN}\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "a German line slips in")
    p = subprocess.run([sys.executable, "-B", str(GATE), "--base", base, "--repo", str(repo), "--json"],
                       capture_output=True, text=True, cwd=str(repo), timeout=120,
                       env=dict(os.environ, **env))
    result = json.loads(p.stdout)
    assert (p.returncode, result["urteil"]) == (1, "ROT"), result
    assert [(b["datei"], b["zeile"]) for b in result["befunde"]] == [("docs/z.md", 2)], result


def test_the_settings_do_change_what_git_prints(tmp_path):
    """The premise, measured: under each setting a plain `git diff -U0` of the change is not the hunk
    the gates read. If git ignored the settings, the cases above would pass against the old gates
    too and prove nothing."""
    for name, config, env, attribute in SETTINGS:
        sub = tmp_path / name
        sub.mkdir()
        repo = _guard_repo(sub)
        _plant(repo, config, attribute, "*")
        _change_for_the_guard(repo)
        _git(repo, "add", "-A")
        plain = subprocess.run(["git", "-C", str(repo), "diff", "--cached", "-U0", "--", "src/proofbundle"],
                               capture_output=True, text=True, env=dict(os.environ, **env)).stdout
        no_hunk = "+if False:\n+    pass\n" not in plain
        empty_context_line = "\n\n" in plain
        assert no_hunk or empty_context_line, (name, plain)


def test_the_hunks_the_guard_reads_carry_no_context_line(tmp_path, monkeypatch):
    """`-U0` promises hunks without context, and `diff.interHunkContext` breaks that promise by
    joining two changes across their context. The counter reads a context line correctly, so the
    cases above stay green without the pin; this case holds the promise itself."""
    guard = _load(GUARD, "_fixed_form_guard_context")
    repo = _guard_repo(tmp_path)
    _plant(repo, {"diff.interHunkContext": "3"}, None, "*")
    _change_for_the_guard(repo)
    _git(repo, "add", "-A")
    seen = []
    real = guard._git
    monkeypatch.setattr(guard, "_git", lambda *args, cwd: seen.append(real(*args, cwd=cwd)) or seen[-1])
    assert guard.run_staged(repo)
    in_hunk = [ln for ln in seen[0].split("\n") if ln.startswith(" ")]
    assert not in_hunk, seen[0]


# -- a line the hunk count cannot hold ends the reading ------------------------------------------

def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


#: A hunk that announces two lines on each side and carries an empty line where a context line
#: stands: the form `diff.suppressBlankEmpty` writes.
LOST_COUNT = ("diff --git a/src/proofbundle/n.txt b/src/proofbundle/n.txt\n"
              "--- a/src/proofbundle/n.txt\n+++ b/src/proofbundle/n.txt\n"
              "@@ -1,3 +1,3 @@\n-b\n+b2\n\n-e\n+e2\n"
              "diff --git a/src/proofbundle/z.py b/src/proofbundle/z.py\n"
              "--- a/src/proofbundle/z.py\n+++ b/src/proofbundle/z.py\n"
              "@@ -1,0 +2,2 @@\n+if False:\n+    pass\n")


def test_the_guard_parser_refuses_a_line_its_hunk_cannot_hold():
    guard = _load(GUARD, "_fixed_form_guard")
    with pytest.raises(guard.DiffNotReadable):
        guard._added_lines_by_file(LOST_COUNT)
    with pytest.raises(guard.DiffNotReadable):        # the diff ends inside an open hunk
        guard._added_lines_by_file("+++ b/src/proofbundle/z.py\n@@ -1,0 +1,2 @@\n+x = 1\n")


def test_the_guard_parser_reads_a_whole_hunk_as_before():
    """The control: a hunk with context lines and the marker of a missing final newline is read."""
    guard = _load(GUARD, "_fixed_form_guard_control")
    diff = ("+++ b/src/proofbundle/z.py\n@@ -1,2 +1,3 @@\n x = 1\n-y = 2\n+y = 3\n+if False:\n"
            "\\ No newline at end of file\n")
    assert guard._added_lines_by_file(diff) == {"src/proofbundle/z.py": [(2, "y = 3"), (3, "if False:")]}


def test_the_guard_exits_2_on_a_diff_it_cannot_read(tmp_path, monkeypatch, capsys):
    guard = _load(GUARD, "_fixed_form_guard_exit")
    repo = _base_repo(tmp_path, {"README.md": "r\n"})
    monkeypatch.chdir(repo)
    monkeypatch.setattr(guard, "_git", lambda *args, cwd: LOST_COUNT)
    assert guard.main(["--staged"]) == 2
    assert "NOT MEASURABLE" in capsys.readouterr().out


def test_the_language_gate_refuses_a_line_its_hunk_cannot_hold(tmp_path, monkeypatch):
    gate = _load(GATE, "_fixed_form_gate")
    monkeypatch.setattr(gate, "REPO", tmp_path)
    monkeypatch.setattr(gate, "_git", lambda *args: (0, LOST_COUNT.replace("src/proofbundle", "docs")))
    lines, state = gate._neue_zeilen("HEAD~1")
    assert (lines, state.split(":")[0]) == ({}, "NOT MEASURABLE"), state
