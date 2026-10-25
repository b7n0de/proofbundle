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
was red in at least one of the two gates before they named their form. A line the hunk count cannot
hold now ends the reading as NOT MEASURABLE, exit 2, instead of being passed over; the cases after
the settings hold that rule directly.

THE SECOND COUNTER-READING, of the fixed form itself (at ba2da31e), found the class one layer further
out: what git writes was decoded as text, so a binary file under `--text` and a lone CR changed the
reading, and the environment of the session, not only its configuration, changed what git printed.
Its cases stand in the last section.
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
    monkeypatch.setattr(gate, "_git", lambda *args, **kw: (0, LOST_COUNT.replace("src/proofbundle", "docs")))
    lines, state = gate._neue_zeilen("HEAD~1")
    assert (lines, state.split(":")[0]) == ({}, "NOT MEASURABLE"), state


# -- the second counter-reading, of the fixed form at ba2da31e -----------------------------------

#: A PNG header: bytes that are not UTF-8, a CR LF and a lone CR, the way a binary file starts.
PNG = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\xff\xfe\x80\x81"


def _gate(repo: Path, base: str, env: dict | None = None) -> tuple[int, dict | None, str]:
    p = subprocess.run([sys.executable, "-B", str(GATE), "--base", base, "--repo", str(repo), "--json"],
                       capture_output=True, text=True, cwd=str(repo), timeout=120,
                       env=dict(os.environ, **(env or {})))
    try:
        return p.returncode, json.loads(p.stdout), p.stderr
    except ValueError:
        return p.returncode, None, p.stderr


def test_F1_a_binary_file_under_text_is_read_not_a_crash(tmp_path):
    """F1 (P2, new with the fixed form): under `--text` a binary file is a hunk, and bytes that are not UTF-8 ended both
    gates with a traceback and exit 1, the code of a finding. Both read past it now, to the change behind it."""
    repo = _guard_repo(tmp_path)
    (repo / "src" / "proofbundle" / "data.bin").write_bytes(PNG)
    _change_for_the_guard(repo)
    _git(repo, "add", "-A")
    r = _guard(repo, {}, "--staged")
    assert "Traceback" not in r.stderr, r.stderr
    assert r.returncode == 1 and "src/proofbundle/z.py:2: trivial-truth branch" in r.stdout, r.stdout + r.stderr
    (tmp_path / "g").mkdir()
    gate_repo = _base_repo(tmp_path / "g", {"docs/z.md": "An English line.\n"})
    base = _git(gate_repo, "rev-parse", "HEAD").strip()
    (gate_repo / "docs" / "pic.md").write_bytes(PNG)
    _write(gate_repo, "docs/z.md", f"An English line.\n{GERMAN}\n")
    _git(gate_repo, "add", "-A")
    _git(gate_repo, "commit", "-q", "-m", "a picture and a German line")
    rc, result, err = _gate(gate_repo, base)
    assert "Traceback" not in err, err
    assert (rc, result["urteil"]) == (1, "ROT") and ("docs/z.md", 2) in [(b["datei"], b["zeile"]) for b in result["befunde"]], result


@pytest.mark.parametrize("name", ["GIT_LITERAL_PATHSPECS", "GIT_GLOB_PATHSPECS", "GIT_NOGLOB_PATHSPECS"])
def test_F2_a_pathspec_switch_of_the_environment_does_not_blind_the_language_gate(tmp_path, name):
    """F2 (P2): each of the three made the `*.md` pathspec match nothing, and the gate was green over a German line."""
    repo = _base_repo(tmp_path, {"docs/z.md": "An English line.\n"})
    base = _git(repo, "rev-parse", "HEAD").strip()
    _write(repo, "docs/z.md", f"An English line.\n{GERMAN}\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "a German line")
    rc, result, err = _gate(repo, base, {name: "1"})
    assert (rc, result["urteil"]) == (1, "ROT"), (result, err)


@pytest.mark.parametrize("content,line", [(b"1\rif False:\r    pass\r", 1), (b"y = 1\n\rif False: pass\n", 2)],
                         ids=["one-line-for-git", "cr-before-the-statement"])
def test_F3_a_lone_cr_does_not_hide_a_mutant(tmp_path, content, line):
    """F3 (P2): Python ends a line at a lone CR, git does not; the statement after it was clean in both gates."""
    repo = _guard_repo(tmp_path)
    (repo / "src" / "proofbundle" / "z.py").write_bytes(content)
    _git(repo, "add", "-A")
    r = _guard(repo, {}, "--staged")
    assert r.returncode == 1 and f"src/proofbundle/z.py:{line}: trivial-truth branch" in r.stdout, r.stdout + r.stderr


def test_F3_a_lone_cr_does_not_hide_a_german_line(tmp_path):
    repo = _base_repo(tmp_path, {"docs/z.md": "Intro.\n"})
    base = _git(repo, "rev-parse", "HEAD").strip()
    (repo / "docs" / "z.md").write_bytes(f"Intro.\nAn English line.\r{GERMAN}\n".encode())
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "a German line after a CR")
    rc, result, err = _gate(repo, base)
    assert (rc, result["urteil"]) == (1, "ROT"), (result, err)


def _committed_mutant(tmp_path: Path) -> tuple[Path, str]:
    repo = _guard_repo(tmp_path)
    base = _git(repo, "rev-parse", "HEAD").strip()
    _change_for_the_guard(repo)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "a mutant slips in")
    return repo, base


def test_F4_a_trace_on_stdout_does_not_skip_the_range(tmp_path):
    """F4 (P3): `GIT_TRACE=/dev/stdout` wrote into the answer of `rev-parse`, and the range mode said "scan skipped
    honestly" with exit 0 over a mutant in the range."""
    repo, base = _committed_mutant(tmp_path)
    r = _guard(repo, {"GIT_TRACE": "/dev/stdout"}, "--base", base)
    assert r.returncode == 1 and "src/proofbundle/z.py:2: trivial-truth branch" in r.stdout, r.stdout + r.stderr


@pytest.mark.parametrize("use_replace_refs", [None, "true"], ids=["default", "core.useReplaceRefs-true"])
def test_F5_a_replacement_ref_does_not_hide_the_change(tmp_path, use_replace_refs):
    """F5 (P3): a local `refs/replace` pointed the mutant's blob at its predecessor, and the range was clean. The second
    form sets `core.useReplaceRefs=true` in the repository, which the receipt chain records winning over the
    environment name and the switch; with git 2.55.0 each of the guard's three settings wins alone."""
    repo, base = _committed_mutant(tmp_path)
    if use_replace_refs:
        _git(repo, "config", "core.useReplaceRefs", use_replace_refs)
    _git(repo, "replace", _git(repo, "rev-parse", "HEAD:src/proofbundle/z.py").strip(),
         _git(repo, "rev-parse", f"{base}:src/proofbundle/z.py").strip())
    assert "+if False:" not in _git(repo, "diff", "-U0", base, "HEAD", "--", "src/proofbundle/z.py"), "premise"
    r = _guard(repo, {}, "--base", base)
    assert r.returncode == 1 and "src/proofbundle/z.py:2: trivial-truth branch" in r.stdout, r.stdout + r.stderr


def test_F6_a_failed_git_call_exits_2_as_the_header_says(tmp_path):
    """F6 (P3): the header promises exit 2 for an internal error; a failed git call ended with exit 1, a finding's."""
    repo = _guard_repo(tmp_path)
    (repo / ".git" / "index").write_bytes(b"not an index")
    r = _guard(repo, {}, "--staged")
    assert r.returncode == 2 and "fail closed" in r.stderr, r.stdout + r.stderr


def test_F1b_a_security_file_that_is_not_utf8_is_not_measurable(tmp_path):
    """F1b (P3): a Latin-1 file on a security path ended the guard with a traceback and exit 1."""
    repo = _guard_repo(tmp_path)
    (repo / "src" / "proofbundle" / "z.py").write_bytes(b"# -*- coding: latin-1 -*-\ny = 'caf\xe9'\nif False:\n    pass\n")
    _git(repo, "add", "-A")
    r = _guard(repo, {}, "--staged")
    assert "Traceback" not in r.stderr, r.stderr
    assert r.returncode == 2 and "is not UTF-8" in r.stdout, r.stdout + r.stderr


def test_the_index_the_hook_names_is_the_index_the_guard_reads(tmp_path):
    """The built environment keeps `GIT_INDEX_FILE`: inside the pre-commit hook of a commit of named paths git names a
    temporary index there, and a guard that dropped it read the default index and let the mutant through."""
    repo = _guard_repo(tmp_path)
    _change_for_the_guard(repo)
    other = tmp_path / "other-index"
    subprocess.run(["git", "-C", str(repo), "read-tree", "HEAD"], check=True, capture_output=True,
                   env=dict(os.environ, GIT_INDEX_FILE=str(other)))
    subprocess.run(["git", "-C", str(repo), "add", "src/proofbundle/z.py"], check=True, capture_output=True,
                   env=dict(os.environ, GIT_INDEX_FILE=str(other)))
    assert _guard(repo, {}, "--staged").returncode == 0, "premise: the default index carries no change"
    r = _guard(repo, {"GIT_INDEX_FILE": str(other)}, "--staged")
    assert r.returncode == 1 and "src/proofbundle/z.py:2: trivial-truth branch" in r.stdout, r.stdout + r.stderr


def test_each_layer_holds_alone_the_pinned_settings_without_the_built_environment(tmp_path, monkeypatch):
    """Defence in depth, measured one layer at a time. With the built environment the context lines of `GIT_DIFF_OPTS`
    never reach the guard, so the pin of `diff.suppressBlankEmpty` had no case of its own. Here the environment lets
    `GIT_DIFF_OPTS` through, and the pinned setting alone must keep the hunk count."""
    guard = _load(GUARD, "_fixed_form_guard_layers")
    repo = _guard_repo(tmp_path)
    _plant(repo, {"diff.suppressBlankEmpty": "true"}, None, "*")
    _change_for_the_guard(repo)
    _git(repo, "add", "-A")
    monkeypatch.setattr(guard, "_GIT_INHERITED", guard._GIT_INHERITED + ("GIT_DIFF_OPTS",))
    monkeypatch.setenv("GIT_DIFF_OPTS", "--unified=3")
    findings = guard.run_staged(repo)
    assert any(f.startswith("src/proofbundle/z.py:2: trivial-truth branch") for f in findings), findings
