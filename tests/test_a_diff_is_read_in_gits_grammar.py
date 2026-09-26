"""A diff is read in git's grammar, by one parser, and its lines are judged in the reader's grammar.

THE CLASS, measured on 2026-09-26 in throwaway repositories. The mutant guard and the language gate
each read `git diff` by the shape of a line, in text mode, under the caller's configuration, and
both reported a clean change over what they exist to catch:

- an added line that looks like a header (`++ 1`, `++ b/z.py`, both valid Python) was taken for one;
- a lone CR, which Python and CommonMark read as a line end and git does not, split the git line in
  text mode, and the rest lost its `+`;
- `diff.mnemonicPrefix` and `diff.external` changed the prefixes, or who writes the diff;
- a U+2028, which `splitlines()` reads as a line end and Python does not, shifted the numbering of
  every later line: a Markdown fence was misplaced, and the guard's allow marker was read two lines
  above the finding it suppressed.

The guard's cases are in tests/test_mutant_signature_guard.py, which the package ships. This file
holds the language gate's cases, whose script the package does not ship, and the sweep: one
function in scripts/ and tools/ reads hunk headers, and it is the guard's.
"""
from __future__ import annotations

import ast
import importlib.util
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GERMAN = "Diese Zeile ist deutsch und die Pruefung muss sie sehen."


def test_one_function_reads_hunk_headers_and_it_is_the_guards():
    readers = []
    for path in sorted((ROOT / "scripts").rglob("*.py")) + sorted((ROOT / "tools").rglob("*.py")):
        rel = path.relative_to(ROOT).as_posix()
        if "target" in path.relative_to(ROOT).parts:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue
        for fn in (n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))):
            if any(isinstance(n, ast.Constant) and isinstance(n.value, str)
                   and (n.value == "@@" or n.value.startswith("@@ ")) for n in ast.walk(fn)):
                readers.append(f"{rel}::{fn.name}")
    assert readers == ["scripts/mutant_signature_guard.py::_added_lines_by_file"], (
        f"functions that read hunk headers: {readers}. A diff is read in one place, in git's "
        "grammar; take `_added_lines_by_file` and `DIFF_GRAMMAR` from the mutant guard.")


def _language_gate():
    spec = importlib.util.spec_from_file_location("_grammar_language_gate",
                                                  ROOT / "scripts" / "neue_zeilen_sind_englisch.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def repo(tmp_path, monkeypatch):
    empty = tmp_path / "empty-gitconfig"
    empty.write_text("", encoding="utf-8")
    for key, value in {"GIT_CONFIG_GLOBAL": str(empty), "GIT_CONFIG_NOSYSTEM": "1",
                       "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
                       "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}.items():
        monkeypatch.setenv(key, value)
    r = tmp_path / "r"
    r.mkdir()
    (r / "m.py").write_text("y = 0\n", encoding="utf-8")
    (r / "a.md").write_text("# T\n", encoding="utf-8")
    for args in (("init", "-q"), ("add", "-A"), ("commit", "-q", "-m", "base")):
        subprocess.run(["git", "-C", str(r), *args], check=True, capture_output=True)
    return r


def _git(r: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(r), *args], check=True, capture_output=True,
                          text=True).stdout.strip()


def _judge(r: Path, rel: str, added: str, *, commit: bool = True, config=()):
    base = _git(r, "rev-parse", "HEAD")
    (r / rel).write_bytes((r / rel).read_bytes() + added.encode("utf-8"))
    if commit:
        _git(r, "add", "-A")
        _git(r, "commit", "-q", "-m", "change")
    for key, value in config:
        _git(r, "config", key, value)
    gate = _language_gate()
    gate.REPO, gate.REPO_HERKUNFT = r, "vorgabe"
    result = gate.pruefe(base, arbeitsbaum=not commit)
    return result["urteil"], [(b["datei"], b["zeile"]) for b in result["befunde"]]


def test_control_the_same_german_line_is_red(repo):
    assert _judge(repo, "m.py", f"x = 1\n# {GERMAN}\n") == ("ROT", [("m.py", 3)])


def test_an_added_line_shaped_like_a_header_is_an_added_line(repo):
    added = f'x = 1\n++ b/z.py\ndef f():\n    """{GERMAN}"""\n'
    assert _judge(repo, "m.py", added) == ("ROT", [("m.py", 5)])


def test_a_lone_cr_ends_a_line_and_the_rest_is_judged(repo):
    assert _judge(repo, "m.py", f"x = 1\r# {GERMAN}\n") == ("ROT", [("m.py", 3)])


@pytest.mark.parametrize("commit", [False, True], ids=["working-tree", "committed"])
@pytest.mark.parametrize("key", ["diff.mnemonicPrefix", "diff.external"])
def test_configuration_does_not_rewrite_the_grammar(repo, key, commit):
    """Both forms: the working tree, where mnemonicPrefix writes `w/`, and a committed range."""
    assert _judge(repo, "m.py", f"x = 1\n# {GERMAN}\n", commit=commit,
                  config=[(key, "true")]) == ("ROT", [("m.py", 3)])


@pytest.mark.parametrize("attribute", ["-diff", "binary"])
def test_an_attribute_that_makes_git_skip_the_lines_does_not_hide_them(repo, attribute):
    (repo / ".gitattributes").write_text(f"*.py {attribute}\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "attributes")
    assert _judge(repo, "m.py", f"x = 1\n# {GERMAN}\n") == ("ROT", [("m.py", 3)])


def test_a_bom_before_the_first_line_is_skipped(repo):
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "n.py").write_bytes(b"\xef\xbb\xbf# " + GERMAN.encode("utf-8") + b"\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "a file that starts with a BOM")
    gate = _language_gate()
    gate.REPO, gate.REPO_HERKUNFT = repo, "vorgabe"
    result = gate.pruefe(base)
    assert [(b["datei"], b["zeile"]) for b in result["befunde"]] == [("n.py", 1)], result


def test_a_markdown_line_after_a_u2028_is_numbered_as_the_diff_numbers_it(repo):
    added = f"One\u2028line.\n```\ncode\n```\n{GERMAN}\n"
    assert _judge(repo, "a.md", added) == ("ROT", [("a.md", 6)])


@pytest.mark.parametrize("rel,added,disk,line", [
    ("m.py", f'def f():\n    """\n    {GERMAN}\n    """\n', "y = 0\n", 4),
    ("a.md", f"{GERMAN}\n", "# T\n```\n\n```\n", 2),
], ids=["docstring", "markdown"])
def test_the_head_form_judges_the_file_at_head_not_the_disk(repo, rel, added, disk, line):
    """The lines come from `<base>...HEAD`, so the file that says which are prose is HEAD's. Here
    the working tree holds another version: no docstring, or a fence where the line was."""
    base = _git(repo, "rev-parse", "HEAD")
    (repo / rel).write_bytes((repo / rel).read_bytes() + added.encode("utf-8"))
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "change")
    (repo / rel).write_text(disk, encoding="utf-8")
    gate = _language_gate()
    gate.REPO, gate.REPO_HERKUNFT = repo, "vorgabe"
    result = gate.pruefe(base)
    assert [(b["datei"], b["zeile"]) for b in result["befunde"]] == [(rel, line)], result


@pytest.mark.parametrize("prefix", ["f", ""], ids=["f-string", "plain"])
def test_a_string_in_docstring_position_is_prose_whatever_its_prefix(repo, prefix):
    """An f-string where a docstring stands is not a docstring to Python, and it is prose all the
    same; the plain form is the control."""
    assert _judge(repo, "m.py", f'def f():\n    {prefix}"""{GERMAN}"""\n') == ("ROT", [("m.py", 3)])


def test_an_untracked_file_is_numbered_in_pythons_grammar(repo):
    (repo / "neu.py").write_bytes(f"x = 1\r# {GERMAN}\n".encode("utf-8"))
    gate = _language_gate()
    gate.REPO, gate.REPO_HERKUNFT = repo, "vorgabe"
    lines, state = gate._neue_zeilen(_git(repo, "rev-parse", "HEAD"), arbeitsbaum=True)
    assert state == "measured", state
    assert lines["neu.py"] == [(1, "x = 1"), (2, f"# {GERMAN}")], lines["neu.py"]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
