"""The language gate reads a `.py` file as Python reads it, and judges a line that the change turns into prose.

A review lens, run 10 at 50f3ef33 (2026-09-26), executed the first case, and the sweep of its class
over the stack found the others; each was reproduced at 50f3ef33 in a throwaway repository, and
each was judged green there:

- READ AS PYTHON READS IT. The gate decoded a `.py` file as UTF-8. Under `# coding: utf-7` the line
  `y = 1 +ACMAIA-Diese+ACA-Zeile...` is `y = 1 # Diese Zeile...` to Python, a German comment, and the
  gate judged the raw bytes: green in the HEAD form and in both working-tree forms. The mutant guard
  was fixed for the same class in 3c3c368e ("read as Python reads it") and the gate, which shares its
  diff reader, was not swept. It now reads the file through the guard's `_read_as_python`, one rule in
  one place; a file Python cannot decode or parse has no prose map, and the run is NOT MEASURABLE.
- JUDGED BY WHAT IT MEANS. The gate judged only added lines, and a change can give lines it leaves
  alone a new meaning: a change of only the coding cookie decodes every line after it anew; removing
  the lines that open and close a string turns the text inside into comments; removing a Markdown fence
  opener turns the code after it into prose. Each such change added no German line, and each was green.
  A line of a changed file that is prose now and whose text was not prose before is new material and is
  judged; a German line the decision keeps, unchanged and prose before and after, is not.
"""
from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GERMAN = "Diese Zeile ist deutsch und die Pruefung muss sie sehen."
#: The German line as a comment under `# coding: utf-7`: `+ACMAIA-` is `# `, `+ACA-` a space. As UTF-8
#: the same bytes are an expression of names, valid Python, so the file parses in both readings.
UTF7_COMMENT = ("y = 1 +ACMAIA-" + "+ACA-".join(GERMAN.rstrip(".").split(" "))).encode("ascii")


def _gate():
    spec = importlib.util.spec_from_file_location("_gate_reads_python", ROOT / "scripts" / "neue_zeilen_sind_englisch.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _git(r: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(r), "-c", "user.name=t", "-c", "user.email=t@t", *args],
                          check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture()
def repo(tmp_path):
    r = tmp_path / "r"
    r.mkdir()
    (r / "m.py").write_text("y = 0\n", encoding="utf-8")
    (r / "a.md").write_text("# T\n", encoding="utf-8")
    _git(r, "init", "-q")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "base")
    return r


def _judge(r: Path, base: str, *, working_tree: bool = False):
    gate = _gate()
    gate.REPO, gate.REPO_HERKUNFT = r, "vorgabe"
    result = gate.pruefe(base, arbeitsbaum=working_tree)
    return result["urteil"], [(b["datei"], b["zeile"]) for b in result["befunde"]]


def _commit(r: Path, message: str) -> str:
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", message)
    return _git(r, "rev-parse", "HEAD")


def test_precondition_python_reads_the_line_as_a_german_comment():
    import io
    import tokenize
    source = b"# coding: utf-7\n" + UTF7_COMMENT + b"\n"
    comments = [t.string for t in tokenize.tokenize(io.BytesIO(source).readline) if t.type == tokenize.COMMENT]
    assert comments == ["# coding: utf-7", "# " + GERMAN.rstrip(".")]
    compile(UTF7_COMMENT, "as-utf-8", "exec")      # and the bytes are Python as UTF-8 too


# -- read as Python reads it ----------------------------------------------------------------------

@pytest.mark.parametrize("form", ["committed", "staged", "untracked"])
def test_a_german_comment_under_a_utf7_cookie_is_judged(repo, form):
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "n.py").write_bytes(b"# coding: utf-7\n" + UTF7_COMMENT + b"\n")
    if form == "committed":
        _commit(repo, "a comment under a utf-7 cookie")
    elif form == "staged":
        _git(repo, "add", "-A")
    assert _judge(repo, base, working_tree=form != "committed") == ("ROT", [("n.py", 2)])


@pytest.mark.parametrize("form", ["committed", "untracked"])
def test_a_file_python_cannot_decode_is_not_measurable(repo, form):
    """No cookie and a byte that is not UTF-8: Python refuses the file. The gate decoded it with
    replacement characters and judged the docstring beside it as if Python could read it."""
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "n.py").write_bytes(b"s = '\xfc'\ndef f():\n    \"\"\"" + GERMAN.encode() + b"\"\"\"\n")
    if form == "committed":
        _commit(repo, "a file Python cannot decode")
    gate = _gate()
    gate.REPO, gate.REPO_HERKUNFT = repo, "vorgabe"
    result = gate.pruefe(base, arbeitsbaum=form != "committed")
    assert (result["urteil"], result["rc"], result["ohne_prosakarte"]) == ("NOT MEASURABLE", 2, ["n.py"])


def test_control_a_latin_1_cookie_is_read_and_judged(repo):
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "n.py").write_bytes(b"# -*- coding: latin-1 -*-\ns = '\xfc'\n# " + GERMAN.encode() + b"\n")
    _commit(repo, "a latin-1 file")
    assert _judge(repo, base) == ("ROT", [("n.py", 3)])


# -- judged by what it means ----------------------------------------------------------------------

def test_a_change_of_only_the_coding_cookie_is_judged(repo):
    (repo / "w.py").write_bytes(b"x = 0\n" + UTF7_COMMENT + b"\n")
    base = _commit(repo, "a line of names")
    (repo / "w.py").write_bytes(b"# coding: utf-7\n" + UTF7_COMMENT + b"\n")
    _commit(repo, "only the first line changes")
    assert _judge(repo, base) == ("ROT", [("w.py", 2)])


def test_removing_the_lines_around_a_string_turns_its_text_into_comments(repo):
    (repo / "w.py").write_text(f'x = """\n# {GERMAN}\n"""\n', encoding="utf-8")
    base = _commit(repo, "German text inside a string, which is data")
    (repo / "w.py").write_text(f"# {GERMAN}\n", encoding="utf-8")
    _commit(repo, "the two lines around it go")
    assert _judge(repo, base) == ("ROT", [("w.py", 1)])


def test_removing_a_fence_opener_turns_the_code_after_it_into_prose(repo):
    (repo / "a.md").write_text(f"# T\n\n```\n{GERMAN}\n```\n", encoding="utf-8")
    base = _commit(repo, "German text in a fence, which is code")
    (repo / "a.md").write_text(f"# T\n\n{GERMAN}\n```\n", encoding="utf-8")
    _commit(repo, "the opener goes")
    assert _judge(repo, base) == ("ROT", [("a.md", 3)])


@pytest.mark.parametrize("rel,before,after", [
    ("w.py", f"# {GERMAN}\nx = 1\n", f"# {GERMAN}\nx = 2\n"),
    ("a.md", f"# T\n\n{GERMAN}\n\nOne.\n", f"# T\n\n{GERMAN}\n\nTwo.\n"),
    ("w.py", f"x = 1\n# {GERMAN}\ny = 2\n", f"# {GERMAN}\ny = 2\n"),
], ids=["python-edit-elsewhere", "markdown-edit-elsewhere", "python-a-line-removed-above"])
def test_control_a_german_line_that_stays_prose_is_kept(repo, rel, before, after):
    """The owner decision keeps the existing body: an unchanged German line that was prose before the
    change and is prose after it is not new material, whatever else the change does."""
    (repo / rel).write_text(before, encoding="utf-8")
    base = _commit(repo, "an existing German line")
    (repo / rel).write_text(after, encoding="utf-8")
    _commit(repo, "a change elsewhere")
    assert _judge(repo, base) == ("gruen", [])


def test_control_a_moved_german_line_is_an_added_line_as_before(repo):
    """Moved past three lines, so that git keeps the three and adds the German one at its new place."""
    (repo / "w.py").write_text(f"# {GERMAN}\na = 1\nb = 2\nc = 3\n", encoding="utf-8")
    base = _commit(repo, "an existing German line")
    (repo / "w.py").write_text(f"a = 1\nb = 2\nc = 3\n# {GERMAN}\n", encoding="utf-8")
    _commit(repo, "the line moves")
    assert _judge(repo, base) == ("ROT", [("w.py", 4)])


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
