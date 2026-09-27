"""The English gate reads each file once per run, and that changes no verdict.

MEASURED 2026-09-26 on pull request 278. For every added line that was not a comment line, the gate
read, tokenized and parsed the whole file again. One call over that branch's 8009 added lines took
139.39 s, against 0.93 s for 26 lines, and seven such calls in the suite pushed the test job past
its 50-minute limit. The gate now keeps what it read for the length of one run.

Three properties are pinned here. The verdict with the per-run cache equals the verdict without it,
on a tree with findings, docstrings, code, a quote inside a string and a Markdown fence. Each file is
read once per run and not once per line. And a second run reads a changed file again: a cache that
outlived the run was measured too, and it answered the second run from the first run's file.
"""
from __future__ import annotations

import collections
import importlib.util
import pathlib
import subprocess

_WURZEL = pathlib.Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "nz_einmal", _WURZEL / "scripts" / "neue_zeilen_sind_englisch.py")
NZ = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(NZ)

Q = chr(34) * 3
DEUTSCH = "Diese deutsche Zeile mit der und die und das gehoert geprueft."

#: A module with a German comment, a German docstring line, an English docstring line, code, and a
#: code line that carries a triple quote inside a string (the case the tokenizer exists for).
MOD = ("X = 1\n"
       "# " + DEUTSCH + "\n"
       "y = 'er sagte " + Q + " und ging'\n"
       "def f():\n"
       "    " + Q + "\n"
       "    " + DEUTSCH + "\n"
       "    An English line inside the docstring.\n"
       "    " + Q + "\n"
       "    return 1\n")
#: A second module whose German docstring stands on line 4, a code line in MOD, so a cache that
#: answered this file from MOD's reading would miss it.
ZWEITE = ("Y = 2\n"
          "Z = 3\n"
          "def g():\n"
          "    " + Q + "Ein Docstring, der und die und das enthaelt." + Q + "\n"
          "    return Y\n")
#: MOD again with the same number of lines, the docstring gone: line 6 now holds the German text as
#: an ordinary string, which is code. A reading kept from MOD would still call it prose.
MOD_OHNE_DOCSTRING = ("X = 1\n"
                      "# " + DEUTSCH + "\n"
                      "y = 'er sagte " + Q + " und ging'\n"
                      "def f():\n"
                      "    x = 0\n"
                      "    s = '" + DEUTSCH + "'\n"
                      "    t = 'An English line.'\n"
                      "    u = 1\n"
                      "    return 1\n")
NOTIZ = ("# Notes\n"
         + DEUTSCH + "\n"
         "```text\n"
         + DEUTSCH + "\n"
         "```\n"
         "An English closing line.\n")


def _git(cwd, *args):
    r = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    assert r.returncode == 0, f"git {' '.join(args)} failed: {r.stderr}"
    return r.stdout.strip()


def _commit(repo: pathlib.Path, files: dict, message: str) -> str:
    for name, text in files.items():
        (repo / name).write_text(text, encoding="utf-8")
    _git(repo, "add", *files)
    _git(repo, "commit", "-q", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


def _baum(tmp_path, monkeypatch, files: dict) -> str:
    """A throwaway repository whose second commit adds `files`; the gate judges it. -> the base."""
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "t@example.invalid")
    _git(tmp_path, "config", "user.name", "t")
    basis = _commit(tmp_path, {"alt.py": "OLD = 0\n"}, "base")
    _commit(tmp_path, files, "added")
    monkeypatch.setattr(NZ, "REPO", tmp_path)
    monkeypatch.setattr(NZ, "REPO_HERKUNFT", "vorgabe")
    return basis


def _ohne_cache(monkeypatch):
    monkeypatch.setattr(NZ, "_gelesen", lambda fn, datei, cache: fn(datei))


def test_the_verdict_with_the_cache_equals_the_verdict_without_it(tmp_path, monkeypatch):
    basis = _baum(tmp_path, monkeypatch, {"mod.py": MOD, "zweite.py": ZWEITE, "notiz.md": NOTIZ})
    mit = NZ.pruefe(basis)
    _ohne_cache(monkeypatch)
    ohne = NZ.pruefe(basis)
    assert mit == ohne
    # The comparison means something only on a tree that has findings and non-findings alike.
    gefunden = {(b["datei"], b["zeile"]) for b in mit["befunde"]}
    assert gefunden == {("mod.py", 2), ("mod.py", 6), ("zweite.py", 4), ("notiz.md", 2)}, gefunden
    assert mit["urteil"] == "ROT" and mit["geprueft"] == 20 and mit["dateien"] == 3


def test_each_file_is_read_once_per_run(tmp_path, monkeypatch):
    basis = _baum(tmp_path, monkeypatch, {"mod.py": MOD, "zweite.py": ZWEITE, "notiz.md": NOTIZ})
    gelesen: collections.Counter = collections.Counter()
    for name in ("_prosazeilen", "_md_prosazeilen"):
        echt = getattr(NZ, name)

        def zaehlend(datei, _echt=echt, _name=name):
            gelesen[(_name, datei)] += 1
            return _echt(datei)
        monkeypatch.setattr(NZ, name, zaehlend)
    NZ.pruefe(basis)
    assert dict(gelesen) == {("_prosazeilen", "mod.py"): 1, ("_prosazeilen", "zweite.py"): 1,
                             ("_md_prosazeilen", "notiz.md"): 1}
    # Positive control: without the cache the same counter sees one read per added line that is
    # not a comment line (8 of the 9 in mod.py, 5 in zweite.py, every line of the Markdown file),
    # so a counter that could only ever say 1 would not pass this test.
    gelesen.clear()
    _ohne_cache(monkeypatch)
    NZ.pruefe(basis)
    assert dict(gelesen) == {("_prosazeilen", "mod.py"): 8, ("_prosazeilen", "zweite.py"): 5,
                             ("_md_prosazeilen", "notiz.md"): 6}


def test_a_second_run_reads_the_file_again(tmp_path, monkeypatch):
    """The cache lives for one run. A cache that outlived it answered this second run from the
    first run's reading of the file: line 6, a docstring line then and a string now, stayed prose,
    and the German text on it stayed a finding."""
    basis = _baum(tmp_path, monkeypatch, {"mod.py": MOD})
    erster = NZ.pruefe(basis)
    assert ("mod.py", 6) in {(b["datei"], b["zeile"]) for b in erster["befunde"]}
    _commit(tmp_path, {"mod.py": MOD_OHNE_DOCSTRING}, "no docstring now")
    zweiter = NZ.pruefe(basis)
    assert ("mod.py", 6) not in {(b["datei"], b["zeile"]) for b in zweiter["befunde"]}
    assert {(b["datei"], b["zeile"]) for b in zweiter["befunde"]} == {("mod.py", 2)}
