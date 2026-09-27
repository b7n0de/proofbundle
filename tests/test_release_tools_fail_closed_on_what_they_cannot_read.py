"""The release tools end in their own verdict on what they cannot parse, cannot see or cannot count.

A review lens, run 10 at 50f3ef33 (2026-09-26), executed three classes in the stack of release tools,
and a sweep over the five tools found their neighbours; each case below was reproduced at 50f3ef33:

- PARSE BOUNDS. An except clause that names SyntaxError and ValueError lets a MemoryError or a
  RecursionError through. A comment `# ok = verify(` with 7000 nested unary minus ended the mutant
  guard with a traceback and exit 1, the code of a finding; the same depth in a `.py` file ended the
  language gate the same way, and so did a string statement of 3000 literals joined by `+`, which the
  gate's recursive `_nur_text` walked. The guard compared two trees with the recursive `ast.dump`, so a
  file Python compiles (2000 nested unary minus) stopped it with the reason "not the text Python
  parsed", which was not true.
- FILE SYSTEM ANSWERS. `pathlib` predicates re-raise EACCES. A tracked path under a directory without
  search permission ended the digest resolver (`is_dir`) and the version gate (`is_file`) with a
  traceback and exit 1; and the version gate's sweep skipped a tracked file it could not open, so a
  current-version claim in it was not seen and the gate said OK with exit 0.
- DIGITS. `str.isdigit()` is true for `²` and for `٣`: `_semver_tuple("6.1.0²")` raised in `int()`,
  and `_semver_tuple("6.1.0٣")` read the Arabic-Indic three as the patch number 3.

Each case runs the real tool, in a subprocess where the exit code is the verdict.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "scripts" / "mutant_signature_guard.py"
GATE = ROOT / "scripts" / "neue_zeilen_sind_englisch.py"
RESOLVER = ROOT / "scripts" / "audit_output_aufloesbar.py"
VERSION_GATE = ROOT / "scripts" / "check_version_and_changelog.py"
GERMAN = "Diese Zeile ist deutsch und die Pruefung muss sie sehen."


def _git(repo: Path, *args: str, **kw) -> str:
    return subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", *args],
                          capture_output=True, text=True, check=True, **kw).stdout.strip()


def _run(script: Path, *args: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-B", str(script), *args], cwd=str(cwd) if cwd else None,
                          capture_output=True, text=True, timeout=300)


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def repo(tmp_path):
    r = tmp_path / "r"
    (r / "src" / "proofbundle").mkdir(parents=True)
    (r / "src" / "proofbundle" / "g.py").write_text("x = 0\n", encoding="utf-8")
    (r / "m.py").write_text("y = 0\n", encoding="utf-8")
    _git(r, "init", "-q")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "base")
    return r


def _no_search_permission():
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        pytest.skip("root reads a directory without search permission, so the case cannot be built")


# -- parse bounds -------------------------------------------------------------------------------

def test_the_guard_stops_fail_closed_on_a_comment_too_deep_to_parse(repo):
    (repo / "src" / "proofbundle" / "g.py").write_text("# ok = verify(" + "-" * 7000 + "1)\n",
                                                       encoding="utf-8")
    _git(repo, "add", "-A")
    r = _run(GUARD, "--staged", cwd=repo)
    assert "Traceback" not in r.stderr, r.stderr
    assert r.returncode == 2, r.stdout + r.stderr
    assert "src/proofbundle/g.py:1: a comment nests deeper than the parser reads" in r.stderr, r.stderr


@pytest.mark.parametrize("expression", ["-" * 2000 + "1", "+".join(["1"] * 1000)],
                         ids=["2000-unary-minus", "1000-terms"])
def test_the_guard_judges_a_deep_file_python_compiles(repo, expression):
    """Python compiles both; the guard judged neither, and said the decoded text was another."""
    source = f"x = {expression}\nif False:\n    pass\n"
    compile(source, "probe", "exec")                  # the precondition: Python reads this file
    (repo / "src" / "proofbundle" / "g.py").write_text(source, encoding="utf-8")
    _git(repo, "add", "-A")
    r = _run(GUARD, "--staged", cwd=repo)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "src/proofbundle/g.py:2: trivial-truth branch" in r.stdout, r.stdout


def test_the_language_gate_is_not_measurable_on_a_file_too_deep_to_parse(repo):
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "m.py").write_text(f"x = 1\n# {GERMAN}\ny = " + "-" * 7000 + "1\n", encoding="utf-8")
    _git(repo, "commit", "-q", "-am", "deep")
    r = _run(GATE, "--base", base, "--json", cwd=repo)
    assert "Traceback" not in r.stderr, r.stderr
    d = json.loads(r.stdout)
    assert (r.returncode, d["urteil"], d["ohne_prosakarte"]) == (2, "NOT MEASURABLE", ["m.py"]), d


def test_the_language_gate_reads_a_long_chain_of_joined_literals(repo):
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "m.py").write_text("x = 1\n" + " + ".join(['"Deutsch und die Zeile"'] * 3000) + "\n",
                               encoding="utf-8")
    _git(repo, "commit", "-q", "-am", "a string statement of 3000 literals")
    r = _run(GATE, "--base", base, "--json", cwd=repo)
    assert "Traceback" not in r.stderr, r.stderr
    d = json.loads(r.stdout)
    assert (r.returncode, d["urteil"], [(b["datei"], b["zeile"]) for b in d["befunde"]]) \
        == (1, "ROT", [("m.py", 2)]), d


def test_the_version_gate_reads_an_external_answer_too_deep_to_parse_as_not_measurable(monkeypatch):
    gate = _load(VERSION_GATE, "_version_gate_parse_bounds")
    monkeypatch.setattr(gate, "_fetch", lambda url, timeout: "[" * 100000 + "]" * 100000)
    result = gate.check_external("1.0.0", 1.0)
    assert [(name, state) for name, state, _ in result] == [("PyPI", gate.NICHT_MESSBAR),
                                                            ("project page", gate.NICHT_MESSBAR)]


def test_the_version_gate_reads_an_external_answer_within_a_bound(monkeypatch):
    """The two answers measured 94753 and 117471 bytes (2026-09-26); a larger one is not read whole."""
    gate = _load(VERSION_GATE, "_version_gate_network_bound")
    asked = []

    class Answer:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self, n=-1):
            asked.append(n)
            return b"x" * (gate._NETZGRENZE + 1 if n == -1 or n > gate._NETZGRENZE else n)

    monkeypatch.setattr(gate.urllib.request, "urlopen", lambda req, timeout: Answer())
    assert gate._fetch("https://example.invalid/", 1.0) is None
    assert asked and all(0 <= n <= gate._NETZGRENZE + 1 for n in asked), asked


# -- file system answers ------------------------------------------------------------------------

def test_the_resolver_counts_a_path_it_may_not_see_as_not_hashed(tmp_path):
    _no_search_permission()
    r = tmp_path / "r"
    (r / "locked").mkdir(parents=True)
    (r / "locked" / "rec.md").write_text("a record\n", encoding="utf-8")
    (r / "README.md").write_text("# r\n", encoding="utf-8")
    _git(r, "init", "-q")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "a record")
    receipt = tmp_path / "q.json"
    receipt.write_text(json.dumps({"audit_output_digest": "a" * 64}), encoding="utf-8")
    (r / "locked").chmod(0)
    try:
        out = _run(RESOLVER, "--receipt", str(receipt), "--repo", str(r), "--json")
    finally:
        (r / "locked").chmod(0o755)
    assert "Traceback" not in out.stderr, out.stderr
    d = json.loads(out.stdout)
    assert (out.returncode, d["zustand"], d["nicht_gehasht"]) == (2, "NICHT_MESSBAR", ["locked/rec.md"]), d


@pytest.fixture()
def tree(tmp_path):
    archive = subprocess.run(["git", "-C", str(ROOT), "archive", "HEAD"], capture_output=True)
    if archive.returncode != 0:
        pytest.skip("NOT MEASURABLE here: this tree is not a git checkout")
    t = tmp_path / "tree"
    t.mkdir()
    subprocess.run(["tar", "-x", "-C", str(t)], input=archive.stdout, check=True)
    _git(t, "init", "-q")
    _git(t, "add", "-A")
    _git(t, "commit", "-q", "-m", "the tree")
    return t


def _version(t: Path) -> str:
    return re.search(r'(?m)^version = "([^"]+)"', (t / "pyproject.toml").read_text(encoding="utf-8")).group(1)


@pytest.mark.parametrize("locked", ["docs/readiness_pack", "docs/readiness_pack/PROGRESS.md"],
                         ids=["directory-without-search-permission", "file-without-read-permission"])
def test_the_version_gate_names_a_tracked_place_it_cannot_read(tree, locked):
    _no_search_permission()
    (tree / locked).chmod(0)
    try:
        r = _run(VERSION_GATE, "--repo", str(tree))
    finally:
        (tree / locked).chmod(0o755 if (tree / locked).is_dir() else 0o644)
    assert "Traceback" not in r.stderr, r.stderr
    assert r.returncode == 1, r.stdout + r.stderr
    assert "docs/readiness_pack/PROGRESS.md cannot be read (Permission denied)" in r.stdout, r.stdout


@pytest.mark.parametrize("locked", ["docs/lockme", "docs/lockme/claim.md"],
                         ids=["directory-without-search-permission", "file-without-read-permission"])
def test_the_version_gate_sweep_does_not_skip_a_file_it_cannot_read(tree, locked):
    _no_search_permission()
    (tree / "docs" / "lockme").mkdir()
    (tree / "docs" / "lockme" / "claim.md").write_text(f"current release: {_version(tree)}\n",
                                                       encoding="utf-8")
    _git(tree, "add", "-A")
    _git(tree, "commit", "-q", "-m", "a claim")
    assert _run(VERSION_GATE, "--repo", str(tree)).returncode == 1      # control: the claim is seen
    (tree / locked).chmod(0)
    try:
        r = _run(VERSION_GATE, "--repo", str(tree))
    finally:
        (tree / locked).chmod(0o755 if (tree / locked).is_dir() else 0o644)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "docs/lockme/claim.md cannot be read (Permission denied)" in r.stdout, r.stdout


# -- digits -------------------------------------------------------------------------------------

@pytest.mark.parametrize("version", ["6.1.0\u00b2", "6.1.0\u0663"], ids=["superscript-two", "arabic-indic-three"])
def test_a_version_part_that_is_no_ascii_digit_counts_as_none(version):
    gate = _load(VERSION_GATE, "_version_gate_digits")
    assert gate._semver_tuple(version)[:3] == (6, 1, 0)


#: More digits than `int()` reads from decimal text (4300), a version part the gate compared with `int()`
#: (the sweep of the class a review lens found in the mutant guard, 2026-09-27 at 53676296).
LONG = "1" * 5000


@pytest.mark.parametrize("smaller,larger", [
    ("1" * 4999 + ".0.0", LONG + ".0.0"),
    (LONG + ".0.0", "1" * 4999 + "2.0.0"),
    ("1.0.0.post1", "1.0.0.post" + LONG),
    ("1.0.0a1.dev1000000001", "1.0.0a1"),
    ("1.0.0a1.dev" + LONG, "1.0.0a1"),
], ids=["more-digits", "same-length", "long-post", "dev-past-a-billion", "long-dev"])
def test_a_version_part_past_the_digit_limit_is_compared_by_value(smaller, larger):
    """PEP 440 order, as `packaging` gives it for each pair; `int()` raised on the long ones, and a dev
    number of 10**9 or more sorted after the release it comes before."""
    gate = _load(VERSION_GATE, "_version_gate_long_digits")
    assert gate._semver_tuple(smaller) < gate._semver_tuple(larger)
    assert gate._semver_tuple("6.1.0")[:3] == (6, 1, 0)


def test_a_version_of_5000_digits_ends_in_the_gates_report(tmp_path):
    """Check 3 compares the source version with the last release tag; the version below ended the gate
    with a ValueError traceback there."""
    r = tmp_path / "r"
    r.mkdir()
    (r / "pyproject.toml").write_text(f'[project]\nname = "proofbundle"\nversion = "{LONG}.0.0"\n',
                                      encoding="utf-8")
    _git(r, "init", "-q")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "base")
    _git(r, "tag", "v1.0.0")
    (r / "a.txt").write_text("x\n", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "fix: a commit after the tag")
    out = _run(VERSION_GATE, "--repo", str(r))
    assert "Traceback" not in out.stderr, out.stderr
    assert out.returncode == 1, out.stdout + out.stderr
    assert out.stdout.startswith("check_version_and_changelog: FAIL"), out.stdout
    assert "non-trivial commit(s) since tag" not in out.stdout, "the long version is past the tag"


def test_the_version_gate_names_an_exception_no_branch_names_as_a_problem(monkeypatch):
    """Planted: the gate's code for a problem is 1, as its docstring says, and an exception is one
    problem with its reason instead of a traceback."""
    gate = _load(VERSION_GATE, "_version_gate_unexpected")

    def planted(repo):
        raise ValueError("planted in a check")

    monkeypatch.setattr(gate, "_check", planted)
    problems = gate.check(Path("."))
    assert len(problems) == 1 and "ValueError: planted in a check" in problems[0], problems
    assert gate.NICHT_MESSBAR in problems[0], problems


def test_a_release_tag_with_a_superscript_digit_is_no_crash(tree):
    _git(tree, "tag", "v6.1.0\u00b2")
    (tree / "README.md").write_bytes((tree / "README.md").read_bytes() + b"x\n")
    _git(tree, "commit", "-q", "-am", "fix: a commit after the tag")
    r = _run(VERSION_GATE, "--repo", str(tree))
    assert "Traceback" not in r.stderr, r.stderr
    assert r.returncode == 0, r.stdout + r.stderr


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
