"""The version gate reads every file within a bound, every git answer without losing a byte, and prints
every path on one line with one reading.

A review of the stack at 1ecc2aca, measured 2026-09-26 at 1ecc2aca and at main 727d161f (the first
case at 1ecc2aca only, where tracked names are read as git names them): a tracked file named with a
newline split one problem into two printed items, one blaming README.md; one byte that is not UTF-8
in CHANGELOG.md ended the gate with a traceback; a FIFO at a tracked path hung it; a 12 GB sparse file
at a tracked path ended it with a MemoryError under an address-space limit; and a commit subject
carrying such a byte emptied the log Check 3 reads, so it said OK with exit 0.

Each case runs the real gate over this repository's own tree, exported with `git archive` into a
fresh repository, with one change made there.
"""
from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "check_version_and_changelog.py"


def _git(repo: Path, *args: str, **kw) -> bytes:
    return subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", *args],
                          capture_output=True, check=True, **kw).stdout


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


def _gate(t: Path, preexec_fn=None) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-B", str(GATE), "--repo", str(t)], capture_output=True,
                          text=True, timeout=120, preexec_fn=preexec_fn)


def test_control_the_exported_tree_passes(tree):
    r = _gate(tree)
    assert r.returncode == 0, r.stdout + r.stderr


def test_a_path_with_a_newline_is_printed_on_one_line(tree):
    name = "docs/z\n  - README.md:1: fake finding.md"
    (tree / name).write_text(f"current release: {_version(tree)}\n", encoding="utf-8")
    _git(tree, "add", "-A")
    _git(tree, "commit", "-q", "-m", "a name with a newline")
    r = _gate(tree)
    assert r.returncode == 1, r.stdout + r.stderr
    items = [line for line in r.stdout.splitlines() if line.startswith("  - ")]
    assert len(items) == 1, r.stdout
    assert items[0].startswith('  - "docs/z\\n  - README.md:1: fake finding.md":1: states a current'), items


def test_a_byte_that_is_not_utf8_in_the_changelog_is_a_problem_naming_it(tree):
    with (tree / "CHANGELOG.md").open("ab") as fh:
        fh.write(b"\xfc\n")
    r = _gate(tree)
    assert "Traceback" not in r.stderr, r.stderr
    assert r.returncode == 1, r.stdout + r.stderr
    assert "CHANGELOG.md is not UTF-8 text (byte 0xfc" in r.stdout, r.stdout


def test_a_fifo_at_a_tracked_path_is_not_opened(tree):
    target = tree / "docs" / "GLOSSARY.md"
    target.unlink()
    try:
        os.mkfifo(target)
    except (AttributeError, OSError) as exc:
        pytest.skip(f"no FIFO here: {exc}")
    r = _gate(tree)                       # a hang ends in TimeoutExpired, which fails the case
    assert r.returncode == 0, r.stdout + r.stderr


def test_a_sparse_file_of_12_gb_is_not_read_under_an_address_space_limit(tree):
    resource = pytest.importorskip("resource")
    if not sys.platform.startswith("linux"):
        pytest.skip("RLIMIT_AS is measured on Linux here")
    target = tree / "docs" / "GLOSSARY.md"
    try:
        os.truncate(target, 12 * 1024 ** 3)
    except OSError as exc:
        pytest.skip(f"this file system refuses a sparse file of 12 GB: {exc}")

    def _bounded():
        resource.setrlimit(resource.RLIMIT_AS, (8_000_000 * 1024, 8_000_000 * 1024))

    r = _gate(tree, preexec_fn=_bounded)
    assert "MemoryError" not in r.stderr, r.stderr
    assert r.returncode == 1, r.stdout + r.stderr
    assert "docs/GLOSSARY.md is 12884901888 bytes, more than the" in r.stdout, r.stdout


def test_a_commit_subject_that_is_not_utf8_is_still_counted(tree):
    """`git commit` would store such a subject as UTF-8; git fast-import and `hash-object` do not."""
    changelog = tree / "CHANGELOG.md"
    changelog.write_bytes(re.sub(rb"(?m)^## \[Unreleased\]\n", b"", changelog.read_bytes()))
    _git(tree, "commit", "-q", "-am", "chore: no unreleased section")
    _git(tree, "tag", "v" + _version(tree))
    (tree / "README.md").write_bytes((tree / "README.md").read_bytes() + b"x\n")
    _git(tree, "add", "-A")
    commit = (b"tree " + _git(tree, "write-tree").strip() + b"\nparent " + _git(tree, "rev-parse", "HEAD").strip()
              + b"\nauthor t <t@t> 1790000000 +0000\ncommitter t <t@t> 1790000000 +0000\n\nfix: caf\xfc\n")
    sha = _git(tree, "hash-object", "-t", "commit", "-w", "--literally", "--stdin", input=commit).strip()
    _git(tree, "update-ref", "HEAD", sha.decode())
    r = _gate(tree)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "1 non-trivial commit(s) since tag" in r.stdout, r.stdout


def test_a_log_that_cannot_be_read_is_not_an_empty_log(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("_version_gate_bounds", GATE)
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    monkeypatch.setattr(gate, "_last_release_tag", lambda repo: ("v1.0.0", ""))
    monkeypatch.setattr(gate, "_git", lambda repo, *args: (128, "fatal: bad revision"))
    problems = gate.check(ROOT)
    assert any("post-tag drift is NICHT MESSBAR: fatal: bad revision" in p for p in problems), problems
