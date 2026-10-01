"""The freeze of the policy-boundary corpus, rounds 1 to 3.

tools/scitt_ccf_external/CORPUS_FREEZE_rounds_1_to_3.sha256 lists every tracked file of the three corpus
directories in sha256sum form, and tools/scitt_ccf_external/check_corpus_freeze.py checks it against a hash
given from outside. These tests hold the check to its contract: it needs the expected hash as an argument and
never falls back to the value in the README, and it fails on a changed file, a missing file, an added tracked
file, a duplicate line and a wrong expected hash. Each failing case is built in a scratch repository with one
planted deviation next to an unchanged control, and the last case runs the command the README prints against
the real tree.
"""
from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
TOOLS = REPO / "tools" / "scitt_ccf_external"
CHECK = TOOLS / "check_corpus_freeze.py"
MANIFEST_REL = "tools/scitt_ccf_external/CORPUS_FREEZE_rounds_1_to_3.sha256"
DIRS = ("differential_corpus", "differential_corpus_round2", "differential_corpus_round3")

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="the freeze check reads git ls-files")


def _git(root: Path, *args: str) -> str:
    out = subprocess.run(["git", "-c", "user.name=freeze-test", "-c", "user.email=freeze-test@example.invalid",
                          "-c", "commit.gpgsign=false", "-C", str(root), *args],
                         capture_output=True, text=True, check=True)
    return out.stdout


def _run(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(root / "tools" / "scitt_ccf_external" / "check_corpus_freeze.py"),
                           *args], cwd=root, capture_output=True, text=True)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def frozen(tmp_path: Path) -> tuple[Path, str]:
    """A scratch repository with three small corpus directories, frozen and committed."""
    root = tmp_path / "repo"
    tools = root / "tools" / "scitt_ccf_external"
    for i, d in enumerate(DIRS):
        for name in ("manifest.json", "vectors/control/request.hex", "vectors/control/record.json"):
            p = tools / d / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(f"{d} {name} {i}\n", encoding="utf-8")
    shutil.copy2(CHECK, tools / "check_corpus_freeze.py")
    _git(root, "init", "-q")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "corpus")
    wrote = _run(root, "--write")
    assert wrote.returncode == 0, wrote.stdout + wrote.stderr
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "freeze")
    return root, _sha256(root / MANIFEST_REL)


@needs_git
def test_the_control_passes(frozen):
    root, expect = frozen
    r = _run(root, "--expect", expect)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "9 files" in r.stdout


@needs_git
def test_without_an_expected_hash_it_fails_and_says_so(frozen):
    # The README carries the RIGHT hash here, so a silent fallback to it would pass and be caught.
    root, expect = frozen
    (root / "tools" / "scitt_ccf_external" / "README.md").write_text(
        "python3 tools/scitt_ccf_external/check_corpus_freeze.py --expect " + expect + "\n", encoding="utf-8")
    r = _run(root)
    assert r.returncode != 0
    assert "expected" in (r.stdout + r.stderr).lower()


@needs_git
def test_a_wrong_expected_hash_fails(frozen):
    root, expect = frozen
    wrong = ("0" if expect[0] != "0" else "1") + expect[1:]
    r = _run(root, "--expect", wrong)
    assert r.returncode != 0
    assert "manifest" in r.stdout.lower()


@needs_git
def test_a_changed_corpus_file_fails(frozen):
    root, expect = frozen
    p = root / "tools" / "scitt_ccf_external" / "differential_corpus_round2" / "vectors" / "control" / "request.hex"
    p.write_text(p.read_text(encoding="utf-8") + "00\n", encoding="utf-8")
    r = _run(root, "--expect", expect)
    assert r.returncode != 0
    assert "differential_corpus_round2/vectors/control/request.hex" in r.stdout


@needs_git
def test_a_missing_corpus_file_fails(frozen):
    root, expect = frozen
    (root / "tools" / "scitt_ccf_external" / "differential_corpus_round3" / "manifest.json").unlink()
    r = _run(root, "--expect", expect)
    assert r.returncode != 0
    assert "differential_corpus_round3/manifest.json" in r.stdout


@needs_git
def test_an_added_tracked_corpus_file_fails(frozen):
    root, expect = frozen
    p = root / "tools" / "scitt_ccf_external" / "differential_corpus" / "vectors" / "extra" / "request.hex"
    p.parent.mkdir(parents=True)
    p.write_text("d2\n", encoding="utf-8")
    _git(root, "add", str(p))
    r = _run(root, "--expect", expect)
    assert r.returncode != 0
    assert "differential_corpus/vectors/extra/request.hex" in r.stdout


@needs_git
def test_a_duplicate_line_fails_even_with_the_matching_hash(frozen):
    root, _ = frozen
    m = root / MANIFEST_REL
    lines = m.read_text(encoding="utf-8").splitlines(keepends=True)
    m.write_text("".join(lines[:1] + lines), encoding="utf-8")
    r = _run(root, "--expect", _sha256(m))
    assert r.returncode != 0
    assert "duplicate" in r.stdout.lower()


@needs_git
def test_a_malformed_line_fails(frozen):
    root, _ = frozen
    m = root / MANIFEST_REL
    m.write_text(m.read_text(encoding="utf-8").replace("  ", " ", 1), encoding="utf-8")
    r = _run(root, "--expect", _sha256(m))
    assert r.returncode != 0
    assert "line 1" in r.stdout


@needs_git
def test_the_command_in_the_readme_passes_on_the_real_tree():
    readme = (TOOLS / "README.md").read_text(encoding="utf-8")
    found = re.findall(r"python3 tools/scitt_ccf_external/check_corpus_freeze\.py --expect ([0-9a-f]{64})", readme)
    assert len(set(found)) == 1, found
    assert found[0] == _sha256(REPO / MANIFEST_REL)
    r = _run(REPO, "--expect", found[0])
    assert r.returncode == 0, r.stdout + r.stderr
    tracked = _git(REPO, "ls-files", "-z", "--", *(f"tools/scitt_ccf_external/{d}" for d in DIRS)).split("\0")
    n = len([t for t in tracked if t])
    assert f"{n} files" in r.stdout
    assert len((REPO / MANIFEST_REL).read_text(encoding="utf-8").splitlines()) == n
