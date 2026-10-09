"""A test that builds the package builds in a private tree, and the checkout other workers read stays as it is.

Codex thread 4222137675 on pull request 309, and the class it names: under `--dist=worksteal` a test that writes into
the shared checkout races the tests other workers run over it. Measured over the whole suite with an inotify watcher,
which sees the writes of every process, and with a recorder of the writes inside the test processes: once the
half-provenance case works on a private root and the English-gate cases write their probes outside the checkout, no
tracked file is written; what remained were the package builds of five modules, each creating a release tree of the
whole distribution in the checkout and deleting it again. Those modules build in `tests/_private_build_tree.py` now.

These cases hold that tree to the checkout and a real build in it to the checkout's state. That the five modules are
the builders is the measurement's result, not a rule over their source; the last case pins that each of them builds
in the private tree, so a revert shows, and a new builder is found by measuring again.
"""
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tests"))
import _private_build_tree  # noqa: E402

#: The modules the measurement of 2026-10-08 found building the package in the checkout.
MEASURED_BUILDERS = ("test_audit_candidate_360.py", "test_audit_matrix_version_pin_binding.py",
                     "test_ausfuehrung_aus_quelltext_l5_g7_04.py", "test_byte_freeze_zweite_haelfte.py",
                     "test_c12_1_nicht_anwendbar_vor_dem_tag.py")

#: What runs leave in a checkout by design and no test reads as the repository: caches and the Rust build directory.
_CACHES = {".git", ".hypothesis", "__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache"}


def _in_einem_checkout() -> bool:
    try:
        oben = subprocess.run(["git", "-C", str(REPO), "rev-parse", "--show-toplevel"], capture_output=True,
                              text=True, timeout=30)
    except OSError:
        return False
    return oben.returncode == 0 and Path(oben.stdout.strip()).resolve() == REPO


pytestmark = pytest.mark.skipif(not _in_einem_checkout(), reason="the private tree is a worktree of a git checkout")


def _git(ort: Path, *args: str) -> bytes:
    return subprocess.run(["git", "-C", str(ort), *args], capture_output=True, check=True, timeout=300).stdout


def _bestand(wurzel: Path) -> set[str]:
    """Every path under `wurzel`, caches and the Rust build directory left out."""
    gefunden = set()
    for ort, ordner, dateien in os.walk(wurzel):
        rel = Path(ort).relative_to(wurzel)
        ordner[:] = [d for d in ordner if d not in _CACHES and (rel / d).as_posix() != "tools/pb_verify_rs/target"]
        gefunden |= {(rel / n).as_posix() for n in ordner + dateien}
    return gefunden


def test_the_private_tree_holds_what_the_checkout_holds() -> None:
    baum = _private_build_tree.private_build_tree()
    assert baum.resolve() != REPO, "control: in a checkout the tree is not the checkout itself"
    getrackt = [p for p in _git(REPO, "ls-files", "-z").decode().split("\0") if p]
    neu = [p for p in _git(REPO, "ls-files", "--others", "--exclude-standard", "-z").decode().split("\0") if p]
    assert getrackt, "control: the checkout lists its files"
    anders = []
    for rel in getrackt + neu:
        quelle, ziel = REPO / rel, baum / rel
        if quelle.is_symlink() or ziel.is_symlink():
            if os.readlink(quelle) != os.readlink(ziel):
                anders.append(rel)
        elif quelle.is_file() != ziel.is_file() or (quelle.is_file() and quelle.read_bytes() != ziel.read_bytes()):
            anders.append(rel)
    assert not anders, anders[:10]


def test_git_answers_in_it_as_in_the_checkout() -> None:
    baum = _private_build_tree.private_build_tree()
    assert _git(baum, "rev-parse", "HEAD") == _git(REPO, "rev-parse", "HEAD")
    assert Path(_git(baum, "rev-parse", "--show-toplevel").decode().strip()).resolve() == baum.resolve()


@pytest.mark.skipif(importlib.util.find_spec("build") is None, reason="the `build` frontend is not installed here")
def test_a_build_in_it_leaves_the_checkout_as_it_was(tmp_path) -> None:
    baum = _private_build_tree.private_build_tree()
    vorher = _bestand(REPO)
    # built as scripts/build_reproducible.py builds by default, in an isolated environment like release.yml
    lauf = subprocess.run([sys.executable, "-m", "build", "--sdist", "--outdir", str(tmp_path)],
                          cwd=str(baum), capture_output=True, text=True, timeout=900)
    assert lauf.returncode == 0, lauf.stderr[-800:]
    assert list(tmp_path.glob("*.tar.gz")), "control: the build produced an sdist"
    assert (baum / "src" / "proofbundle.egg-info").is_dir(), "control: setuptools wrote its build into the tree it built"
    nachher = _bestand(REPO)
    assert nachher == vorher, {"new": sorted(nachher - vorher)[:10], "gone": sorted(vorher - nachher)[:10]}


def test_a_tree_whose_process_is_gone_is_removed_by_the_next_one(tmp_path, monkeypatch) -> None:
    """A process killed before its exit handler ran leaves its tree, measured on 2026-10-08 when a timeout ended a run.
    The next process that makes a tree removes it, and leaves the tree of a process that is alive."""
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    beendet = subprocess.Popen([sys.executable, "-c", "pass"])
    beendet.wait()
    baeume = {}
    try:
        for name, pid in (("gone", beendet.pid), ("alive", os.getpid())):
            baeume[name] = tmp_path / f"{_private_build_tree._PRAEFIX}{pid}_{name}"
            baeume[name].mkdir()
            _git(REPO, "worktree", "add", "--detach", "--quiet", str(baeume[name] / "tree"), "HEAD")
        _private_build_tree._verwaiste_entfernen()
        eingetragen = _git(REPO, "worktree", "list", "--porcelain").decode()
        assert str(baeume["gone"] / "tree") not in eingetragen and not baeume["gone"].exists()
        assert str(baeume["alive"] / "tree") in eingetragen, "control: the tree of a live process stays"
    finally:
        for eltern in baeume.values():
            subprocess.run(["git", "-C", str(REPO), "worktree", "remove", "--force", str(eltern / "tree")],
                           capture_output=True, timeout=300)


def test_outside_a_checkout_the_tree_itself_is_used(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(_private_build_tree, "REPO", tmp_path)
    monkeypatch.setattr(_private_build_tree, "_BAUM", None)
    assert _private_build_tree.private_build_tree() == tmp_path


def test_every_measured_builder_builds_in_the_private_tree() -> None:
    for name in MEASURED_BUILDERS:
        quelle = (REPO / "tests" / name).read_text(encoding="utf-8")
        assert "private_build_tree()" in quelle, f"{name} no longer builds in the private tree"
