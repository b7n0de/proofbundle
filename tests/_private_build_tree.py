"""A private tree of this checkout for a test that builds the package, or runs what builds it.

Codex thread 4222137675 on pull request 309: with the suite distributed by `--dist=worksteal`, a test that writes into
the shared checkout races the tests other workers run over the same tree. setuptools builds in the source tree, so a
test that builds from the checkout creates `src/proofbundle.egg-info`, `build/` and, for each sdist, a release tree
`proofbundle-<version>/` holding the whole distribution, which it deletes again. Measured over the whole suite with an
inotify watcher, which sees every process: 46 such release trees in one run, from five modules. A reader walking the
tree meanwhile (`scripts/doc_link_check.py` over every `*.md`, for one) meets files that are not the repository's or
a directory that vanishes under its walk, and two of those builds on two workers share one release tree name.

A lock that let a builder run alone was measured too, and dropped: the five modules spend about an hour in their
builds, which a lock turns into serial time. So each builder builds in a tree of its own instead. The tree is a git
worktree of the checkout's repository at the checkout's HEAD, with every tracked file the working tree changed or
deleted and every untracked file git does not ignore laid over it, so it holds what the checkout holds, and the same
repository answers its git questions (HEAD, commits, merge bases). One per process, made when first asked for and
removed when the process ends. A process killed before its exit handler runs, by a timeout say, leaves its tree; the
directory of each tree names its process, and making a tree first removes every tree of this repository whose process
is gone, so such a tree lasts until the next run and no longer. Outside a git checkout, an extracted sdist say, there
is no repository to make one from, and the checkout itself is returned, as before.
"""
from __future__ import annotations

import atexit
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
_BAUM: Path | None = None
#: The directory of a private tree is `<this><pid>_<random>` in the temporary directory, the tree itself `tree` in it.
_PRAEFIX = "pb_private_build_tree_"


def _git(*args: str, ort: Path = REPO) -> bytes:
    return subprocess.run(["git", "-C", str(ort), *args], capture_output=True, check=True, timeout=300).stdout


def _entferne(ort: Path, eltern: Path) -> None:
    subprocess.run(["git", "-C", str(REPO), "worktree", "remove", "--force", str(ort)], capture_output=True,
                   timeout=300)
    shutil.rmtree(eltern, ignore_errors=True)


def _lebt(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:          # a process of another user: alive
        return True
    return True


def _verwaiste_entfernen() -> None:
    """Remove every private tree of this repository, in this temporary directory, whose process is gone."""
    for zeile in _git("worktree", "list", "--porcelain").decode().splitlines():
        if not zeile.startswith("worktree "):
            continue
        ort = Path(zeile[len("worktree "):])
        treffer = re.fullmatch(re.escape(_PRAEFIX) + r"([0-9]+)_\w+", ort.parent.name)
        if (treffer and ort.name == "tree" and ort.parent.parent == Path(tempfile.gettempdir())
                and not _lebt(int(treffer.group(1)))):
            _entferne(ort, ort.parent)


def private_build_tree() -> Path:
    """The private tree of this process, made on first use."""
    global _BAUM
    if _BAUM is not None:
        return _BAUM
    try:
        if Path(_git("rev-parse", "--show-toplevel").decode().strip()).resolve() != REPO:
            raise subprocess.CalledProcessError(1, "git rev-parse")
    except (OSError, subprocess.SubprocessError):
        _BAUM = REPO                        # not a checkout of this repository: nothing to make a worktree from
        return _BAUM
    _verwaiste_entfernen()
    eltern = Path(tempfile.mkdtemp(prefix=f"{_PRAEFIX}{os.getpid()}_"))
    ort = eltern / "tree"
    _git("worktree", "add", "--detach", "--quiet", str(ort), "HEAD")
    atexit.register(_entferne, ort, eltern)
    geaendert = [p for p in _git("diff", "--name-only", "-z", "HEAD").decode().split("\0") if p]
    neu = [p for p in _git("ls-files", "--others", "--exclude-standard", "-z").decode().split("\0") if p]
    for rel in geaendert + neu:
        quelle, ziel = REPO / rel, ort / rel
        if quelle.is_file() or quelle.is_symlink():
            ziel.parent.mkdir(parents=True, exist_ok=True)
            if ziel.exists() or ziel.is_symlink():
                ziel.unlink()
            shutil.copy2(quelle, ziel, follow_symlinks=False)
        elif ziel.exists() or ziel.is_symlink():
            ziel.unlink()                   # deleted in the working tree
    _BAUM = ort
    return _BAUM
