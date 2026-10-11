"""Build the toy repository the example pull request points at, byte-for-byte reproducibly.

Fixed author, committer, dates and contents, and no user or system git configuration, so the two
commit ids are the same on every machine. The diff digest is the one docs/AGENT_REVIEW_PREDICATE.md
defines for `reviewedDiffDigest`: sha256 over the raw diff-tree record, not over a rendered patch.
"""
import hashlib
import os
import subprocess
import sys
from pathlib import Path

_ENV = {
    "GIT_AUTHOR_NAME": "Example Author", "GIT_AUTHOR_EMAIL": "author@example.invalid",
    "GIT_AUTHOR_DATE": "2026-10-11T00:00:00+0000",
    "GIT_COMMITTER_NAME": "Example Author", "GIT_COMMITTER_EMAIL": "author@example.invalid",
    "GIT_COMMITTER_DATE": "2026-10-11T00:00:00+0000",
    "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
    "LC_ALL": "C",
}

BASE_FILE = b"def add(a, b):\n    return a + b\n"
HEAD_FILE = BASE_FILE + b"\n\ndef sub(a, b):\n    return a - b\n"


def _git(repo: Path, *args: str) -> bytes:
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), **_ENV}
    return subprocess.run(["git", "-C", str(repo), *args], env=env, check=True,
                          capture_output=True).stdout


def build(repo: Path) -> dict:
    """Create the repository if it is absent and return its two commit ids and the diff digest."""
    if not (repo / ".git").exists():
        repo.mkdir(parents=True, exist_ok=True)
        _git(repo, "init", "-q", "-b", "main")
        (repo / "calc.py").write_bytes(BASE_FILE)
        _git(repo, "add", "calc.py")
        _git(repo, "commit", "-q", "-m", "base")
        (repo / "calc.py").write_bytes(HEAD_FILE)
        _git(repo, "commit", "-q", "-am", "add sub")
    head = _git(repo, "rev-parse", "HEAD").decode().strip()
    base = _git(repo, "rev-parse", "HEAD~1").decode().strip()
    return {"baseSha": base, "headSha": head, "reviewedDiffDigest": diff_digest(repo, base, head)}


def diff_digest(repo: Path, base: str, head: str) -> str:
    raw = _git(repo, "--no-replace-objects", "diff-tree", "-r", "-z", "--no-renames",
               "--no-abbrev", "-O/dev/null", base, head)
    return hashlib.sha256(raw).hexdigest()


if __name__ == "__main__":
    print(build(Path(sys.argv[1] if len(sys.argv) > 1 else "toyrepo")))
