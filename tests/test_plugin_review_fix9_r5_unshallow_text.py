"""Review round 9 of 2026-10-11, R9-5: DECISIONS.md D3 no longer says `git fetch --unshallow` removes both restrictions.

Measured by the reviewer at b288ee66 with git 2.43.0 and 2.51.1: after `git fetch --unshallow` the single-branch rule
+refs/heads/main:refs/remotes/origin/main stays. The sentence is replaced by the reviewer's wording, verbatim.
"""
from __future__ import annotations

import pathlib
import shutil
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
DECISIONS = ROOT / "plugins" / "proofbundle" / "DECISIONS.md"
NEW = ("A full clone with a pattern fetch rule avoids both restrictions. git fetch --unshallow removes the "
       "shallow-history restriction but leaves the fetch rules unchanged.")
OLD = "or `git fetch --unshallow`, leaves both conditions behind"


def _flat(text: str) -> str:
    return " ".join(text.split())


def test_decisions_d3_carries_the_replacement_verbatim_and_not_the_old_claim():
    text = _flat(DECISIONS.read_text(encoding="utf-8"))
    assert NEW in text
    assert OLD not in text


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
def test_git_fetch_unshallow_leaves_the_single_branch_rule(tmp_path):
    """Non-vacuous: the measurement the replacement rests on."""
    env = {"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1", "PATH": __import__("os").environ["PATH"]}
    source = tmp_path / "source"
    subprocess.run(["git", "init", "-q", "-b", "main", str(source)], check=True, env=env)
    for n in range(3):
        (source / "f.txt").write_text(f"{n}\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(source), "add", "-A"], check=True, env=env)
        subprocess.run(["git", "-C", str(source), "-c", "user.name=t", "-c", "user.email=t@example.org", "commit",
                        "-q", "-m", str(n)], check=True, env=env)
    clone = tmp_path / "clone"
    subprocess.run(["git", "clone", "-q", "--depth", "1", f"file://{source}", str(clone)], check=True, env=env)
    subprocess.run(["git", "-C", str(clone), "fetch", "-q", "--unshallow"], check=True, env=env)
    rules = subprocess.run(["git", "-C", str(clone), "config", "--get-all", "remote.origin.fetch"], capture_output=True,
                           text=True, check=True, env=env).stdout.split()
    shallow = subprocess.run(["git", "-C", str(clone), "rev-parse", "--is-shallow-repository"], capture_output=True,
                             text=True, check=True, env=env).stdout.strip()
    assert rules == ["+refs/heads/main:refs/remotes/origin/main"] and shallow == "false"
