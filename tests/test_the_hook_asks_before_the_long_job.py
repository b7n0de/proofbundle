"""The pre-commit hook calls the MANIFEST node, and only when scripts/ is touched.

WHY THIS FILE EXISTS, measured and not assumed. On 2026-09-13 THREE branches failed
``test_jede_datei_unter_scripts_ist_in_manifest_entschieden``: PR 200 with
``b7_paketinhalt_ohne_schluesselmaterial.py`` (1 failed / 4024 passed in 21:45 min), PR 198 with
``b7_historie.py`` (1 failed / 4158 passed in 26:08 min) and ``feat/pr-language-gate`` with
``pr_language_gate.py``, the last one found by a neighbour sweep BEFORE it cost CI time. Nine jobs
of 22 to 42 minutes each, to learn ONE line each.

The guard was never wrong. Its PLACE was: it sat at the end of the most thorough job, while its
whole input stands in the working tree. The latency of a guard belongs to its effect.

WHAT IS CHECKED HERE, and why it is not the node itself: that the HOOK CALLS it, and only then.
The node has its own contract; this one measures the WIRING. The real hook script runs against a
built tree with a fake ``git`` on PATH, so the staged set is an input and not an assumption.
"""
from __future__ import annotations

import os
import pathlib
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
HOOK = REPO / "scripts" / "git-hooks" / "pre-commit"


def _build_tree(tmp_path: pathlib.Path, staged: list[str], node_fails: bool = False):
    """A tree that matches the hook exactly as far as the hook touches it."""
    root = tmp_path / "tree"
    (root / "scripts").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "scripts" / "mutant_signature_guard.py").write_text(
        "import sys\nsys.exit(0)\n", encoding="utf-8")
    mark = root / "node_ran"
    (root / "tests" / "test_sdist_ohne_signierwerkzeug.py").write_text(
        "import pathlib\n"
        "def test_jede_datei_unter_scripts_ist_in_manifest_entschieden():\n"
        f"    pathlib.Path({str(mark)!r}).write_text('yes')\n"
        f"    assert not {node_fails!r}, 'planted failure'\n",
        encoding="utf-8")

    bin_ = tmp_path / "bin"
    bin_.mkdir()
    listing = "\\n".join(staged)
    (bin_ / "git").write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "rev-parse" ]; then printf "%s\\n" ' + f"'{root}'" + "; exit 0; fi\n"
        'if [ "$1" = "diff" ]; then printf "' + listing + '\\n"; exit 0; fi\n'
        "exit 0\n", encoding="utf-8")
    (bin_ / "git").chmod(0o755)
    return root, bin_, mark


def _run(tmp_path, staged, node_fails=False):
    root, bin_, mark = _build_tree(tmp_path, staged, node_fails)
    env = dict(os.environ, PATH=f"{bin_}{os.pathsep}{os.environ['PATH']}")
    p = subprocess.run(["sh", str(HOOK)], cwd=root, env=env,
                       capture_output=True, text=True, timeout=300)
    return p, mark


def test_a_file_under_scripts_triggers_the_node(tmp_path):
    pytest.importorskip("pytest")
    p, mark = _run(tmp_path, ["scripts/b7_neu.py", "README.md"])
    assert mark.is_file(), (
        "the hook did NOT call the MANIFEST node although a file under scripts/ was staged, so the "
        f"author learns the one-line fact after 26 minutes again.\nstdout: {p.stdout}\nstderr: {p.stderr}")
    assert p.returncode == 0, p.stderr


def test_a_change_outside_scripts_does_not_start_it_at_all(tmp_path):
    """The other direction, and it is not cosmetic: if the node ran on EVERY commit, the hook would
    cost each change the pytest start-up time, and an expensive hook gets switched off."""
    p, mark = _run(tmp_path, ["docs/something.md", "README.md"])
    assert not mark.exists(), (
        "the hook starts the node without any relation to scripts/, which makes every commit dearer")
    assert p.returncode == 0, p.stderr


def test_when_the_node_fails_the_hook_fails(tmp_path):
    """The catch proof that counts: green wiring that swallows the failure is worse than none,
    because it looks like a check."""
    pytest.importorskip("pytest")
    p, mark = _run(tmp_path, ["scripts/b7_neu.py"], node_fails=True)
    assert mark.is_file(), "the node did not run, so this case checks nothing"
    assert p.returncode != 0, (
        f"the node failed and the hook still reports success.\nstdout: {p.stdout}")


def test_the_hook_calls_exactly_the_node_that_ci_runs():
    """No second producer (OA-714de2fcdd): the hook must not REBUILD the question, it must call the
    same node. Measured on the hook's text AND on the existence of the node."""
    text = HOOK.read_text(encoding="utf-8")
    node = ("tests/test_sdist_ohne_signierwerkzeug.py::"
            "test_jede_datei_unter_scripts_ist_in_manifest_entschieden")
    assert node in text, "the hook does not name the shared node"
    target = REPO / "tests" / "test_sdist_ohne_signierwerkzeug.py"
    assert target.is_file(), f"{target} does not exist, so the hook points nowhere"
    assert "def test_jede_datei_unter_scripts_ist_in_manifest_entschieden" in target.read_text(
        encoding="utf-8"), "the named node no longer exists in that file"
