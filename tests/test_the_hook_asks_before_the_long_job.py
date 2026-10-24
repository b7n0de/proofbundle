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
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
HOOK = REPO / "scripts" / "git-hooks" / "pre-commit"


def _python3_shim(bin_: pathlib.Path) -> None:
    """`python3` on the hook's PATH is the interpreter that runs this test, which has pytest.

    THE HOOK ASKS ITS OWN `python3` (witness run on 78a702bb, 2026-10-24): on a runner whose `python3`
    finds no pytest, the hook skipped the node for that reason, and five cases read the skip as wiring
    that never calls it. `pytest.importorskip` asked the test's interpreter, not the hook's. The cases
    measure the wiring, so the interpreter is named here instead of taken from the machine."""
    shim = bin_ / "python3"
    shim.write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n', encoding="utf-8")
    shim.chmod(0o755)


def _fill(root: pathlib.Path, mark: pathlib.Path, node_fails: bool, manifest: str) -> None:
    (root / "scripts").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "scripts" / "mutant_signature_guard.py").write_text(
        "import sys\nsys.exit(0)\n", encoding="utf-8")
    (root / "MANIFEST.in").write_text(manifest, encoding="utf-8")
    # The planted node reads MANIFEST.in next to its own tests/ folder, as the real node does
    # (REPO = Path(__file__).resolve().parents[1]), so it judges whichever tree it is run from.
    (root / "tests" / "test_sdist_ohne_signierwerkzeug.py").write_text(
        "import pathlib\n"
        "def test_jede_datei_unter_scripts_ist_in_manifest_entschieden():\n"
        f"    pathlib.Path({str(mark)!r}).write_text('yes')\n"
        f"    assert not {node_fails!r}, 'planted failure'\n"
        "    text = (pathlib.Path(__file__).resolve().parents[1] / 'MANIFEST.in').read_text()\n"
        "    assert 'undecided' not in text, 'planted: this tree carries no decision'\n",
        encoding="utf-8")


def _build_tree(tmp_path: pathlib.Path, staged: list[str], node_fails: bool = False,
                deleted: tuple[str, ...] = (), staged_manifest: str = "decided\n",
                working_manifest: str = "decided\n"):
    """A tree that matches the hook exactly as far as the hook touches it, with a separate INDEX.

    The fake `git` keeps the two apart the way git does: `diff --cached` lists what is staged,
    honouring `--diff-filter` for the paths staged as deletions, and `checkout-index --all --prefix=`
    writes the staged snapshot, not the working tree.
    """
    root = tmp_path / "tree"
    index = tmp_path / "index"
    mark = tmp_path / "node_ran"
    _fill(root, mark, node_fails, working_manifest)
    _fill(index, mark, node_fails, staged_manifest)

    bin_ = tmp_path / "bin"
    bin_.mkdir()
    alle = "\\n".join([*staged, *deleted])
    ohne_d = "\\n".join(staged)
    (bin_ / "git").write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "rev-parse" ]; then printf "%s\\n" ' + f"'{root}'" + "; exit 0; fi\n"
        'if [ "$1" = "diff" ]; then\n'
        '  case "$*" in *--diff-filter=*) printf "' + ohne_d + '\\n" ;; *) printf "' + alle + '\\n" ;; esac\n'
        "  exit 0\n"
        "fi\n"
        'if [ "$1" = "checkout-index" ]; then\n'
        '  for a in "$@"; do case "$a" in --prefix=*) cp -R ' + f"'{index}'" + '/. "${a#--prefix=}" ;; esac; done\n'
        "  exit 0\n"
        "fi\n"
        "exit 0\n", encoding="utf-8")
    (bin_ / "git").chmod(0o755)
    _python3_shim(bin_)
    return root, bin_, mark


def _run(tmp_path, staged, node_fails=False, **tree):
    root, bin_, mark = _build_tree(tmp_path, staged, node_fails, **tree)
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


def test_a_deleted_file_under_scripts_triggers_the_node(tmp_path):
    """Codex on pull request 368, round one, P2: the staged-set filter `--diff-filter=ACMR` left out
    deletions, so a script deleted while MANIFEST.in still listed it never reached the node, which
    refuses exactly that stale line."""
    pytest.importorskip("pytest")
    p, mark = _run(tmp_path, ["README.md"], deleted=("scripts/b7_alt.py",))
    assert mark.is_file(), (
        f"a staged deletion under scripts/ did not start the node.\nstdout: {p.stdout}\nstderr: {p.stderr}")
    assert p.returncode == 0, p.stderr


def test_the_node_judges_the_staged_snapshot_not_the_working_tree(tmp_path):
    """Codex on pull request 368, round one, P2: the node ran on the files on disk. With the decision
    only in the working tree and not staged, the hook passed a commit that CI then refused; the
    reverse rejected a correct staged snapshot because of a stale working tree."""
    pytest.importorskip("pytest")
    p, mark = _run(tmp_path, ["scripts/b7_neu.py"], staged_manifest="undecided\n",
                   working_manifest="decided\n")
    assert mark.is_file(), "the node did not run, so this case checks nothing"
    assert p.returncode != 0, (
        "the staged MANIFEST.in carries no decision, the hook still passed because it read the working "
        f"tree.\nstdout: {p.stdout}")


def test_a_correct_staged_snapshot_passes_beside_a_stale_working_tree(tmp_path):
    """The reverse direction of the same finding, and the counter-direction of the case above."""
    pytest.importorskip("pytest")
    p, mark = _run(tmp_path, ["scripts/b7_neu.py"], staged_manifest="decided\n",
                   working_manifest="undecided\n")
    assert mark.is_file(), "the node did not run, so this case checks nothing"
    assert p.returncode == 0, f"a correct staged snapshot was refused.\nstdout: {p.stdout}\nstderr: {p.stderr}"


def _real_repo(tmp_path: pathlib.Path) -> tuple[pathlib.Path, dict, pathlib.Path]:
    """A real git repository with the hook's inputs committed, so the staged set comes from git itself.

    The fake `git` above cannot show what the counter-reading of pull request 368 found (F1, F2): how
    git LISTS a rename and a path outside ASCII. Here git does, with no global or system configuration."""
    root = tmp_path / "real"
    mark = tmp_path / "node_ran"
    _fill(root, mark, False, "decided\n")
    (root / "scripts" / "b7_alt.py").write_text("print('old')\n", encoding="utf-8")
    # The hook's `python3` is this test's interpreter (see `_python3_shim`); git stays the real one.
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    _python3_shim(bin_)
    env = dict(os.environ, PATH=f"{bin_}{os.pathsep}{os.environ['PATH']}",
               GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull,
               GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")
    for args in (["init", "-q", "-b", "main"], ["add", "-A"], ["commit", "-q", "-m", "base"]):
        subprocess.run(["git", *args], cwd=root, env=env, check=True, capture_output=True, timeout=60)
    return root, env, mark


def _run_real(root: pathlib.Path, env: dict):
    return subprocess.run(["sh", str(HOOK)], cwd=root, env=env, capture_output=True, text=True, timeout=300)


def test_a_script_moved_out_of_scripts_triggers_the_node(tmp_path):
    """Counter-reading of pull request 368, F1 (P2): `git diff --cached --name-only` lists a rename
    under its new path only, so `git mv scripts/x.py tools/x.py` never reached the node, which refuses
    the stale `include scripts/x.py` that move leaves behind."""
    pytest.importorskip("pytest")
    root, env, mark = _real_repo(tmp_path)
    (root / "tools").mkdir()
    subprocess.run(["git", "mv", "scripts/b7_alt.py", "tools/b7_alt.py"], cwd=root, env=env, check=True,
                   capture_output=True, timeout=60)
    p = _run_real(root, env)
    assert mark.is_file(), (
        f"a script moved out of scripts/ did not start the node.\nstdout: {p.stdout}\nstderr: {p.stderr}")
    assert p.returncode == 0, p.stderr


def test_a_path_outside_ascii_under_scripts_triggers_the_node(tmp_path):
    """Counter-reading of pull request 368, F2 (P3): git lists a path with a byte outside ASCII in
    quotes, `"scripts/gr\\303\\266..."`, which no longer starts with `scripts/`."""
    pytest.importorskip("pytest")
    root, env, mark = _real_repo(tmp_path)
    (root / "scripts" / "größe.py").write_text("print('new')\n", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=root, env=env, check=True, capture_output=True, timeout=60)
    p = _run_real(root, env)
    assert mark.is_file(), (
        f"a staged path outside ASCII under scripts/ did not start the node.\nstdout: {p.stdout}\nstderr: {p.stderr}")
    assert p.returncode == 0, p.stderr


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
