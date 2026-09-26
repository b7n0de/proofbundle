"""The version gate reads `__version__` as Python reads `src/proofbundle/__init__.py`, and a source that
states no version is no agreement.

The sweep of the class a review lens, run 10 at 50f3ef33 (2026-09-26), found in the language gate
("read a `.py` file as Python reads it") reached the version gate: it read `__version__` with a pattern
over the file's UTF-8 text and took the first match, and a source that stated no version it could
read counted as agreeing. Each of these said OK with exit 0 at 50f3ef33 while
`import proofbundle; proofbundle.__version__` gave `9.9.9` against the `6.1.0` of the other sources,
or while the file stated nothing the gate could read:

- a lone CR before a second binding, `x = 1<CR>__version__ = "9.9.9"`: one line to the pattern, two
  statements to Python, which keeps the last;
- the file under `# coding: utf-7`, where `+AAo-` is a line end, holding the same second binding;
- an annotated binding `__version__: str = "9.9.9"`, which the pattern does not read;
- `from ._v import __version__`, a binding no pattern can evaluate.

Each case runs the real gate over this repository's own tree, exported with `git archive` into a
fresh repository, with one change made there.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "check_version_and_changelog.py"
INIT = "src/proofbundle/__init__.py"


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", *args],
                   capture_output=True, check=True)


@pytest.fixture()
def tree(tmp_path):
    archive = subprocess.run(["git", "-C", str(ROOT), "archive", "HEAD"], capture_output=True)
    if archive.returncode != 0:
        pytest.skip("NOT MEASURABLE here: this tree is not a git checkout")
    t = tmp_path / "tree"
    t.mkdir()
    subprocess.run(["tar", "-x", "-C", str(t)], input=archive.stdout, check=True)
    return t


def _gate(t: Path) -> subprocess.CompletedProcess:
    _git(t, "init", "-q")
    _git(t, "add", "-A")
    _git(t, "commit", "-q", "-m", "the tree")
    return subprocess.run([sys.executable, "-B", str(GATE), "--repo", str(t)], capture_output=True,
                          text=True, timeout=120)


def _python_reads(t: Path) -> str:
    return subprocess.run([sys.executable, "-B", "-c", "import proofbundle; print(proofbundle.__version__)"],
                          cwd=str(t), env={"PYTHONPATH": str(t / "src"), "PATH": "/usr/bin:/bin"},
                          capture_output=True, text=True, check=True).stdout.strip()


def _version(t: Path) -> str:
    return re.search(r'(?m)^version = "([^"]+)"', (t / "pyproject.toml").read_text(encoding="utf-8")).group(1)


def test_control_the_exported_tree_passes(tree):
    r = _gate(tree)
    assert r.returncode == 0, r.stdout + r.stderr


def test_a_second_binding_behind_a_lone_cr_is_seen(tree):
    with (tree / INIT).open("ab") as fh:
        fh.write(b'x = 1\r__version__ = "9.9.9"\n')
    assert _python_reads(tree) == "9.9.9"
    r = _gate(tree)
    assert r.returncode == 1, r.stdout + r.stderr
    assert f"{INIT} binds `__version__` to more than one value" in r.stdout, r.stdout


def test_a_second_binding_under_a_utf7_cookie_is_seen(tree):
    text = (tree / INIT).read_text(encoding="utf-8")
    (tree / INIT).write_bytes(b"# coding: utf-7\n" + text.encode("utf-7")
                              + b"x = 1 +AAo-__version__ = +ACI-9.9.9+ACI-\n")
    assert _python_reads(tree) == "9.9.9"
    r = _gate(tree)
    assert r.returncode == 1, r.stdout + r.stderr
    assert f"{INIT} binds `__version__` to more than one value" in r.stdout, r.stdout


def test_an_annotated_binding_is_read(tree):
    version = _version(tree)
    text = (tree / INIT).read_text(encoding="utf-8")
    (tree / INIT).write_text(text.replace(f'__version__ = "{version}"', '__version__: str = "9.9.9"'),
                             encoding="utf-8")
    assert _python_reads(tree) == "9.9.9"
    r = _gate(tree)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "version disagreement across sources" in r.stdout and "'__init__': '9.9.9'" in r.stdout, r.stdout


def test_a_binding_no_pattern_evaluates_is_not_measurable(tree):
    version = _version(tree)
    text = (tree / INIT).read_text(encoding="utf-8")
    (tree / INIT).write_text(text.replace(f'__version__ = "{version}"', "from ._v import __version__"),
                             encoding="utf-8")
    (tree / "src" / "proofbundle" / "_v.py").write_text('__version__ = "9.9.9"\n', encoding="utf-8")
    assert _python_reads(tree) == "9.9.9"
    r = _gate(tree)
    assert r.returncode == 1, r.stdout + r.stderr
    assert f"{INIT} binds `__version__` in a way this gate does not read" in r.stdout, r.stdout


@pytest.mark.parametrize("source", [INIT, "CITATION.cff"])
def test_a_source_that_states_no_version_is_no_agreement(tree, source):
    """The OK line says "single-sourced across pyproject.toml/__init__.py/CITATION.cff"; a source that
    states no version the gate can read did not take part in that, and was counted as agreeing."""
    version = _version(tree)
    text = (tree / source).read_text(encoding="utf-8")
    changed = (text.replace(f'__version__ = "{version}"', "")
               if source == INIT else re.sub(r"(?m)^version\s*:.*\n", "", text))
    assert changed != text
    (tree / source).write_text(changed, encoding="utf-8")
    r = _gate(tree)
    assert r.returncode == 1, r.stdout + r.stderr
    assert f"{source} states no version this gate can read" in r.stdout, r.stdout


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
