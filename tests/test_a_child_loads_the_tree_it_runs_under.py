"""Lesson L206: a child a test starts loads the proofbundle the test process imports, and a run is red when one does not.

tests/_child_tree.py holds the rule. The first case is the incident's form: a child started without env= from a folder
outside the tree. Without the session fixture, under `-o pythonpath=src` and an interpreter whose installed proofbundle
lies elsewhere (the Farmer's venv: an editable install of another checkout), it loads that one and the case is red. Where
the installed proofbundle IS this tree (CI's `pip install -e .`), it passes either way; the gate metas below hold the
watch on every runner."""
from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import textwrap

import pytest

import _child_tree as CT

ROOT = CT.package_root()
pytestmark = pytest.mark.skipif(ROOT is None, reason="this process imports no proofbundle")

_WHERE = "import proofbundle, sys; sys.stdout.write(proofbundle.__file__)"


def _real(p) -> str:
    return os.path.realpath(str(p))


def _under(p, top) -> bool:
    return _real(p).startswith(_real(top) + os.sep)


def _foreign_package(folder: pathlib.Path) -> pathlib.Path:
    """A proofbundle that is not this tree's, as an installed copy elsewhere would be."""
    pkg = folder / "proofbundle"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("__version__ = '0.0.0-foreign'\n", encoding="utf-8")
    return pkg / "__init__.py"


def test_a_child_without_env_loads_the_package_of_this_process(tmp_path):
    """The incident's form: no env=, a working directory outside the tree. The child loads the proofbundle this
    process imports, not the one its interpreter has installed."""
    r = subprocess.run([sys.executable, "-c", _WHERE], cwd=str(tmp_path), capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr[-600:]
    assert _under(r.stdout, ROOT), f"the child loaded {r.stdout!r}, this process imports the package under {ROOT}"


def test_every_child_that_inherits_the_environment_carries_the_watch(tmp_path):
    """The session's rule is in place for real children, not only for the probes below: a child that inherits the
    environment has the watch first on its meta path."""
    probe = "import sys; sys.stdout.write(repr([getattr(f, '__name__', '') for f in sys.meta_path][:1]))"
    r = subprocess.run([sys.executable, "-c", probe], cwd=str(tmp_path), capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr[-600:]
    assert r.stdout == "['_ChildTreeWatch']", r.stdout


def _child(env_path: list, tmp_path: pathlib.Path, code: str = _WHERE) -> subprocess.CompletedProcess:
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(str(p) for p in env_path))
    return subprocess.run([sys.executable, "-c", code], cwd=str(tmp_path), env=env, capture_output=True, text=True,
                          timeout=120)


def test_gate_meta_the_watch_records_a_child_that_loads_a_foreign_package(tmp_path):
    """The watch's own failure: a child whose proofbundle resolves outside the tree is recorded with the file it
    loaded and its command line, and the child itself runs on unchanged and prints nothing of the watch."""
    watch = tmp_path / "watch"
    record = CT.write_watch(watch, ROOT)
    fremd = _foreign_package(tmp_path / "elsewhere")
    r = _child([watch, fremd.parent.parent], tmp_path)
    assert r.returncode == 0, r.stderr[-600:]
    assert _real(r.stdout) == _real(fremd), "the child ran on and loaded the foreign package"
    rows = CT.read_record(record)
    assert len(rows) == 1, rows
    assert repr(str(fremd)) in rows[0] or repr(_real(fremd)) in rows[0], rows[0]
    assert "'-c'" in rows[0], "the row names the child's command line"


def test_control_the_watch_stays_silent_for_a_child_that_loads_the_tree(tmp_path):
    """The null run: the same watch, the tree first on the path, nothing recorded."""
    watch = tmp_path / "watch"
    record = CT.write_watch(watch, ROOT)
    r = _child([watch, ROOT], tmp_path)
    assert r.returncode == 0, r.stderr[-600:]
    assert _under(r.stdout, ROOT), r.stdout
    assert CT.read_record(record) == []


def test_a_package_below_the_own_temporary_folder_is_a_tests_own_tree(tmp_path):
    """A copy a test built under the session's temporary folder passes; the same copy without that folder named is
    recorded, so the exception is exactly that folder."""
    fremd = _foreign_package(tmp_path / "copy")
    for own, expected in ((tmp_path, 0), (None, 1)):
        watch = tmp_path / f"watch_{expected}"
        record = CT.write_watch(watch, ROOT, own)
        r = _child([watch, fremd.parent.parent], tmp_path)
        assert r.returncode == 0, r.stderr[-600:]
        assert len(CT.read_record(record)) == expected, (own, CT.read_record(record))


def test_the_watch_hands_on_to_the_sitecustomize_it_shadows(tmp_path):
    """A sitecustomize later on the path (Ubuntu's apport hook, say) still runs: the watch shadows none."""
    watch = tmp_path / "watch"
    CT.write_watch(watch, ROOT)
    later = tmp_path / "later"
    later.mkdir()
    marker = tmp_path / "marker"
    (later / "sitecustomize.py").write_text(f"open({str(marker)!r}, 'w').close()\n", encoding="utf-8")
    probe = "import sys; sys.stdout.write(getattr(sys.meta_path[0], '__name__', ''))"
    r = _child([watch, later, ROOT], tmp_path, probe)
    assert r.returncode == 0, r.stderr[-600:]
    assert r.stdout == "_ChildTreeWatch"
    assert marker.exists(), "the shadowed sitecustomize did not run"


def test_two_watches_on_the_path_do_not_hand_on_to_each_other(tmp_path):
    """A pytest session inside a test puts its own watch before the caller's. The first one watches, neither hands on
    to the other, and the child runs; before this case two watches handed on to each other in a circle."""
    first, second = tmp_path / "first", tmp_path / "second"
    CT.write_watch(first, ROOT)
    CT.write_watch(second, ROOT)
    probe = "import sys; sys.stdout.write(repr([getattr(f, '__name__', '') for f in sys.meta_path].count('_ChildTreeWatch')))"
    r = _child([first, ROOT, second, ROOT], tmp_path, probe)
    assert r.returncode == 0, r.stderr[-600:]
    assert r.stdout == "1", r.stdout


def _session(tmp_path: pathlib.Path, body: str) -> subprocess.CompletedProcess:
    """A pytest session of its own with the fixture and one test, so the fixture's end is measured, not assumed."""
    tree = tmp_path / "session"
    tree.mkdir(parents=True)
    (tree / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    (tree / "_child_tree.py").write_text(pathlib.Path(CT.__file__).read_text(encoding="utf-8"), encoding="utf-8")
    (tree / "conftest.py").write_text("from _child_tree import children_load_this_tree  # noqa: F401\n",
                                      encoding="utf-8")
    (tree / "test_one.py").write_text(textwrap.dedent(body), encoding="utf-8")
    return subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-c",
                           str(tree / "pytest.ini"), "--rootdir", str(tree), str(tree)],
                          cwd=str(tree), capture_output=True, text=True, timeout=300)


def test_gate_meta_a_session_whose_child_loads_a_foreign_package_is_red(tmp_path):
    """The fixture's end: a session in which one child loaded proofbundle from elsewhere ends red and names it, and the
    same session with a child that loads the tree ends green."""
    fremd = _foreign_package(pathlib.Path(os.path.realpath(tmp_path)).parent / f"{tmp_path.name}_elsewhere")
    body = f"""
        import os, subprocess, sys
        def test_one():
            first = os.environ["PYTHONPATH"].split(os.pathsep)[0]
            path = os.pathsep.join([first, {str(fremd.parent.parent)!r}]) if {{switch}} else os.environ["PYTHONPATH"]
            subprocess.run([sys.executable, "-c", "import proofbundle"], env=dict(os.environ, PYTHONPATH=path),
                           check=True)
        """
    red = _session(tmp_path / "red", body.replace("{switch}", "True"))
    green = _session(tmp_path / "green", body.replace("{switch}", "False"))
    assert red.returncode != 0, red.stdout[-1500:] + red.stderr[-1500:]
    assert "loaded proofbundle from outside" in red.stdout and str(fremd.parent) in red.stdout, (
        red.stdout[-1500:] + red.stderr[-1500:])
    assert green.returncode == 0, green.stdout[-1500:] + green.stderr[-1500:]
