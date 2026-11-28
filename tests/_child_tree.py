"""A child a test starts loads the proofbundle this test process imports, not the installed one (lesson L206).

Measured on 22 November 2026 at head c1ae176b: pytest's pythonpath option (`-o pythonpath=src`, the form the witness
uses) puts src/ on sys.path of the pytest process only. tests/test_verifier_block.py starts conformance/run_conformance.py
as a child without env=, the child had no PYTHONPATH, imported the proofbundle 6.5.0 the venv carries as an editable
install of another checkout, and the case was red (`subject_matches_build: False`) for a reason that was not in the tree.
tests/_plugin_env.py already set PYTHONPATH, but only for plugin test modules; a neighbour in test_verifier_block.py set
it by hand for one call. Both were instances. This module holds the class for every test module:

* `children_load_this_tree`, a session-scoped autouse fixture tests/conftest.py imports, puts the directory that holds
  the proofbundle this process imports first on PYTHONPATH, so a child that inherits the environment imports the same
  package, and before it a folder of the session's own with a `sitecustomize.py`, the watch.
* The watch runs at the start of every such Python child. It records each child whose `import proofbundle` resolves to
  an INSTALLED package outside that directory, and the fixture fails at the end of the session with the list: the test
  that started the child, its command line and the file it loaded. Installed means what the interpreter brings by
  itself, not what the child was given: a `sys.path` entry the interpreter had at start that did not come from
  PYTHONPATH (site-packages, a path from a `.pth` file, which is the editable install of the incident), or a finder
  of its own on the meta path (an editable install of the newer form). A copy of the tree that a test puts on
  PYTHONPATH, into the working directory or onto `sys.path` is the test's own choice and passes; the suite builds such
  copies on purpose (tests/_private_build_tree.py, the pre-tag checkers), and the first form of this watch, which
  judged by place instead of by origin, recorded 58 of them in a full run (28 November 2026). The watch prints nothing
  and never ends a child; it hands on to the `sitecustomize` it shadows, so a child behaves as without it.

NAMED LIMITS. A child started with `-I`, `-E` or `-S`, or with an environment that has no PYTHONPATH or whose
PYTHONPATH a test replaced, reads neither the directory nor the watch; the watch cannot see it, and PYTHONPATH cannot
steer it. Such a child loads what its interpreter has installed, by design or not. The plugin's own starts are `-I` on
purpose (tests/test_codex_plugin.py::test_the_host_start_commands_isolate_the_interpreter_and_the_server).

tests/test_a_child_loads_the_tree_it_runs_under.py holds both pieces."""
from __future__ import annotations

import importlib.util
import os
import pathlib

import pytest

#: The package whose origin a child must share with this process.
PACKAGE = "proofbundle"
#: The name of the watch's record file in its folder.
RECORD = "children_outside_the_tree.tsv"

# The watch. It imports nothing at module level beyond what every interpreter has loaded at start (sys, os), so a
# test that asks which modules a child imported sees no difference, and it writes nothing to stdout or stderr.
_MARK = "# The watch of tests/_child_tree.py (lesson L206), written for one pytest session."
_WATCH = r'''@@MARK@@
import os as _os
import sys as _sys

_TREE = @@TREE@@
_RECORD = @@RECORD@@
_HERE = _os.path.dirname(_os.path.realpath(__file__))


def _real(path):
    return _os.path.realpath(path or _os.curdir)


# What the interpreter brings by itself. sitecustomize runs at the end of site, after the .pth files and before the
# script's own directory or the working directory join sys.path, so every entry here that PYTHONPATH did not bring is
# the interpreter's: site-packages, the paths of .pth files, the standard library.
_GIVEN = set(_real(p) for p in _os.environ.get("PYTHONPATH", "").split(_os.pathsep) if p)
_BROUGHT = set(_real(p) for p in _sys.path if p) - _GIVEN


def _inside(path):
    real = _real(path)
    return real == _TREE or real.startswith(_TREE + _os.sep)


def _installed(spec, finder):
    if getattr(finder, "__name__", "") != "PathFinder":
        return True    # a finder of the interpreter's own on the meta path: an editable install of the newer form
    origin = getattr(spec, "origin", None)
    places = list(getattr(spec, "submodule_search_locations", None) or [])
    folder = _os.path.dirname(origin) if origin and origin not in ("built-in", "frozen") else (places[0] if places else "")
    return bool(folder) and _real(_os.path.dirname(folder)) in _BROUGHT


class _ChildTreeWatch(object):
    """Finds nothing itself: it asks the finders after it and records where `import proofbundle` resolved."""

    @classmethod
    def find_spec(cls, name, path=None, target=None):
        if name != @@PACKAGE@@:
            return None
        spec, by = None, None
        for finder in list(_sys.meta_path):
            if finder is cls or not hasattr(finder, "find_spec"):
                continue
            try:
                spec = finder.find_spec(name, path, target)
            except TypeError:
                spec = finder.find_spec(name, path)
            if spec is not None:
                by = finder
                break
        try:
            if spec is not None:
                places = [p for p in [getattr(spec, "origin", None)] if p and p not in ("built-in", "frozen")]
                places += list(getattr(spec, "submodule_search_locations", None) or [])
                outside = [p for p in places if not _inside(p)]
                if outside and _installed(spec, by):
                    row = "\t".join([str(_os.getpid()), repr(outside[0]), repr(_os.getcwd()),
                                     repr(_os.environ.get("PYTEST_CURRENT_TEST", "")), repr(list(_sys.argv))])
                    with open(_RECORD, "a", encoding="utf-8") as handle:
                        handle.write(row.replace("\n", " ") + "\n")
        except Exception:
            pass
        return spec


_sys.meta_path.insert(0, _ChildTreeWatch)

# Hand on to the sitecustomize this file shadows (Ubuntu's apport hook, say), so a child behaves as without the watch.
# Never to another watch: a pytest session inside a test puts its own watch before the caller's, and two watches that
# hand on to each other ran in a circle until the child died (measured on the gate meta of the session's end).
def _is_watch(folder):
    try:
        with open(_os.path.join(folder or _os.curdir, "sitecustomize.py"), encoding="utf-8") as handle:
            return handle.readline().rstrip("\n") == @@MARKREPR@@
    except OSError:
        return False


try:
    _rest = [p for p in _sys.path if _real(p) != _HERE and not _is_watch(p)]
    _finder = [f for f in _sys.meta_path if getattr(f, "__name__", "") == "PathFinder"]
    _spec = _finder[0].find_spec("sitecustomize", _rest) if _finder else None
    if _spec is not None and _spec.loader is not None:
        import _frozen_importlib as _bootstrap
        _spec.loader.exec_module(_bootstrap.module_from_spec(_spec))
except Exception:
    pass
'''


def package_root() -> pathlib.Path | None:
    """The directory that holds the proofbundle this test process imports (src/ of the tree in a checkout), or None
    when this process cannot import it."""
    spec = importlib.util.find_spec(PACKAGE)
    if spec is None or not spec.origin:
        return None
    return pathlib.Path(spec.origin).resolve().parent.parent


def write_watch(folder: pathlib.Path, root: pathlib.Path) -> pathlib.Path:
    """Write the watch for `root` into `folder` and return the path of its record file, which it creates empty."""
    folder.mkdir(parents=True, exist_ok=True)
    record = folder / RECORD
    record.write_text("", encoding="utf-8")
    text = (_WATCH.replace("@@MARKREPR@@", repr(_MARK)).replace("@@MARK@@", _MARK)
            .replace("@@TREE@@", repr(os.path.realpath(root)))
            .replace("@@RECORD@@", repr(str(record)))
            .replace("@@PACKAGE@@", repr(PACKAGE)))
    (folder / "sitecustomize.py").write_text(text, encoding="utf-8")
    return record


def read_record(record: pathlib.Path) -> list[str]:
    """The children the watch recorded, one line each."""
    try:
        return [z for z in record.read_text(encoding="utf-8").splitlines() if z.strip()]
    except OSError:
        return []


@pytest.fixture(scope="session", autouse=True)
def children_load_this_tree(tmp_path_factory):
    """For the whole session: the package's directory and the watch first on PYTHONPATH; at the end, red when a child
    loaded an installed proofbundle from outside that directory."""
    root = package_root()
    if root is None:
        yield
        return
    folder = tmp_path_factory.mktemp("child_tree_watch")
    record = write_watch(folder, root)
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("PYTHONPATH", os.pathsep.join(p for p in (str(folder), str(root), os.environ.get("PYTHONPATH"))
                                                   if p))
        yield
    children = read_record(record)
    if children:
        raise AssertionError(
            f"{len(children)} child process(es) loaded an installed {PACKAGE} from outside {root} (lesson L206; "
            "columns: pid, the file it loaded, its working directory, the test that started it, its command line):\n"
            + "\n".join(children))
