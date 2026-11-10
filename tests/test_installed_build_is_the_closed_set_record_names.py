"""The installed build is the closed set of files its RECORD names, and nothing beside them.

Local review of 8a05ceef (2026-11-10, P1), the neighbour of DELTA2 N4. `_installed_record_rows` held every RECORD row
to its bytes, but never held the package directory to the rows: an added `proofbundle/signature/__init__.py` is
imported in place of `signature.py`, and the listing, the digest and `report` stayed those of the wheel. A file of
the package that RECORD does not name now makes the tree measure as `source-tree`; bytecode stays outside the
identity, as before.
"""
from __future__ import annotations

import importlib.machinery
import importlib.metadata as im
import py_compile
import subprocess
import sys

import pytest

from proofbundle import verifier_block as VB

_NAMEN = ("__init__.py", "signature.py")


def _install(tmp_path, monkeypatch):
    """A package as a wheel install leaves it, with the RECORD that names its two files."""
    pkg = tmp_path / "site" / "proofbundle"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("__version__ = 'x'\n")
    (pkg / "signature.py").write_text("def verify_ed25519(*a):\n    return False\n")
    record = "".join(f"proofbundle/{n},sha256={VB._record_digest_of(pkg / n)},1\n" for n in _NAMEN)
    record += "proofbundle-6.6.0.dist-info/RECORD,,\n"

    class Dist:
        def read_text(self, name):
            return record if name == "RECORD" else None

        def locate_file(self, rel):
            return tmp_path / "site" / rel

    monkeypatch.setattr(im, "distribution", lambda name: Dist())
    return pkg


def test_positive_control_the_files_record_names_are_the_installed_build(tmp_path, monkeypatch):
    b = VB.measure_build(_install(tmp_path, monkeypatch))
    assert (b["source"], b["files"]) == ("installed-record", len(_NAMEN))


def test_bytecode_beside_the_files_is_still_the_installed_build(tmp_path, monkeypatch):
    pkg = _install(tmp_path, monkeypatch)
    (pkg / "__pycache__").mkdir()
    (pkg / "__pycache__" / "signature.cpython-312.pyc").write_bytes(b"\0\1")
    assert VB.measure_build(pkg)["source"] == "installed-record"


@pytest.mark.parametrize("rel", ["signature/__init__.py", "extra.py", "data.json", "tief/innen/notiz.txt"])
def test_a_file_record_does_not_name_is_not_the_installed_build(tmp_path, monkeypatch, rel):
    pkg = _install(tmp_path, monkeypatch)
    vorher = VB.measure_build(pkg)
    ziel = pkg / rel
    ziel.parent.mkdir(parents=True, exist_ok=True)
    ziel.write_text("def verify_ed25519(*a):\n    return True\n")
    nachher = VB.measure_build(pkg)
    assert nachher["source"] == "source-tree", rel
    assert nachher["digest"] != vorher["digest"], rel


def _importiert(site) -> str:
    """What Python's own importer loads as `proofbundle.signature` from the site directory, in a fresh process: the
    half of each case below that shows the plant is live, so the case cannot pass on a plant nothing imports."""
    r = subprocess.run([sys.executable, "-I", "-B", "-c", "import sys; sys.path.insert(0, sys.argv[1]); "
                        "import proofbundle.signature as s; print(s.verify_ed25519())", str(site)],
                       capture_output=True, text=True, timeout=60)
    return r.stdout.strip() or r.stderr.strip()[-200:]


def test_a_link_to_a_directory_elsewhere_is_no_build_of_the_package(tmp_path, monkeypatch):
    """Second local review of 9b0181cf (P1): a link `signature` to a directory outside, beside the files RECORD names,
    is imported in place of `signature.py`; the first form of the check skipped every directory."""
    pkg = _install(tmp_path, monkeypatch)
    aussen = tmp_path / "aussen_signature"
    aussen.mkdir()
    (aussen / "__init__.py").write_text("def verify_ed25519(*a):\n    return True\n")
    assert _importiert(pkg.parent) == "False"
    (pkg / "signature").symlink_to(aussen, target_is_directory=True)
    assert _importiert(pkg.parent) == "True", "the link is not imported; the case would prove nothing"
    with pytest.raises(VB.VerifierBlockError, match="link to a directory outside"):
        VB.measure_build(pkg)


def test_bytecode_without_its_source_is_not_the_installed_build(tmp_path, monkeypatch):
    """Second local review of 9b0181cf (P1): `signature/__init__.pyc` without a source is a package the importer
    takes in place of `signature.py`; the first form of the check skipped every `.pyc`."""
    pkg = _install(tmp_path, monkeypatch)
    vorher = VB.measure_build(pkg)
    quelle = tmp_path / "pflanze.py"
    quelle.write_text("def verify_ed25519(*a):\n    return True\n")
    (pkg / "signature").mkdir()
    py_compile.compile(str(quelle), cfile=str(pkg / "signature" / "__init__.pyc"), doraise=True)
    assert _importiert(pkg.parent) == "True", "the bytecode is not imported; the case would prove nothing"
    nachher = VB.measure_build(pkg)
    assert nachher["source"] == "source-tree"
    assert nachher["digest"] != vorher["digest"]


def test_the_source_tree_counts_what_the_importer_loads(tmp_path, monkeypatch):
    """The other measurement path: a source tree took `.py`, `.json` and `.typed` only, so bytecode outside the cache
    or an extension module beside a `.py` of the same name moved nothing. Each moves the digest now; a text file and
    the interpreter's own cache do not."""
    def _keine(name):
        raise im.PackageNotFoundError(name)

    monkeypatch.setattr(im, "distribution", _keine)
    pkg = tmp_path / "baum" / "proofbundle"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("__version__ = 'x'\n")
    (pkg / "signature.py").write_text("def verify_ed25519(*a):\n    return False\n")
    basis = VB.measure_build(pkg)
    assert basis["source"] == "source-tree"
    (pkg / "notiz.txt").write_text("no code\n")
    (pkg / "__pycache__").mkdir()
    (pkg / "__pycache__" / "signature.cpython-312.pyc").write_bytes(b"\0\1")
    assert VB.measure_build(pkg)["digest"] == basis["digest"], "a text file and the cache are not the build"
    for name in ("signature.pyc", "signature" + importlib.machinery.EXTENSION_SUFFIXES[0]):
        (pkg / name).write_bytes(b"\0\1\2")
        assert VB.measure_build(pkg)["digest"] != basis["digest"], name
        (pkg / name).unlink()
