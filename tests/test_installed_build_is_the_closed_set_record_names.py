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
import json
import os
import py_compile
import stat
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
    with pytest.raises(VB.VerifierBlockError, match="is a link to a directory"):
        VB.measure_build(pkg)


def test_a_link_inside_the_package_that_chooses_the_code_has_no_identity(tmp_path, monkeypatch):
    """Third local review of 643a33b5 (P1): both target packages are files of the tree before the link exists, and only
    the link `signature` decides which of them a name imports. The files stay the same, so a digest over them could
    not see the link added or turned to the other target; a tree carrying a link to a directory is refused."""
    def _keine(name):
        raise im.PackageNotFoundError(name)

    monkeypatch.setattr(im, "distribution", _keine)
    site = tmp_path / "baum"
    pkg = site / "proofbundle"
    for sub, wert in (("_gut", "False"), ("_boese", "True")):
        (pkg / sub).mkdir(parents=True)
        (pkg / sub / "__init__.py").write_text(f"def verify_ed25519(*a):\n    return {wert}\n")
    (pkg / "__init__.py").write_text("__version__ = 'x'\n")
    (pkg / "signature.py").write_text("def verify_ed25519(*a):\n    return False\n")
    assert VB.measure_build(pkg)["source"] == "source-tree", "positive control: the tree without the link measures"
    for ziel, erwartet in (("_gut", "False"), ("_boese", "True")):
        (pkg / "signature").symlink_to(pkg / ziel, target_is_directory=True)
        assert _importiert(site) == erwartet, (ziel, "the link does not decide the import; the case would prove nothing")
        with pytest.raises(VB.VerifierBlockError, match="is a link to a directory"):
            VB.measure_build(pkg)
        (pkg / "signature").unlink()


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


def test_the_source_tree_is_every_file_but_the_interpreter_cache(tmp_path, monkeypatch):
    """The other measurement path: a source tree took `.py`, `.json` and `.typed` only, and three reviews each found
    one more form the importer loads while the digest stayed: bytecode outside the cache, an extension module, and
    `signature/__init__.PY`, which CPython takes as the package on a file system that does not tell upper from lower
    case (fourth local review of aa578913, measured there on a simulated case-insensitive file system; this host's
    file system tells them apart, so the import half of that case is not shown here). Every file of the tree moves
    the digest now; only the interpreter's own cache does not."""
    def _keine(name):
        raise im.PackageNotFoundError(name)

    monkeypatch.setattr(im, "distribution", _keine)
    pkg = tmp_path / "baum" / "proofbundle"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("__version__ = 'x'\n")
    (pkg / "signature.py").write_text("def verify_ed25519(*a):\n    return False\n")
    basis = VB.measure_build(pkg)
    assert basis["source"] == "source-tree"
    (pkg / "__pycache__").mkdir()
    (pkg / "__pycache__" / "signature.cpython-312.pyc").write_bytes(b"\0\1")
    assert VB.measure_build(pkg)["digest"] == basis["digest"], "the interpreter's cache is not the build"
    (pkg / "signature").mkdir()
    for name in ("signature.pyc", "signature" + importlib.machinery.EXTENSION_SUFFIXES[0], "signature/__init__.PY",
                 "signature/__init__.Py", "notiz.txt"):
        (pkg / name).write_bytes(b"\0\1\2")
        gemessen = VB.measure_build(pkg)
        assert gemessen["digest"] != basis["digest"] and gemessen["files"] == basis["files"] + 1, name
        (pkg / name).unlink()
    assert VB.measure_build(pkg)["digest"] == basis["digest"], "each plant taken out, the tree measures as before"


def _nur_durchsuchbar(ordner):
    """Mode 0111: the directory can be searched but not listed. Returns False where this user can list it anyway
    (root), measured, so a case built on it would not exist here."""
    ordner.chmod(stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    try:
        os.listdir(ordner)
    except PermissionError:
        return True
    return False


def test_a_package_directory_that_cannot_be_listed_has_no_identity(tmp_path, monkeypatch):
    """Fifth local review of 6e3d4d72 (P1): `Path.rglob` swallowed the error of a directory it could not list, and
    `signature/` in mode 0111 still lets the importer take its `__init__.py` in place of `signature.py`; both build
    measurements stayed the same. The walk now stops there, as the third-party verifier of the release gate does
    since its review R2-5."""
    pkg = _install(tmp_path, monkeypatch)
    ordner = pkg / "signature"
    ordner.mkdir()
    (ordner / "__init__.py").write_text("def verify_ed25519(*a):\n    return True\n")
    try:
        if not _nur_durchsuchbar(ordner):
            pytest.skip("this user can list a directory without its read bit (root?): the case does not exist here")
        assert _importiert(pkg.parent) == "True", "the hidden package is not imported; the case would prove nothing"
        with pytest.raises(VB.VerifierBlockError, match="cannot be listed"):
            VB.measure_build(pkg)
    finally:
        ordner.chmod(stat.S_IRWXU)
    assert VB.measure_build(pkg)["source"] == "source-tree", "listable again, the extra package is measured"


def test_a_corpus_directory_that_cannot_be_listed_is_no_vector_set(tmp_path):
    """The same walk read the vector set: a case directory, or a directory with an unnamed `case.json`, that cannot be
    listed left the digest and the count of the rest. Both refuse now; listable again, the corpus measures."""
    root = tmp_path / "c"
    root.mkdir()
    (root / "manifest.json").write_text(json.dumps({"schema": "proofbundle.conformance.manifest.v1", "cases": ["a"]}))
    (root / "a").mkdir()
    (root / "a" / "case.json").write_text(json.dumps({"caseId": "a"}))
    (root / "a" / "tief").mkdir()
    (root / "a" / "tief" / "vector.json").write_text("{}")
    assert VB.measure_vector_set(root)["cases"] == 1, "positive control"
    for ordner in (root / "a" / "tief", root / "a"):
        try:
            if not _nur_durchsuchbar(ordner):
                pytest.skip("this user can list a directory without its read bit (root?): the case does not exist here")
            with pytest.raises(VB.VerifierBlockError, match="cannot be listed"):
                VB.measure_vector_set(root)
        finally:
            ordner.chmod(stat.S_IRWXU)
    assert VB.measure_vector_set(root)["cases"] == 1
