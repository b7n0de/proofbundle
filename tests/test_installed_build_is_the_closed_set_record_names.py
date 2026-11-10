"""The installed build is the closed set of files its RECORD names, and nothing beside them.

Local review of 8a05ceef (2026-11-10, P1), the neighbour of DELTA2 N4. `_installed_record_rows` held every RECORD row
to its bytes, but never held the package directory to the rows: an added `proofbundle/signature/__init__.py` is
imported in place of `signature.py`, and the listing, the digest and `report` stayed those of the wheel. A file of
the package that RECORD does not name now makes the tree measure as `source-tree`; bytecode stays outside the
identity, as before.
"""
from __future__ import annotations

import importlib.metadata as im

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
