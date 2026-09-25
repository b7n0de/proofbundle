"""A SOURCES.txt is chosen by the project it belongs to, never by where it sorts.

Four readers under tests/ asked which file list describes this distribution and each took the first
non-empty SOURCES.txt in alphabetical glob order. An adversarial lens showed on 2026-09-24 that an
egg-info sorting before the real one then decides the answer, and on 2026-09-25 the main checkout
was measured carrying exactly such a stranger (`UNKNOWN.egg-info`, 26 scripts, beside
`src/proofbundle.egg-info`). The choice now lives once, in `tests/conftest.py::_quellenliste_waehlen`,
and these cases pin its three outcomes and the readers that use it. Every tree is built here, so no
case borrows a fact from the real one.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

CONFTEST = Path(__file__).resolve().parent / "conftest.py"


def _cf():
    spec = importlib.util.spec_from_file_location("_cf_sources_by_name", CONFTEST)
    modul = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = modul
    spec.loader.exec_module(modul)
    return modul


def _egg_info(root: Path, where: str, name: str, entries: str) -> Path:
    d = root / where
    d.mkdir(parents=True)
    (d / "PKG-INFO").write_text(f"Metadata-Version: 2.1\nName: {name}\nVersion: 0\n",
                                encoding="utf-8")
    (d / "SOURCES.txt").write_text(entries, encoding="utf-8")
    return d / "SOURCES.txt"


def _project(root: Path, name: str = "beispiel") -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "pyproject.toml").write_text(f'[project]\nname = "{name}"\nversion = "0"\n\n'
                                         '[tool.x]\nname = "not-the-project"\n', encoding="utf-8")
    return root


def test_a_foreign_list_that_sorts_first_does_not_decide(tmp_path):
    """The lens case: `aaa/` sorts before `src/`, and the old rule took its list."""
    root = _project(tmp_path / "t")
    _egg_info(root, "aaa/fremd.egg-info", "fremd", "scripts/fremd.py\n")
    own = _egg_info(root, "src/beispiel.egg-info", "beispiel", "scripts/eigen.py\n")
    chosen, reason = _cf()._quellenliste_waehlen(root)
    assert chosen == own, (chosen, reason)
    first_in_old_order = sorted(root.glob("*/*.egg-info/SOURCES.txt"))[0]
    assert first_in_old_order != own, "precondition: the old order would have chosen the stranger"


def test_the_readers_answer_from_the_list_of_this_project(tmp_path):
    root = _project(tmp_path / "t")
    _egg_info(root, "aaa/fremd.egg-info", "fremd", "werkzeuge/fremd.py\n")
    _egg_info(root, "src/beispiel.egg-info", "beispiel", "scripts/eigen.py\n")
    cf = _cf()
    assert cf._verteilung_sollte_enthalten("scripts/eigen.py", root) is True
    assert cf._verteilung_sollte_enthalten("werkzeuge/fremd.py", root) is False
    assert cf._verteilung_kennt_den_ort("scripts/x.py", root) is True
    assert cf._verteilung_kennt_den_ort("werkzeuge/x.py", root) is False


def test_only_foreign_lists_are_no_basis_and_say_so(tmp_path):
    root = _project(tmp_path / "t")
    _egg_info(root, "UNKNOWN.egg-info", "UNKNOWN", "scripts/alt.py\n")
    chosen, reason = _cf()._quellenliste_waehlen(root)
    assert chosen is None
    assert "UNKNOWN.egg-info/SOURCES.txt" in reason, reason


def test_two_lists_of_this_project_are_a_guess_not_an_answer(tmp_path):
    root = _project(tmp_path / "t")
    _egg_info(root, "build/beispiel.egg-info", "beispiel", "scripts/alt.py\n")
    _egg_info(root, "src/beispiel.egg-info", "beispiel", "scripts/neu.py\n")
    chosen, reason = _cf()._quellenliste_waehlen(root)
    assert chosen is None
    assert "picking one is a guess" in reason, reason


def test_without_a_project_name_nothing_can_be_attributed(tmp_path):
    root = tmp_path / "t"
    _egg_info(root, "src/beispiel.egg-info", "beispiel", "scripts/eigen.py\n")
    chosen, reason = _cf()._quellenliste_waehlen(root)
    assert chosen is None
    assert "pyproject.toml" in reason, reason


def test_an_empty_list_of_this_project_is_no_basis(tmp_path):
    root = _project(tmp_path / "t")
    _egg_info(root, "src/beispiel.egg-info", "beispiel", "\n")
    _egg_info(root, "aaa/fremd.egg-info", "fremd", "scripts/fremd.py\n")
    assert _cf()._quellenliste_waehlen(root)[0] is None


@pytest.mark.parametrize("declared,in_pkg_info", [("Proof_Bundle", "proof-bundle"),
                                                  ("proof.bundle", "Proof-Bundle")])
def test_names_compare_as_normalised_distribution_names(tmp_path, declared, in_pkg_info):
    root = _project(tmp_path / "t", declared)
    own = _egg_info(root, "src/x.egg-info", in_pkg_info, "scripts/eigen.py\n")
    assert _cf()._quellenliste_waehlen(root)[0] == own


@pytest.mark.parametrize("pyproject", [
    '[project]  # PEP 621 metadata\nname = "beispiel"\nversion = "0"\n',
    '[ project ]\nname = "beispiel"\nversion = "0"\n',
    '[project]\ndescription = """\nname = "fremd"\n"""\nname = "beispiel"\nversion = "0"\n',
])
def test_the_project_name_is_parsed_as_toml_not_searched_as_text(tmp_path, pyproject):
    """A review lens, 2026-09-25: two regular expressions lost the name or found a decoy."""
    root = tmp_path / "t"
    root.mkdir()
    (root / "pyproject.toml").write_text(pyproject, encoding="utf-8")
    own = _egg_info(root, "src/beispiel.egg-info", "beispiel", "scripts/eigen.py\n")
    _egg_info(root, "aaa/fremd.egg-info", "fremd", "scripts/fremd.py\n")
    chosen, reason = _cf()._quellenliste_waehlen(root)
    assert chosen == own, (chosen, reason)


def test_a_symlink_to_the_same_list_is_one_list_not_two(tmp_path):
    root = _project(tmp_path / "t")
    own = _egg_info(root, "src/beispiel.egg-info", "beispiel", "scripts/eigen.py\n")
    (root / "beispiel.egg-info").symlink_to(own.parent, target_is_directory=True)
    chosen, reason = _cf()._quellenliste_waehlen(root)
    assert chosen is not None and chosen.resolve() == own.resolve(), (chosen, reason)


def test_without_any_basis_the_readers_stay_loud(tmp_path):
    """Unchanged rule of conftest: no basis means 'should be shipped' and 'place unknown'."""
    root = tmp_path / "t"
    root.mkdir()
    cf = _cf()
    assert cf._verteilung_sollte_enthalten("scripts/x.py", root) is True
    assert cf._verteilung_kennt_den_ort("scripts/x.py", root) is False
