"""Python and the Rust verifier read an sd_jwt_vc block and its disclosures alike (pull request 373).

Codex thread 4303513211: `verify_sd_jwt` now places each disclosure and refuses a claim name twice in
one object, while Rust verify-bundle never read the disclosures at all and still verified those
bundles. Measured on 2026-10-18 with the Rust of main 2379659e, 15 of the first 32 vectors of
`crosscheck._disclosure_bundle_cases` gave a different exit code with the Python of main, among them
five disclosure defects that Python already refused, and 20 with the Python of this pull request. A
lens then built 37 mutants of the Rust rules; 16 survived the 32, and the 46 vectors now kill all but
the three it showed to be equivalent. `_disclosure_rust_stricter_cases` pins a named gap, JSON that only
Python's parser reads. The vectors live in crosscheck.py, so the differential the rust-parity job runs
and this test read one list.
"""
from __future__ import annotations

import collections
import importlib.util
import pathlib

import pytest

try:
    import _pb_verify_rs  # tests/_pb_verify_rs.py, the one way to the binary
except ModuleNotFoundError:  # `python -m unittest tests.<module>` puts the root on sys.path
    from tests import _pb_verify_rs

REPO = pathlib.Path(__file__).resolve().parents[1]
CROSSCHECK = REPO / "tools" / "pb_verify_rs" / "crosscheck.py"


def _load(name: str):
    if not CROSSCHECK.is_file():
        pytest.skip("repo-context: tools/ is pruned from the sdist, crosscheck.py is not shipped")
    spec = importlib.util.spec_from_file_location(name, CROSSCHECK)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_every_vector_gets_the_same_exit_code_on_both_sides(monkeypatch, tmp_path):
    binary = _pb_verify_rs.binary_or_skip()
    monkeypatch.setenv(_pb_verify_rs.PINNED_ENV, str(binary))
    crosscheck = _load("_crosscheck_disclosures")
    assert crosscheck.BIN == binary
    failures, compared, gap = crosscheck._disclosure_bundle_differential(tmp_path)
    assert failures == []
    assert compared == len(crosscheck._disclosure_bundle_cases())
    assert gap == len(crosscheck._disclosure_rust_stricter_cases())


def test_the_vectors_pin_each_exit_code_and_name_each_vector_once():
    """Without the binary: a list that lost its controls, or every malformed vector, would agree on
    fewer questions and still pass the differential."""
    crosscheck = _load("_crosscheck_disclosure_cases")
    cases = crosscheck._disclosure_bundle_cases()
    names = [name for name, _bundle, _want in cases]
    gap = [name for name, _bundle in crosscheck._disclosure_rust_stricter_cases()]
    assert len(names + gap) == len(set(names + gap))
    by_exit = collections.Counter(want for _name, _bundle, want in cases)
    assert set(by_exit) == {0, 1, 2}
    assert sum(1 for name in names if name.startswith("positive:")) >= 5
    assert gap, "the named gap carries no vector, so a change of either parser would pass unseen"
