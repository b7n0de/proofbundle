"""The Sig_structure comparison in tools/scitt_ccf_datahash_vector compares BYTES, not lengths.

Finding `GLEICHE-LAENGE-IST-KEIN-NACHWEIS-GLEICHER-BYTES-01` (external review, 2026-09-25): the
recomputation recorded 109 bytes of Sig_structure per case and nothing across cases, and equal
length is no proof of equal bytes. These cases are hermetic: they use only material committed in
the tool directory (the D vector and the A and C bytes derived from it), no network and no
upstream fetch.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import sys

import pytest

TOOL = pathlib.Path(__file__).resolve().parents[1] / "tools" / "scitt_ccf_datahash_vector"


def _load():
    spec = importlib.util.spec_from_file_location("_nachrechnen_under_test", TOOL / "nachrechnen.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


N = _load()


def _committed_cases() -> dict[str, bytes]:
    """A, C and D from vektor_d.json alone: D is committed, A is D with a definite outer array."""
    d = bytes.fromhex(json.loads((TOOL / "vektor_d.json").read_text(encoding="utf-8"))
                      ["D_indefinite_array"]["hex"])
    assert d[:2] == b"\xd2\x9f" and d[-1:] == b"\xff"
    a = b"\xd2\x84" + d[2:-1]
    return {"A": a, "C": a[1:], "D": d}


def test_the_committed_cases_share_one_sig_structure():
    cases = _committed_cases()
    result = N.compare_sig_structures({k: N.sig_structure_bytes(b) for k, b in cases.items()})
    assert result["all_identical"] is True
    assert len(result["distinct_sha256"]) == 1


def test_equal_length_different_bytes_is_not_identical():
    one = bytes(109)
    other = bytes(108) + b"\x01"
    assert len(one) == len(other)
    assert N.compare_sig_structures({"x": one, "y": other})["all_identical"] is False


def test_a_single_case_compares_with_nothing_and_is_never_identical():
    assert N.compare_sig_structures({"only": bytes(109)})["all_identical"] is False


@pytest.mark.parametrize("flip", ["A", "C", "D"])
def test_a_flipped_protected_header_byte_breaks_the_equality(flip):
    probe = N.falling_probe(_committed_cases(), flip)
    assert probe["caught"] is True
    assert probe["all_identical_after_flip"] is False


def test_the_exit_code_follows_the_comparison_and_the_probe():
    row = {"size_trifft": True, "sha256_trifft": True, "signatur_aus_seed_reproduziert": True}
    assert N.exit_code([row], {"all_identical": True}, {"caught": True}) == 0
    assert N.exit_code([row], {"all_identical": False}, {"caught": True}) == 1
    assert N.exit_code([row], {"all_identical": True}, {"caught": False}) == 1
