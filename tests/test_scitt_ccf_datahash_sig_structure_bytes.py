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
    assert probe["all_identical_before_flip"] is True
    assert probe["all_identical_after_flip"] is False


def _sign1(protected: bytes, payload: bytes) -> bytes:
    """A tagged COSE_Sign1 with an empty unprotected map and a zero signature, for probe edges."""
    def bstr(b: bytes) -> bytes:
        return N.C.kopf_bytes(2, len(b)) + b
    return b"\xd2\x84" + bstr(protected) + b"\xa0" + bstr(payload) + bstr(bytes(64))


PROTECTED = b"\xa1\x01\x27"


def test_a_difference_that_existed_before_the_flip_is_not_caught():
    """A review lens found this on 2026-09-25: "broke after the flip" alone was reported as caught."""
    probe = N.falling_probe({"X": _sign1(PROTECTED, b"one"), "Y": _sign1(PROTECTED, b"two")}, "X")
    assert probe["all_identical_before_flip"] is False
    assert probe["caught"] is False


@pytest.mark.parametrize("protected", [PROTECTED, b"\xaa" * 170])
def test_the_flip_position_comes_from_the_structure_not_from_a_search(protected):
    """The protected bytes also appear in the payload, and a self-similar header (a lens case)."""
    raw = _sign1(protected, b"p" + protected)
    at = N._last_protected_byte(raw)
    head = len(N.C.kopf_bytes(2, len(protected)))
    assert at == 2 + head + len(protected) - 1
    probe = N.falling_probe({"X": raw, "Y": raw}, "X")
    assert probe["caught"] is True
    assert f"byte {at} " in probe["flipped"]


@pytest.mark.parametrize("cases,flip,reason", [
    ({"X": _sign1(b"", b"p"), "Y": _sign1(b"", b"p")}, "X", "empty protected header"),
    ({"X": _sign1(PROTECTED, b"p")}, "X", "at least one other case"),
    ({"X": _sign1(PROTECTED, b"p"), "X (flipped)": _sign1(PROTECTED, b"p")}, "X",
     "already exists"),
])
def test_a_probe_whose_preconditions_do_not_hold_raises_instead_of_reporting(cases, flip, reason):
    with pytest.raises(ValueError, match=reason):
        N.falling_probe(cases, flip)


def test_the_exit_code_follows_the_comparison_and_the_probe():
    row = {"size_trifft": True, "sha256_trifft": True, "signatur_aus_seed_reproduziert": True}
    assert N.exit_code([row], {"all_identical": True}, {"caught": True}) == 0
    assert N.exit_code([row], {"all_identical": False}, {"caught": True}) == 1
    assert N.exit_code([row], {"all_identical": True}, {"caught": False}) == 1
