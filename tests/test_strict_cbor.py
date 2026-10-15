"""Every strict CBOR reader of this repository refuses what is not one valid data item, and accepts what is.

The strict decoding rule stated in test_strict_decoding_guard.py: a duplicate map key, an encoding that is not
valid under RFC 8949 Section 5.3.1 and bytes after the one value are refused with a reason, fail-closed, by
every reader of checked, signed or evidential bytes. The corpus in ``_strict_cbor_corpus`` is shared, so the
three readers below cannot drift apart without one of them turning red:

* ``proofbundle._strict_cbor``, the helper next to ``_strict_json``;
* ``cbor_min`` of ``tools/scitt_ccf_datahash_vector``, which carries the recomputation of the data-hash vector;
* the checker of ``docs/scitt/statement_identification/package``, which reads with cbor2 behind its own
  pre-scan. It needs cbor2, which CI does not install, so that part skips there like the package's own tests;
  it is measured locally under cbor2 5.9.0 and 6.1.4.

Each refusal case has its control: the same reader accepts the valid corpus.
"""
from __future__ import annotations

import importlib.util
import math
import sys
from pathlib import Path

import pytest

from proofbundle._strict_cbor import (UNDEFINED, CborInvalid, Simple, Tag, load_item_strict,
                                      loads_strict_cbor)
from proofbundle.errors import BundleFormatError

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _strict_cbor_corpus import INVALID, VALID  # noqa: E402

REPO = Path(__file__).resolve().parents[1]


def _module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


CBOR_MIN = _module("_cbor_min_strict", REPO / "tools" / "scitt_ccf_datahash_vector" / "cbor_min.py")


def _without_framing(v):
    """cbor_min marks an indefinite container with `Unbestimmt`; the value under the mark is what is compared."""
    if isinstance(v, CBOR_MIN.Unbestimmt):
        return _without_framing(v.wert)
    if isinstance(v, list):
        return [_without_framing(x) for x in v]
    if isinstance(v, dict):
        return {k: _without_framing(x) for k, x in v.items()}
    return v


def _helper(b: bytes):
    return loads_strict_cbor(b)


def _cbor_min(b: bytes):
    return _without_framing(CBOR_MIN.load_exactly_one(b))


READERS = {"strict_cbor": (_helper, (CborInvalid,)),
           "cbor_min": (_cbor_min, (ValueError,))}

if importlib.util.find_spec("cbor2") is not None:
    import cbor2

    _PACKAGE = _module("_statement_package_verify",
                       REPO / "docs" / "scitt" / "statement_identification" / "package" / "verify.py")

    def _package(b: bytes):
        end = _PACKAGE.item_end(b, 0)
        if end != len(b):
            raise _PACKAGE.Malformed("trailing bytes")
        return cbor2.loads(b)

    READERS["statement_package"] = (_package, (ValueError, cbor2.CBORDecodeError))


@pytest.mark.parametrize("reader", sorted(READERS))
@pytest.mark.parametrize("case", sorted(VALID))
def test_every_reader_accepts_valid_cbor(reader, case):
    read, _errors = READERS[reader]
    hx, expected = VALID[case]
    assert read(bytes.fromhex(hx)) == expected


@pytest.mark.parametrize("reader", sorted(READERS))
@pytest.mark.parametrize("case", sorted(INVALID))
def test_every_reader_refuses_invalid_cbor(reader, case):
    read, errors = READERS[reader]
    with pytest.raises(errors):
        read(bytes.fromhex(INVALID[case]))


def test_the_reason_names_the_duplicate_key_and_its_offset():
    with pytest.raises(CborInvalid) as exc:
        loads_strict_cbor(bytes.fromhex("a2014161014162"))
    assert exc.value.reason == "duplicate map key 1"
    assert exc.value.offset == 4
    assert isinstance(exc.value, BundleFormatError)


def test_bytes_after_the_value_name_their_count_and_offset():
    with pytest.raises(CborInvalid) as exc:
        loads_strict_cbor(bytes.fromhex("a10141610000"))
    assert exc.value.reason == "2 byte(s) after the data item"
    assert exc.value.offset == 4


@pytest.mark.parametrize("hx, pair", [
    ("a201416af93c00416b", "1 and 1.0"),
    ("a2f5416a01416b", "true and 1"),
])
def test_distinct_data_items_that_would_be_one_dict_key_are_refused(hx, pair):
    """Two different data items that Python treats as one dict key: keeping one would be the silent merge."""
    with pytest.raises(CborInvalid) as exc:
        loads_strict_cbor(bytes.fromhex(hx))
    assert "collide as one dict key" in exc.value.reason, pair


@pytest.mark.parametrize("hx", ["a2f90000416af98000416b", "a2fb000000000000000001f9800002", "a2f93c0001fa3f80000002"])
def test_numerically_equal_floats_are_one_key(hx):
    """RFC 8949 Section 5.6.1: numeric values are distinct unless numerically equal, and -0.0 is equal to 0.0."""
    with pytest.raises(CborInvalid) as exc:
        loads_strict_cbor(bytes.fromhex(hx))
    assert exc.value.reason.startswith("duplicate map key")


@pytest.mark.parametrize("hx", ["a1f97e0001", "a2f97e0001f9fe0002", "a2f97e0101fa7fc0200002", "a1fb7ff800000000000101"])
def test_a_nan_as_map_key_is_refused_not_compared(hx):
    """NaN keys are equal when their significands are (RFC 8949 Section 5.6.1). A decoded half-precision NaN does not keep
    its significand, so comparing would say equal where the RFC says distinct and the reverse; the key is refused."""
    with pytest.raises(CborInvalid) as exc:
        loads_strict_cbor(bytes.fromhex(hx))
    assert exc.value.reason == "a NaN as map key, which this reader does not represent"


def test_control_a_nan_as_value_is_read():
    assert math.isnan(loads_strict_cbor(bytes.fromhex("a101f97e00"))[1])


def test_control_distinct_keys_without_a_collision_both_stay():
    assert loads_strict_cbor(bytes.fromhex("a201416a6131416b")) == {1: b"j", "1": b"k"}


def test_a_tagged_array_is_a_list_under_any_library():
    """cbor2 6 returns a tagged array as a tuple, cbor2 5 as a list; this reader returns a list either way."""
    value = loads_strict_cbor(bytes.fromhex("d28401020304"))
    assert value == Tag(18, [1, 2, 3, 4])
    assert type(value.value) is list


def test_simple_values_floats_and_undefined_have_fixed_types():
    assert loads_strict_cbor(bytes.fromhex("f7")) is UNDEFINED
    assert loads_strict_cbor(bytes.fromhex("f0")) == Simple(16)
    assert loads_strict_cbor(bytes.fromhex("f820")) == Simple(32)
    assert loads_strict_cbor(bytes.fromhex("f93e00")) == 1.5
    assert loads_strict_cbor(bytes.fromhex("fa3fc00000")) == 1.5
    assert loads_strict_cbor(bytes.fromhex("fb3ff8000000000000")) == 1.5
    assert math.isnan(loads_strict_cbor(bytes.fromhex("f97e00")))


def test_an_array_as_a_map_key_is_refused():
    with pytest.raises(CborInvalid) as exc:
        loads_strict_cbor(bytes.fromhex("a1810101"))
    assert "does not represent" in exc.value.reason


@pytest.mark.parametrize("kwargs, hx", [
    ({"max_bytes": 3}, "a2014161024162"),
    ({"max_depth": 2}, "818181" + "00"),
    ({"max_items": 2}, "83010203"),
    ({"max_items": 2}, "9f010203ff"),
    ({"max_items": 1}, "bf01010202ff"),
    ({"max_items": 2}, "5f414141414141ff"),
    ({"max_items": 2}, "7f616161616161ff"),
])
def test_the_limits_hold(kwargs, hx):
    with pytest.raises(CborInvalid):
        loads_strict_cbor(bytes.fromhex(hx), **kwargs)


@pytest.mark.parametrize("kwargs, hx", [
    ({"max_bytes": 7}, "a2014161024162"),
    ({"max_depth": 3}, "818181" + "00"),
    ({"max_items": 3}, "83010203"),
    ({"max_items": 3}, "9f010203ff"),
    ({"max_items": 2}, "bf01010202ff"),
    ({"max_items": 3}, "5f414141414141ff"),
    ({"max_items": 3}, "7f616161616161ff"),
])
def test_control_exactly_at_the_limit_is_read(kwargs, hx):
    loads_strict_cbor(bytes.fromhex(hx), **kwargs)


def test_without_arguments_the_three_limits_are_those_of_the_default_budget(monkeypatch):
    """The defaults are DEFAULT_BUDGET.input_bytes, .json_depth and .json_nodes, each on its own axis. A small budget
    with three different numbers stands in for the default, so a swap of two axes changes a verdict here, and no test
    load is built from a budget value (the rule of test_lauf11_l3_testlast_ist_gedeckelt)."""
    import dataclasses  # noqa: PLC0415

    from proofbundle import budget  # noqa: PLC0415

    monkeypatch.setattr(budget, "DEFAULT_BUDGET",
                        dataclasses.replace(budget.DEFAULT_BUDGET, input_bytes=40, json_depth=3, json_nodes=5))
    with pytest.raises(CborInvalid) as exc:
        loads_strict_cbor(b"\x00" * 41)
    assert exc.value.reason == "input of 41 bytes exceeds 40"
    assert loads_strict_cbor(b"\x58\x26" + b"\x00" * 38) == b"\x00" * 38
    with pytest.raises(CborInvalid) as exc:
        loads_strict_cbor(b"\x86" + b"\x00" * 6)
    assert exc.value.reason == "more than 5 array elements, map pairs and string chunks"
    assert loads_strict_cbor(b"\x85" + b"\x00" * 5) == [0] * 5
    with pytest.raises(CborInvalid) as exc:
        loads_strict_cbor(b"\x81" * 4 + b"\x00")
    assert exc.value.reason == "nesting deeper than 3"
    assert loads_strict_cbor(b"\x81" * 3 + b"\x00") == [[[0]]]
    for start, empty in ((b"\x5f", b"\x40"), (b"\x7f", b"\x60")):
        with pytest.raises(CborInvalid) as exc:
            loads_strict_cbor(start + empty * 6 + b"\xff")
        assert exc.value.reason == "more than 5 array elements, map pairs and string chunks"
        assert loads_strict_cbor(start + empty * 5 + b"\xff") in (b"", "")


def test_the_chunks_of_an_indefinite_string_count_against_the_default_budget():
    """Without this, 8 MiB of empty chunks were read inside the byte budget (4 s, about 740 MiB, measured
    2026-10-15). The load is capped at HARTER_LASTDECKEL; the value itself is asserted, so a larger default fails here
    on the assertion and not on the memory of the run."""
    from _lastdeckel import HARTER_LASTDECKEL  # noqa: PLC0415

    from proofbundle.budget import DEFAULT_BUDGET  # noqa: PLC0415

    assert DEFAULT_BUDGET.json_nodes <= HARTER_LASTDECKEL
    n = min(DEFAULT_BUDGET.json_nodes, HARTER_LASTDECKEL)
    for start, empty in ((b"\x5f", b"\x40"), (b"\x7f", b"\x60")):
        with pytest.raises(CborInvalid) as exc:
            loads_strict_cbor(start + empty * (n + 1) + b"\xff")
        assert exc.value.reason.startswith(f"more than {n} ")
        assert loads_strict_cbor(start + empty * n + b"\xff") in (b"", "")


@pytest.mark.parametrize("hx", ["7f61c361bcff", "7f61e2618261acff"])
def test_a_code_point_spread_between_chunks_is_refused_at_the_chunk(hx):
    """RFC 8949 Section 3.2.3: if any chunk of an indefinite text string is invalid, the string is invalid."""
    with pytest.raises(CborInvalid) as exc:
        loads_strict_cbor(bytes.fromhex(hx))
    assert exc.value.reason == "a chunk of an indefinite text string is not valid UTF-8 on its own"
    assert exc.value.offset == 1


@pytest.mark.parametrize("hx, value", [
    ("a2f001f102", {Simple(16): 1, Simple(17): 2}),
    ("a2f401f502", {False: 1, True: 2}),
    ("a2f601f702", {None: 1, UNDEFINED: 2}),
])
def test_control_different_simple_values_are_different_keys(hx, value):
    assert loads_strict_cbor(bytes.fromhex(hx)) == value


@pytest.mark.parametrize("hx", ["a2f001f002", "a2f401f402", "a2f701f702", "a2f82001f82002"])
def test_the_same_simple_value_twice_is_a_duplicate_key(hx):
    with pytest.raises(CborInvalid) as exc:
        loads_strict_cbor(bytes.fromhex(hx))
    assert exc.value.reason.startswith("duplicate map key")


@pytest.mark.parametrize("hx, strict_reason, cbor_min_words", [
    ("4561", "string runs past the end of the input", "runs past the end of the input"),
    ("4261", "string runs past the end of the input", "runs past the end of the input"),
    ("7f6461626364", "input ends inside an indefinite string", "input ends inside an indefinite string"),
    ("19ff", "input ends inside a head", "input ends inside the head"),
    ("830102", "array declares more elements than bytes remain", "declares more elements than bytes remain"),
    ("a201", "map declares more pairs than bytes remain", "declares more pairs than bytes remain"),
])
def test_a_cut_item_is_refused_where_it_is_cut_not_by_the_end_check(hx, strict_reason, cbor_min_words):
    """Read one item WITHOUT the end check: each cut must be refused by its own rule. Through loads_strict_cbor a
    missing rule would still end red, through the end check with the wrong reason, so the corpus alone cannot tell."""
    with pytest.raises(CborInvalid) as exc:
        load_item_strict(bytes.fromhex(hx))
    assert exc.value.reason == strict_reason
    with pytest.raises(ValueError, match=cbor_min_words):
        CBOR_MIN.lade(bytes.fromhex(hx), 0)


@pytest.mark.parametrize("hx, words", [
    ("ff", "outside an indefinite container"),
    ("a1c00101", "is not an integer, a text string or a byte string"),
    ("a1810101", "is not an integer, a text string or a byte string"),
])
def test_cbor_min_names_a_break_alone_and_a_key_it_does_not_represent(hx, words):
    with pytest.raises(ValueError, match=words):
        CBOR_MIN.lade(bytes.fromhex(hx), 0)


def test_the_package_checker_never_lets_cbor2_merge_two_pairs_into_one():
    """cbor2 builds one dict key from two pairs whose keys are equal in Python, and which keys those are depends on the
    version: under cbor2 5.9.0 the simple value 5 equals the array [5], under 6.1.4 it does not (measured 2026-10-15).
    The checker must either refuse such a map or get back a map with as many entries as it has pairs."""
    cbor2 = pytest.importorskip("cbor2")
    for hx in ("a2e501810502", "a201416af93c00416b", "a2f5416a01416b", "a2f90000416af98000416b", "a2014161024162"):
        data = bytes.fromhex(hx)
        try:
            _PACKAGE.item_end(data, 0)
        except _PACKAGE.Malformed:
            continue
        assert len(cbor2.loads(data)) == 2, hx


def test_one_item_from_an_offset_and_its_end():
    data = bytes.fromhex("01" + "a1014161" + "02")
    assert load_item_strict(data, 1) == ({1: b"a"}, 5)


@pytest.mark.parametrize("offset", [-1, 7, True])
def test_an_offset_outside_the_input_is_refused(offset):
    with pytest.raises(CborInvalid):
        load_item_strict(bytes.fromhex("a1014161"), offset)


@pytest.mark.parametrize("given", ["a0", ["a0"], None])
def test_only_bytes_are_read(given):
    with pytest.raises(CborInvalid):
        loads_strict_cbor(given)
