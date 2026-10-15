"""Every strict CBOR reader of this repository refuses what is not one valid data item, and accepts what is.

The strict decoding rule of 2026-10-14: a duplicate map key, an encoding that is not
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
    ("a2f90000416af98000416b", "0.0 and -0.0"),
])
def test_distinct_data_items_that_would_be_one_dict_key_are_refused(hx, pair):
    """Two different data items that Python treats as one dict key: keeping one would be the silent merge."""
    with pytest.raises(CborInvalid) as exc:
        loads_strict_cbor(bytes.fromhex(hx))
    assert "collide as one dict key" in exc.value.reason, pair


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
])
def test_the_limits_hold(kwargs, hx):
    with pytest.raises(CborInvalid):
        loads_strict_cbor(bytes.fromhex(hx), **kwargs)


@pytest.mark.parametrize("kwargs, hx", [
    ({"max_bytes": 7}, "a2014161024162"),
    ({"max_depth": 3}, "818181" + "00"),
    ({"max_items": 3}, "83010203"),
])
def test_control_exactly_at_the_limit_is_read(kwargs, hx):
    loads_strict_cbor(bytes.fromhex(hx), **kwargs)


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
