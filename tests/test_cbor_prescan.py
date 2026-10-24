"""The structural pre-scan of the scitt-ccf/v1 reader (ADR 0009, Decision 8). Standard library only.

Every refusal below sits next to a control that the same scan accepts, and every limit is probed at
L and L+1, so a scan that refused everything or accepted everything fails here.
"""
from __future__ import annotations

import pytest

from proofbundle._cbor_prescan import CborRefused, Tag, encode_head, no_tags, scan

BIG = 1 << 20


def _s(data: bytes, **kw):
    kw.setdefault("max_bytes", BIG)
    return scan(data, **kw)


def test_control_a_map_of_everything_the_profile_reads():
    # {1: -7, "a": h'00', 2: [true, false, null], 3: "x"}
    data = bytes.fromhex("a40126616141000283f5f4f6036178")
    v = _s(data).value
    assert v == {1: -7, "a": b"\x00", 2: [True, False, None], 3: "x"}


@pytest.mark.parametrize("hexdata, why", [
    ("9f0102ff", "indefinite length"),
    ("5f4100ff", "indefinite length"),
    ("1801", "shortest form"),
    ("190001", "shortest form"),
    ("5801aa", "shortest form"),
    ("f93c00", "float"),
    ("fb3ff0000000000000", "float"),
    ("f7", "simple value 23"),
    ("a201010102", "duplicate map key"),
    ("a1f501", "neither an integer nor a text string"),
    ("a14100f6", "neither an integer nor a text string"),
    ("0102", "trailing"),
    ("62ff00", "UTF-8"),
    ("1c", "reserved additional information"),
    ("590100", "runs past the end"),
    ("9bffffffffffffffff", "more elements than bytes remain"),
])
def test_each_refusal_names_its_reason(hexdata, why):
    with pytest.raises(CborRefused) as ei:
        _s(bytes.fromhex(hexdata))
    assert why in str(ei.value)


def test_depth_limit_at_l_and_l_plus_one():
    at = b"\x81" * 16 + b"\x00"
    over = b"\x81" * 17 + b"\x00"
    assert _s(at, max_depth=16).value is not None
    with pytest.raises(CborRefused, match="nesting deeper"):
        _s(over, max_depth=16)


def test_byte_limit_counts_bytes_at_l_and_l_plus_one():
    data = encode_head(2, 100) + b"\x00" * 100          # 102 bytes
    assert _s(data, max_bytes=102).value == b"\x00" * 100
    with pytest.raises(CborRefused, match="exceeds"):
        _s(data, max_bytes=101)


def test_a_multibyte_text_string_is_limited_by_bytes_not_characters():
    text = "é" * 40                                   # 40 characters, 80 bytes
    data = encode_head(3, 80) + text.encode("utf-8")
    assert len(data) == 82
    assert _s(data, max_bytes=82).value == text
    with pytest.raises(CborRefused):
        _s(data, max_bytes=81)


def test_tags_only_where_the_policy_allows_them():
    tagged = bytes.fromhex("d28440a0f640")
    with pytest.raises(CborRefused, match="tag 18"):
        _s(tagged)
    sc = _s(tagged, tag_allowed=lambda path, n: path == () and n == 18)
    assert isinstance(sc.value, Tag) and sc.value.number == 18
    assert sc.tagged_with == 18 and len(sc.element_spans) == 4


@pytest.mark.parametrize("hexdata", [
    "c11a5f5e1000",            # tag 1
    "c24101",                  # tag 2 bignum
    "d81841f6",                # tag 24
    "82d81c8101d81d00",        # tags 28/29 shared references
    "d901008243616263d81900",  # tags 256/25 string references
    "d9d9f701",                # tag 55799
    "da0001869f01",            # an unregistered tag
])
def test_the_tags_cbor2_interprets_by_default_are_refused_by_default(hexdata):
    with pytest.raises(CborRefused, match="not allowed"):
        _s(bytes.fromhex(hexdata), tag_allowed=no_tags)


def test_tag_1_must_wrap_an_integer_and_tag_18_an_array():
    allow_all = lambda path, n: True  # noqa: E731
    assert _s(bytes.fromhex("c11a5f5e1000"), tag_allowed=allow_all).value == Tag(1, 1600000000)
    with pytest.raises(CborRefused, match="tag 1 must wrap an integer"):
        _s(bytes.fromhex("c16178"), tag_allowed=allow_all)
    with pytest.raises(CborRefused, match="tag 18 must wrap an array"):
        _s(bytes.fromhex("d2a0"), tag_allowed=allow_all)


def test_element_spans_point_at_the_bytes_as_served():
    data = bytes.fromhex("d28443a10126a0f64100")
    sc = _s(data, tag_allowed=lambda p, n: p == () and n == 18)
    assert [data[a:b].hex() for a, b in sc.element_spans] == ["43a10126", "a0", "f6", "4100"]


@pytest.mark.parametrize("bad", [None, 1, "text", [b"x"], {"a": 1}])
def test_not_bytes_is_a_typed_refusal(bad):
    with pytest.raises(CborRefused, match="not bytes"):
        scan(bad, max_bytes=BIG)


@pytest.mark.parametrize("n", [0, 23, 24, 255, 256, 65535, 65536, (1 << 32) - 1, 1 << 32])
def test_encode_head_is_shortest_and_scans_back(n):
    head = encode_head(0, n)
    assert _s(head).value == n
