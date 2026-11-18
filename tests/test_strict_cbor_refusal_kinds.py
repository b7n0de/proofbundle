"""Which refusals of ``proofbundle._strict_cbor`` say "not read" and which say "not valid".

``CborUnrepresentable`` marks valid input that holds a map key the reader does not represent, ``CborBeyondLimits`` input
over its budget; every other refusal stays a plain ``CborInvalid``. Both are subclasses, so every caller that catches
``CborInvalid`` reads them as before, with the same reason. The reader of draft-gruszka-scitt-statement-identification-03
relies on the split: a refusal of one of the two subclasses gives no verdict, any other one means "not a statement".
The cases come from the shared corpus of every strict reader, so a new case there is classified here as well.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from proofbundle._strict_cbor import CborBeyondLimits, CborInvalid, CborUnrepresentable, loads_strict_cbor

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _strict_cbor_corpus import INVALID  # noqa: E402

#: The cases of the shared corpus that are valid CBOR this reader does not represent.
UNREPRESENTABLE = {"keys_1_and_1_0_collide", "keys_true_and_1_collide"}
#: The cases of the shared corpus that are over the default budget.
BEYOND_LIMITS = {"too_deep", "too_deep_indefinite_arrays", "too_deep_map_values", "too_deep_tags"}


@pytest.mark.parametrize("case", sorted(INVALID))
def test_each_refusal_of_the_corpus_has_its_kind(case):
    with pytest.raises(CborInvalid) as exc:
        loads_strict_cbor(bytes.fromhex(INVALID[case]))
    kind = type(exc.value)
    if case in UNREPRESENTABLE:
        assert kind is CborUnrepresentable
    elif case in BEYOND_LIMITS:
        assert kind is CborBeyondLimits
    else:
        assert kind is CborInvalid, f"{case} is refused as {kind.__name__}, which says it may be valid"


@pytest.mark.parametrize("hx, reason", [
    ("a1810101", "map key is an array, a map or a tag, which this reader does not represent"),
    ("a1c10101", "map key is an array, a map or a tag, which this reader does not represent"),
    ("a1f97e0001", "a NaN as map key, which this reader does not represent"),
    ("a2f40100416b", "map keys 0 and an earlier key are distinct CBOR data items that collide as one dict key"),
    ("a2f90000416a00416b", "map keys 0 and an earlier key are distinct CBOR data items that collide as one dict key"),
])
def test_valid_input_with_a_key_it_does_not_represent_is_unrepresentable(hx, reason):
    """false and 0, 0.0 and 0: distinct keys under RFC 8949 Section 5.6.1 that are one Python dict key."""
    with pytest.raises(CborUnrepresentable) as exc:
        loads_strict_cbor(bytes.fromhex(hx))
    assert exc.value.reason == reason


@pytest.mark.parametrize("kwargs, data", [
    ({"max_bytes": 3}, bytes.fromhex("a2014161024162")),
    ({"max_depth": 2}, bytes.fromhex("81818100")),
    ({"max_items": 2}, bytes.fromhex("83010203")),
    ({"max_items": 2}, bytes.fromhex("7f616161616161ff")),
])
def test_each_budget_is_beyond_limits(kwargs, data):
    with pytest.raises(CborBeyondLimits):
        loads_strict_cbor(data, **kwargs)


def test_control_a_duplicate_key_and_bytes_after_the_value_are_plain_refusals():
    for hx in ("a2014161014162", "a2f90000416af98000416b", "a1014161" + "00"):
        with pytest.raises(CborInvalid) as exc:
            loads_strict_cbor(bytes.fromhex(hx))
        assert type(exc.value) is CborInvalid, hx
