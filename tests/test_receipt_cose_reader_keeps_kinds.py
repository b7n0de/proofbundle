"""The statement reader judges the bytes: the verdict does not depend on which tags a decoder knows.

Step 1 of the check (Section 5.2.2 of the mappings draft) refuses what is not one well-formed data item in
the deterministic encoding (RFC 8949 sections 3 and 4.2.1), what is not valid under RFC 8949 section 5.3.1
(a text string that is not UTF-8, a map with two keys equal under the key equivalence of section 5.6.1, so
that 1 and true are two keys and 0.0 and -0.0 are one), and what is not a COSE_Sign1 (outer tag,
four-element array, element types). It does not check whether the content of a tag inside the COSE_Sign1
is valid for that tag (RFC 8949 section 5.3.2); the data items inside a tag are checked like any other data
item. Every header label of another kind than one of the five integers, and every value of the wrong type,
is step 2's case: outside_profile.

Before this test the reader decoded with cbor2 and judged Python values: a float, a simple value, a tag
or a key true beside the label 1 was malformed, and a tag with content cbor2 calls invalid was malformed
while one it does not know was outside_profile. The controls below are refused in step 1 before and after.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle import receipt_cose as rc

pytestmark = pytest.mark.skipif(importlib.util.find_spec("cbor2") is None,
                                reason="the [scitt] extra (cbor2) is not installed")

REPO = Path(__file__).resolve().parents[1]
COSE = json.loads((REPO / "tests" / "fixtures" / "receipt_cose" / "vectors.json").read_text(encoding="utf-8"))
DRAFT1 = json.loads((REPO / "tests" / "fixtures" / "signed_eval_receipt" / "draft1_vectors.json")
                    .read_text(encoding="utf-8"))
#: The Draft 1 PURE TEST seed of the issuer key, written out (tests/test_sdist_ohne_signierwerkzeug.py).
_DRAFT_TEST_SEED = b'#eR\x04\x10t\x8d\xe8w\x8bTD\x10\xb1W\x92\xfc\xf1t\xe0\xfb\xa4\x80j\x8c\x1a\xfb\xdb\xb0\x94k\x07'
ISSUER_KEY = Ed25519PrivateKey.from_private_bytes(_DRAFT_TEST_SEED)
ISSUER_PUB = ISSUER_KEY.public_key().public_bytes_raw()
PAIRS = [(COSE["issuer"], ISSUER_PUB)]
B1 = bytes.fromhex(next(v for v in COSE["backward"] if v["id"] == "B1")["statement_hex"])
#: B1 as written: tag 18 (d2), an array of four (84), the protected header as a byte string of 182 bytes
#: (58 b6), the empty unprotected header (a0), the 32-byte payload (58 20) and the signature (58 40).
PROTECTED = B1[4:4 + 182]
PAYLOAD = B1[4 + 182 + 1 + 2:4 + 182 + 1 + 2 + 32]


def _receipt_p1() -> bytes:
    import base64
    v = next(x for x in DRAFT1["vectors"] if x["id"] == "P1")
    b1 = DRAFT1["payloads"]["B1"]["text"].encode("utf-8")
    return v["receipt_text"].encode("utf-8").replace(b"@B1@", base64.b64encode(b1))


def _entries() -> list:
    """B1's protected header as its five (encoded label, encoded value) pairs, in B1's order; cbor2 only
    splits the header of a valid statement here, it judges nothing."""
    import cbor2
    return [(rc._enc(k), rc._enc(v)) for k, v in cbor2.loads(PROTECTED).items()]


def _map(pairs, order: str = "bytewise") -> bytes:
    if order == "bytewise":
        pairs = sorted(pairs)
    return rc._head(5, len(pairs)) + b"".join(k + v for k, v in pairs)


def _statement(protected: bytes, unprotected: bytes = b"\xa0") -> bytes:
    sig = ISSUER_KEY.sign(rc._sig_structure(protected, PAYLOAD))
    return rc._head(6, 18) + b"\x84" + rc._enc(protected) + unprotected + rc._enc(PAYLOAD) + rc._enc(sig)


def _check(statement: bytes) -> rc.StatementCheck:
    return rc.check_statement(statement, receipt=_receipt_p1(), receipt_key=ISSUER_PUB, statement_keys=PAIRS)


def _with(extra=(), replace=None) -> bytes:
    pairs = [(k, (replace[k] if replace and k in replace else v)) for k, v in _entries()]
    return _statement(_map(pairs + list(extra)))


def test_the_header_rebuilt_from_its_entries_is_b1():
    assert _map(_entries()) == PROTECTED
    assert _statement(PROTECTED) == B1
    assert _check(B1).status == rc.ACCEPTED


SIXTH_KEYS = [
    ("float 1.5, half precision", b"\xf9\x3e\x00"),
    ("float NaN, half precision", b"\xf9\x7e\x00"),
    ("false", b"\xf4"),
    ("true, beside the label 1", b"\xf5"),
    ("undefined", b"\xf7"),
    ("simple(16)", b"\xf0"),
    ("simple(32)", b"\xf8\x20"),
    ("tag 1 around 0", b"\xc1\x00"),
    ("tag 1 around a text, content not admissible for tag 1", b"\xc1\x61x"),
    ("tag 32 around a text", b"\xd8\x20\x61x"),
    ("tag 2 around one byte", b"\xc2\x41\x01"),
    ("tag 24 around an empty byte string", b"\xd8\x18\x40"),
]


@pytest.mark.parametrize("kind,key", SIXTH_KEYS, ids=[k for k, _ in SIXTH_KEYS])
def test_a_sixth_key_of_any_other_kind_is_outside_profile(kind, key):
    result = _check(_with(extra=[(key, b"\x00")]))
    assert (result.status, "fail-closed" in result.detail) == ("outside_profile", False), (kind, result.detail)


def test_the_arrays_of_1_and_of_true_are_two_keys():
    result = _check(_with(extra=[(b"\x81\x01", b"\x00"), (b"\x81\xf5", b"\x00")]))
    assert result.status == "outside_profile", result.detail


EQUAL_FLOAT_KEYS = [
    ("0.0 and -0.0, numerically equal", b"\xf9\x00\x00", b"\xf9\x80\x00"),
    ("two NaNs of the same significand, signs differ", b"\xf9\x7e\x00", b"\xf9\xfe\x00"),
    ("arrays of 0.0 and of -0.0", b"\x81\xf9\x00\x00", b"\x81\xf9\x80\x00"),
]


@pytest.mark.parametrize("what,first,second", EQUAL_FLOAT_KEYS, ids=[w for w, _, _ in EQUAL_FLOAT_KEYS])
def test_floats_equal_under_the_key_equivalence_are_one_key_and_malformed(what, first, second):
    """RFC 8949 section 5.6.1: -0.0 is equal to 0.0, and NaNs are equal when their significands are; two such
    keys are duplicates, so the map is not valid (section 5.3.1), although the two encodings differ."""
    result = _check(_with(extra=[(first, b"\x00"), (second, b"\x00")]))
    assert (result.status, "fail-closed" in result.detail) == ("malformed", False), (what, result.detail)


def test_two_nans_of_different_significands_are_two_keys():
    """RFC 8949 section 5.6.1: NaNs whose significands differ are distinct keys; the map is valid, step 2
    refuses the header (outside_profile)."""
    result = _check(_with(extra=[(b"\xf9\x7e\x00", b"\x00"), (b"\xf9\x7e\x01", b"\x00")]))
    assert (result.status, "fail-closed" in result.detail) == ("outside_profile", False), result.detail


WRONG_VALUES = [
    ("alg as tag 1 around -19", b"\x01", b"\xc1\x32"),
    ("payload hash algorithm as float -16.0", b"\x19\x01\x02", b"\xf9\xcc\x00"),
    ("preimage content type as tag 1 around a text", b"\x19\x01\x03", b"\xc1\x61x"),
    ("preimage content type as tag 32 around a text", b"\x19\x01\x03", b"\xd8\x20\x61x"),
    ("kid as tag 24 around its bytes", b"\x04", None),
]


@pytest.mark.parametrize("what,label,value", WRONG_VALUES, ids=[w for w, _, _ in WRONG_VALUES])
def test_a_value_of_the_wrong_type_is_outside_profile_whatever_a_tag_holds(what, label, value):
    if value is None:
        value = b"\xd8\x18" + dict(_entries())[label]
    result = _check(_with(replace={label: value}))
    assert (result.status, "fail-closed" in result.detail) == ("outside_profile", False), (what, result.detail)


def test_an_unprotected_header_with_a_float_key_is_outside_profile():
    result = _check(_statement(PROTECTED, unprotected=b"\xa1\xf9\x3e\x00\x00"))
    assert result.status == "outside_profile", result.detail


TAG_CONTENT_NOT_VALID = [
    ("a sixth key -1 whose value is tag 1 around a text of the one byte ff", [(b"\x20", b"\xc1\x61\xff")]),
    ("a sixth key that is tag 1 around a text of the one byte ff", [(b"\xc1\x61\xff", b"\x00")]),
    ("a sixth key -1 whose value is tag 32 around a map of the keys 0.0 and -0.0, in bytewise order and equal",
     [(b"\x20", b"\xd8\x20\xa2\xf9\x00\x00\x00\xf9\x80\x00\x00")]),
    ("a sixth key -1 whose value is tag 1 around the integer 1 written in two bytes", [(b"\x20", b"\xc1\x18\x01")]),
]


@pytest.mark.parametrize("what,extra", TAG_CONTENT_NOT_VALID, ids=[w for w, _ in TAG_CONTENT_NOT_VALID])
def test_the_data_items_inside_a_tag_are_checked_like_any_other_data_item(what, extra):
    """Step 1 does not check whether the content of a tag is valid for that tag (RFC 8949 section 5.3.2); the
    data items inside a tag are checked like any other data item, for validity under section 5.3.1 and for
    the deterministic encoding. A reader that skipped them would go on to step 2 (outside_profile)."""
    result = _check(_with(extra=extra))
    assert (result.status, "fail-closed" in result.detail) == ("malformed", False), (what, result.detail)


MALFORMED = [
    ("float 1.5 in single precision, not the shortest form", [(b"\xfa\x3f\xc0\x00\x00", b"\x00")]),
    ("float 1.5 in double precision, not the shortest form", [(b"\xfb\x3f\xf8\x00\x00\x00\x00\x00\x00", b"\x00")]),
    ("simple(16) in two bytes, not well-formed", [(b"\xf8\x10", b"\x00")]),
    ("tag 1 with a one-byte head, not the shortest form", [(b"\xd8\x01\x00", b"\x00")]),
    ("the integer 1 written in two bytes, not the shortest form", [(b"\x18\x01", b"\x00")]),
    ("a text that is not UTF-8", [(b"\x61\xff", b"\x00")]),
    ("an indefinite-length text", [(b"\x7f\x61x\xff", b"\x00")]),
    ("an indefinite-length map as a value", [(b"\x20", b"\xbf\xff")]),
    ("a lone break code", [(b"\xff", b"\x00")]),
    ("a reserved additional information", [(b"\x1c", b"\x00")]),
]


@pytest.mark.parametrize("what,extra", MALFORMED, ids=[w for w, _ in MALFORMED])
def test_what_is_not_well_formed_valid_and_deterministic_stays_malformed(what, extra):
    result = _check(_with(extra=extra))
    assert (result.status, "fail-closed" in result.detail) == ("malformed", False), (what, result.detail)


def test_two_equal_keys_are_malformed_and_so_is_a_map_out_of_order():
    entries = _entries()
    twice = _map(entries + [(b"\x20", b"\x00"), (b"\x20", b"\x01")])
    assert _check(_statement(twice)).status == "malformed"
    out_of_order = _map([(b"\x20", b"\x00")] + entries, order="as given")   # -1 (0x20) before 1 (0x01)
    result = _check(_statement(out_of_order))
    assert (result.status, "fail-closed" in result.detail) == ("malformed", False), result.detail


def test_a_byte_after_the_header_map_or_after_the_statement_is_malformed():
    assert _check(_statement(PROTECTED + b"\x00")).status == "malformed"
    assert _check(B1 + b"\x00").status == "malformed"


def test_the_cose_sign1_check_concerns_only_the_outer_tag_the_array_and_its_element_types():
    assert _check(b"\xd8\x62" + B1[1:]).status == "malformed"               # tag 98, not 18
    assert _check(B1[1:]).status == "outside_profile"                        # no tag
    assert _check(b"\xc1" + B1).status == "malformed"                        # tag 1 around the tagged item
    assert _check(_statement(b"")).status == "outside_profile"               # the empty header is the empty map
    assert _check(_statement(b"\xc1\xa0")).status == "malformed"             # a tag around the header map
    assert _check(_statement(b"\x80")).status == "malformed"                 # an array, not a map
