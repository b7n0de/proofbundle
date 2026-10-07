"""A statement header in the deterministic encoding whose keys are not integers is outside_profile.

Step 1 of the check (Section 5.2.2 of the mappings draft) refuses what is not one well-formed and valid CBOR
data item in the deterministic encoding (malformed); step 2 refuses a header that does not hold exactly the
five integer labels (outside_profile). A key of another kind (a map, an array, a text or a byte string) is
still a valid, deterministically encoded data item, so it is step 2's case. Before this test the reader turned
a map or an array used as a key into an unhashable value, raised TypeError and reported malformed fail-closed.

The same holds where the reader meets a map inside the statement: the CWT Claims (label 15) and the
unprotected header. A header that is not in the deterministic encoding stays malformed, whatever its keys,
and a text string that is not valid UTF-8 (RFC 8949 section 5.3.1) is malformed.
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


def _receipt_p1() -> bytes:
    import base64
    v = next(x for x in DRAFT1["vectors"] if x["id"] == "P1")
    b1 = DRAFT1["payloads"]["B1"]["text"].encode("utf-8")
    return v["receipt_text"].encode("utf-8").replace(b"@B1@", base64.b64encode(b1))


def _b1_parts():
    import cbor2
    raw = bytes.fromhex(next(v for v in COSE["backward"] if v["id"] == "B1")["statement_hex"])
    protected, _unprotected, payload, _sig = cbor2.loads(raw).value
    pairs = [(rc._enc(k), rc._enc(v)) for k, v in cbor2.loads(protected).items()]
    return protected, pairs, payload


def _map(pairs, order="bytewise") -> bytes:
    """A CBOR map from encoded (key, value) pairs: bytewise order (RFC 8949 4.2.1) or length first
    (the canonical order of RFC 7049 section 3.9)."""
    if order == "bytewise":
        pairs = sorted(pairs)
    elif order == "length-first":
        pairs = sorted(pairs, key=lambda kv: (len(kv[0]), kv[0]))
    return rc._head(5, len(pairs)) + b"".join(k + v for k, v in pairs)


def _statement(protected: bytes, payload: bytes, unprotected: bytes = b"\xa0") -> bytes:
    sig = ISSUER_KEY.sign(rc._sig_structure(protected, payload))
    return (rc._head(6, 18) + rc._head(4, 4) + rc._enc(protected) + unprotected + rc._enc(payload)
            + rc._enc(sig))


def _check(statement: bytes) -> rc.StatementCheck:
    return rc.check_statement(statement, receipt=_receipt_p1(), receipt_key=ISSUER_PUB, statement_keys=PAIRS)


def test_b1_rebuilt_here_is_accepted():
    protected, pairs, payload = _b1_parts()
    assert _map(pairs) == protected
    assert _check(_statement(protected, payload)).status == rc.ACCEPTED


@pytest.mark.parametrize("kind,key", [("map", b"\xa0"), ("array", b"\x80"), ("text", b"\x61x"), ("bytes", b"\x40"),
                                      ("nested map", b"\xa1\xa0\x00"), ("array of a map", b"\x81\xa0")])
def test_a_sixth_protected_key_of_another_kind_is_outside_profile(kind, key):
    _protected, pairs, payload = _b1_parts()
    protected = _map(pairs + [(key, b"\x00")])
    result = _check(_statement(protected, payload))
    assert (result.status, "fail-closed" in result.detail) == ("outside_profile", False), (kind, result.detail)


def test_the_empty_array_and_the_empty_map_are_two_keys():
    _protected, pairs, payload = _b1_parts()
    protected = _map(pairs + [(b"\x80", b"\x00"), (b"\xa0", b"\x01")])
    result = _check(_statement(protected, payload))
    assert (result.status, "fail-closed" in result.detail) == ("outside_profile", False), result.detail


def test_a_cwt_claims_map_with_a_map_key_is_outside_profile():
    _protected, pairs, payload = _b1_parts()
    import cbor2
    claims = cbor2.loads(dict(pairs)[rc._enc(15)])
    claims_raw = _map([(rc._enc(k), rc._enc(v)) for k, v in claims.items()] + [(b"\xa0", b"\x00")])
    protected = _map([kv for kv in pairs if kv[0] != rc._enc(15)] + [(rc._enc(15), claims_raw)])
    result = _check(_statement(protected, payload))
    assert (result.status, "fail-closed" in result.detail) == ("outside_profile", False), result.detail


def test_an_unprotected_header_with_a_map_key_is_outside_profile():
    protected, _pairs, payload = _b1_parts()
    result = _check(_statement(protected, payload, unprotected=b"\xa1\xa0\x00"))
    assert (result.status, "fail-closed" in result.detail) == ("outside_profile", False), result.detail


def test_a_header_with_a_map_key_out_of_deterministic_order_stays_malformed():
    _protected, pairs, payload = _b1_parts()
    protected = rc._head(5, 6) + b"\xa0\x00" + b"".join(k + v for k, v in sorted(pairs))
    result = _check(_statement(protected, payload))
    assert (result.status, "fail-closed" in result.detail) == ("malformed", False), result.detail


def test_a_sixth_key_minus_1_in_length_first_order_is_malformed():
    """B45's construction: the order of RFC 7049 section 3.9 puts -1 (one byte) before 258 and 259 (three
    bytes); RFC 8949 section 4.2.1 orders the encoded keys bytewise, where 0x20 follows 0x19."""
    _protected, pairs, payload = _b1_parts()
    extra = pairs + [(rc._enc(-1), b"\x00")]
    assert _map(extra, "length-first") != _map(extra)
    assert _check(_statement(_map(extra, "length-first"), payload)).status == "malformed"
    assert _check(_statement(_map(extra), payload)).status == "outside_profile"


def test_an_iss_that_is_not_valid_utf8_is_malformed():
    """B43's construction: one byte of iss replaced by 0xff, which is no UTF-8 (RFC 8949 section 5.3.1)."""
    import cbor2
    _protected, pairs, payload = _b1_parts()
    claims = cbor2.loads(dict(pairs)[rc._enc(15)])
    iss = claims[1].encode("utf-8")
    bad = rc._head(3, len(iss)) + iss[:8] + b"\xff" + iss[9:]
    claims_raw = _map([(rc._enc(1), bad), (rc._enc(2), rc._enc(claims[2]))])
    protected = _map([kv for kv in pairs if kv[0] != rc._enc(15)] + [(rc._enc(15), claims_raw)])
    result = _check(_statement(protected, payload))
    assert result.status == "malformed", result.detail
