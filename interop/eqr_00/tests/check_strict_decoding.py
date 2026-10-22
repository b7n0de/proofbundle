"""The strict decoding standard of 14 October 2026, rule 4, for this reader: a red test with a duplicated key and a
control with valid bytes, at every place the reader decodes JSON (the signed payload, the protected header, an
unprotected receipt), and the proof that these tests would see a lax decoder."""
from __future__ import annotations

import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [ROOT, os.path.join(ROOT, "vectors")]

import build  # noqa: E402
from eqr00 import wire  # noqa: E402
from eqr00.verify import verify  # noqa: E402

DUPLICATES = (
    ('"version": "1",', '"version": "1",\n  "version": "1",'),
    ('"status": "pass",', '"status": "fail",\n    "status": "pass",'),
    ('"class": "signed_invoice_record",', '"class": "model_summary",\n      "class": "signed_invoice_record",'),
)


def _with_duplicate(old, new):
    body = build.text(build.payload())
    assert body.count(old) == 1, old
    return body.replace(old, new, 1)


@pytest.mark.parametrize("old,new", DUPLICATES)
def test_RED_a_duplicated_member_in_the_signed_payload_is_refused(old, new):
    res = verify(build.jws_receipt_raw(_with_duplicate(old, new)), build.context())
    assert res["receipt_validity"] == "INVALID"
    assert "STRICT_DECODING" in {r["code"] for r in res["refusals"]}


@pytest.mark.parametrize("old,new", DUPLICATES)
def test_RED_a_duplicated_member_in_an_unprotected_receipt_is_refused(old, new):
    res = verify({"form": "json", "text": _with_duplicate(old, new)}, build.context(inter_domain=False))
    assert res["receipt_validity"] == "INVALID"
    assert "STRICT_DECODING" in {r["code"] for r in res["refusals"]}


def test_RED_a_duplicated_member_in_the_protected_header_is_refused():
    with pytest.raises(Exception):
        wire.decode_json(b'{"alg":"EdDSA","kid":"k1","kid":"k9"}')


def test_CONTROL_the_same_bytes_without_the_duplicate_verify():
    assert verify(build.jws_receipt_raw(build.text(build.payload())), build.context())["qualification"]["qualifies"]
    assert verify({"form": "json", "text": build.text(build.payload())},
                  build.context(inter_domain=False))["qualification"]["qualifies"]
    assert wire.decode_json(b'{"alg":"EdDSA","kid":"k1"}') == {"alg": "EdDSA", "kid": "k1"}


@pytest.mark.parametrize("raw,why", [
    (b"\xef\xbb\xbf{}", "byte order mark"),
    ('{"a":1}'.encode("utf-16"), "not UTF-8"),
    (b'{"a": NaN}', "NaN"),
    (b'{"a": Infinity}', "NaN or an infinity"),
    (b'{"a": 9007199254740992}', "I-JSON range"),
    (b'{"a": 1} {}', "strict JSON decoding refused"),
    (b'{"a": "\\ud800"}', "strict JSON decoding refused"),
])
def test_RED_what_the_strict_helper_lets_through_is_refused_in_front_of_it(raw, why):
    """proofbundle's loads_strict takes a BOM, UTF-16, NaN, the infinities and integers outside I-JSON (measured
    22.10.2026 at 07b6122c); the front of this reader refuses them, each with its reason."""
    with pytest.raises(wire.WireError, match=why):
        wire.decode_json(raw)


def test_META_the_tests_above_would_see_a_lax_decoder(monkeypatch):
    """With json.loads in place of the strict helper the duplicated member is taken (last value wins) and the
    receipt verifies; so the red tests above are not true of any decoder, only of a strict one."""
    monkeypatch.setattr(wire, "loads_strict", json.loads)
    old, new = DUPLICATES[1]
    res = verify(build.jws_receipt_raw(_with_duplicate(old, new)), build.context())
    assert res["receipt_validity"] == "VALID" and res["evaluation_status"] == "pass"
