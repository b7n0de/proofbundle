"""A presented Disclosure stands at one place, or the SD-JWT is refused (6.6.1).

``verify_sd_jwt`` counts a Disclosure as committed when its digest stands under an ``_sd`` or a ``...`` key of the
issuer-signed payload, or of another committed Disclosure. It then places each Disclosure where its digest stands: a
``[salt, name, value]`` Disclosure in the object whose ``_sd`` list names it, a ``[salt, value]`` Disclosure at the
array position of its ``{"...": digest}``. Until this release it did not ask that every presented Disclosure was
placed. Two forms of a payload let a Disclosure be committed and stand nowhere: an object under ``_sd`` with an
``_sd`` of its own, and a ``...`` key in an object. Measured on 2026-11-23 on the tree that prepares 6.6.1: the
structure check passed for both, and a bundle whose SD-JWT presented a ``cnf`` Disclosure that way verified with no
Key Binding JWT. Only the issuer can write such a payload; a holder cannot make one without breaking the issuer
signature.

Only keys generated in this run.
"""
from __future__ import annotations

import base64
import functools
import hashlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import emit_bundle, generate_signer, verify_bundle
from proofbundle.sdjwt import verify_sd_jwt

_VCT = "https://example.test/vct"
_NO_PLACE = "no place"


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@functools.lru_cache(maxsize=None)
def _issuer():
    return ed25519.Ed25519PrivateKey.generate()


def _raw() -> bytes:
    return _issuer().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _claim(name: str, value) -> str:
    return _b64u(json.dumps(["c2FsdA", name, value]).encode())


def _element(value) -> str:
    return _b64u(json.dumps(["c2FsdA", value]).encode())


def _digest(disclosure: str) -> str:
    return _b64u(hashlib.sha256(disclosure.encode("ascii")).digest())


def _compact(claims: dict, presented) -> str:
    header = _b64u(json.dumps({"alg": "EdDSA", "typ": "dc+sd-jwt"}).encode())
    payload = _b64u(json.dumps({"iss": "https://issuer.example.test", "vct": _VCT, **claims}).encode())
    signature = _b64u(_issuer().sign(f"{header}.{payload}".encode("ascii")))
    return f"{header}.{payload}.{signature}~" + "".join(d + "~" for d in presented)


_CNF = _claim("cnf", {"kid": "holder-key-1"})
_NAME = _claim("given_name", "Ada")
_ITEM = _element("DE")
_UNDER_AN_ELLIPSIS = _claim("address", {"...": {"_sd": [_digest(_NAME)]}})


def _without_a_place() -> dict:
    """(claims, presented): each presented Disclosure is committed by digest and stands at no place."""
    return {
        "an-object-under-sd-with-an-sd-of-its-own": ({"_sd": {"_sd": [_digest(_NAME)]}}, [_NAME]),
        "the-same-with-a-cnf-claim": ({"_sd": {"_sd": [_digest(_CNF)]}}, [_CNF]),
        "an-ellipsis-key-in-the-payload-object": ({"...": _digest(_NAME)}, [_NAME]),
        "the-same-with-a-cnf-claim-under-the-ellipsis": ({"...": _digest(_CNF)}, [_CNF]),
        "an-ellipsis-key-in-a-nested-object": ({"holder": {"...": _digest(_CNF)}}, [_CNF]),
        "an-ellipsis-beside-another-key-in-an-array-element": (
            {"nationalities": [{"...": _digest(_ITEM), "note": "x"}]}, [_ITEM]),
        "one-placed-and-one-without-a-place": (
            {"_sd": [_digest(_NAME)], "extra": {"...": _digest(_CNF)}}, [_NAME, _CNF]),
        # A digest as text under one ellipsis key, and an `_sd` list that names it under the OBJECT value of another:
        # the first makes it count as committed, and a walk that descends into the second would call it placed.
        "committed-under-one-ellipsis-and-listed-under-the-object-of-another": (
            {"...": _digest(_NAME), "child": {"...": {"_sd": [_digest(_NAME)]}}}, [_NAME]),
        "the-same-mixed-form-with-a-cnf-claim": (
            {"...": _digest(_CNF), "child": {"...": {"_sd": [_digest(_CNF)]}}}, [_CNF]),
        "the-mixed-form-inside-a-disclosed-claim": (
            {"_sd": [_digest(_UNDER_AN_ELLIPSIS)], "...": _digest(_NAME)}, [_UNDER_AN_ELLIPSIS, _NAME]),
    }


def _placed_and_again_under_an_ellipsis() -> dict:
    """(claims, presented): the Disclosure stands at its place, and its digest stands a second time, in the form of
    a place, below a ``...`` key of an object. 6.6.0 walked below that key and refused the second place; the walk of
    this release does not, and until this case it lost the second occurrence with it (measured on 2026-11-23:
    refused at 6.6.0 from the package index, accepted on the tree that prepares 6.6.1)."""
    return {
        "in-a-list-under-an-ellipsis-key-of-the-payload": (
            {"_sd": [_digest(_NAME)], "...": [{"...": _digest(_NAME)}]}, [_NAME]),
        "in-a-list-under-an-ellipsis-key-of-a-nested-object": (
            {"_sd": [_digest(_NAME)], "x": {"...": [{"...": _digest(_NAME)}]}}, [_NAME]),
        "in-an-sd-list-under-an-ellipsis-key": (
            {"_sd": [_digest(_NAME)], "...": {"_sd": [_digest(_NAME)]}}, [_NAME]),
        "the-same-with-a-cnf-claim": (
            {"_sd": [_digest(_CNF)], "...": {"_sd": [_digest(_CNF)]}}, [_CNF]),
        "an-array-element-placed-and-again-under-an-ellipsis-key": (
            {"nationalities": [{"...": _digest(_ITEM)}], "x": {"...": [{"...": _digest(_ITEM)}]}}, [_ITEM]),
        "deeper-below-the-ellipsis-key": (
            {"_sd": [_digest(_NAME)], "...": {"a": [{"b": {"_sd": [_digest(_NAME)]}}]}}, [_NAME]),
    }


def _with_a_place() -> dict:
    """The controls: every presented Disclosure stands where its digest stands."""
    inner = _claim("street", "Main Street 1")
    outer = _claim("address", {"_sd": [_digest(inner)], "city": "Bonn"})
    return {
        "a-claim-in-the-payload-list": ({"_sd": [_digest(_NAME)]}, [_NAME]),
        "a-claim-in-a-nested-object": ({"holder": {"_sd": [_digest(_NAME)]}}, [_NAME]),
        "an-array-element": ({"nationalities": [{"...": _digest(_ITEM)}, "FR"]}, [_ITEM]),
        "a-claim-inside-a-disclosed-claim": ({"_sd": [_digest(outer)]}, [outer, inner]),
        "a-digest-nobody-presents": ({"_sd": [_digest(_NAME), _digest(_CNF)]}, [_NAME]),
        "nothing-presented-over-an-sd-that-is-an-object": ({"_sd": {"_sd": [_digest(_NAME)]}}, []),
        "the-same-disclosure-presented-twice": ({"_sd": [_digest(_NAME)]}, [_NAME, _NAME]),
        "an-array-placeholder-nobody-presents": ({"nationalities": [{"...": _digest(_ITEM)}, "FR"]}, []),
        # Below a `...` key the check reads what the walk of 6.6.0 read there, and that walk read nothing below an
        # `_sd` key but the text entries of an `_sd` list. A second occurrence it never saw passed in 6.6.0 and
        # passes here (measured on 2026-11-23 at 6.6.0 from the package index).
        "placed-and-again-below-an-sd-object-under-an-ellipsis-key": (
            {"_sd": [_digest(_NAME)], "...": {"_sd": {"_sd": [_digest(_NAME)]}}}, [_NAME]),
        "placed-and-again-below-an-sd-list-of-objects-under-an-ellipsis-key": (
            {"_sd": [_digest(_NAME)], "...": {"_sd": [{"_sd": [_digest(_NAME)]}]}}, [_NAME]),
        "an-array-element-placed-and-again-below-an-sd-object-under-an-ellipsis-key": (
            {"nationalities": [{"...": _digest(_ITEM)}], "x": {"...": {"_sd": {"a": [{"...": _digest(_ITEM)}]}}}}, [_ITEM]),
    }


@pytest.mark.parametrize("form", sorted(_without_a_place()))
def test_a_disclosure_that_stands_nowhere_fails_the_structure_check(form):
    claims, presented = _without_a_place()[form]
    verdict = verify_sd_jwt(_compact(claims, presented), _raw())
    assert verdict["sig_ok"] is True, (form, verdict)
    assert verdict["structure_ok"] is False and _NO_PLACE in verdict["detail"], (form, verdict)


@pytest.mark.parametrize("form", sorted(_without_a_place()))
def test_a_bundle_with_a_disclosure_that_stands_nowhere_does_not_verify(form):
    claims, presented = _without_a_place()[form]
    sd = {"compact": _compact(claims, presented), "issuer_public_key_b64": base64.b64encode(_raw()).decode("ascii")}
    result = verify_bundle(emit_bundle(b'{"generic":"vc"}', generate_signer(), sd_jwt_vc=sd))
    structure = [c.ok for c in result.checks if c.name == "sd-jwt-disclosures"]
    assert result.ok is False and structure == [False], (form, [(c.name, c.ok, c.detail) for c in result.checks])


@pytest.mark.parametrize("form", sorted(_placed_and_again_under_an_ellipsis()))
def test_a_second_occurrence_below_an_ellipsis_key_fails_the_structure_check(form):
    claims, presented = _placed_and_again_under_an_ellipsis()[form]
    verdict = verify_sd_jwt(_compact(claims, presented), _raw())
    assert verdict["sig_ok"] is True, (form, verdict)
    assert verdict["structure_ok"] is False and _NO_PLACE in verdict["detail"], (form, verdict)


@pytest.mark.parametrize("form", sorted(_placed_and_again_under_an_ellipsis()))
def test_a_bundle_with_a_second_occurrence_below_an_ellipsis_key_does_not_verify(form):
    claims, presented = _placed_and_again_under_an_ellipsis()[form]
    sd = {"compact": _compact(claims, presented), "issuer_public_key_b64": base64.b64encode(_raw()).decode("ascii")}
    result = verify_bundle(emit_bundle(b'{"generic":"vc"}', generate_signer(), sd_jwt_vc=sd))
    structure = [c.ok for c in result.checks if c.name == "sd-jwt-disclosures"]
    assert result.ok is False and structure == [False], (form, [(c.name, c.ok, c.detail) for c in result.checks])


@pytest.mark.parametrize("form", sorted(_with_a_place()))
def test_a_disclosure_that_stands_at_its_place_passes_the_structure_check_as_before(form):
    claims, presented = _with_a_place()[form]
    verdict = verify_sd_jwt(_compact(claims, presented), _raw())
    assert verdict["sig_ok"] is True and verdict["structure_ok"] is True, (form, verdict)
