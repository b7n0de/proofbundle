"""The TRACE v0.2 Trust Record verifier, held to the specification it was written from.

INDEPENDENCE. Nothing here imports ``agentrust_trace`` or ``trace_tests``; the last test reads this
file and the module and fails if either ever does. Every record below is built by this file's own
signer from fixed seeds, so the vectors are reproducible without the TRACE reference and without
network. The comparison against the reference lives in ``interop/trace/`` and runs outside the suite.

WHAT EACH GROUP PINS, with the section of ``spec/trace-v0.2.md`` (trace-spec at a131c640) it reads:
the binding forms and algorithms (3.2, 3.2.1, 3.2.2), the canonical-form binding (3.2.2), the cnf
binding (3.2.2), the profile cutover ("Changes from v0.1", 3.3), the schema and the 3.1 rules,
freshness (3.2.2), relying-party expectations (3.2.2 nonce, 3.3 step 5), and the exit contract.
"""
from __future__ import annotations

import ast
import base64
import copy
import json
from pathlib import Path

import pytest
import rfc8785
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from proofbundle.adapters.trace_record import (
    NOT_CHECKED,
    SPEC_PIN,
    TRACE_PROFILE_V0_2,
    exit_code,
    jwk_thumbprint,
    verify_trace_record,
)
from proofbundle.cli import main

NOW = 1792000000
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


ED = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
ED_OTHER = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
P256 = ec.derive_private_key(0x1F2E3D4C5B6A79881726354453627180A9B8C7D6E5F40312233445566778899A, ec.SECP256R1())
P384 = ec.derive_private_key(
    0x0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20212223242526272829, ec.SECP384R1())


def ed_jwk(key=ED) -> dict:
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "x": b64(raw)}


def ec_jwk(key) -> dict:
    n = 32 if isinstance(key.curve, ec.SECP256R1) else 48
    nums = key.public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256" if n == 32 else "P-384",
            "x": b64(nums.x.to_bytes(n, "big")), "y": b64(nums.y.to_bytes(n, "big"))}


KEYS = {"EdDSA": (ED, ed_jwk()), "ES256": (P256, ec_jwk(P256)), "ES384": (P384, ec_jwk(P384))}


def record(jwk: dict, **changes) -> dict:
    rec = {
        "eat_profile": TRACE_PROFILE_V0_2,
        "iat": NOW - 60,
        "subject": "spiffe://trust.example.org/agent/payments/prod",
        "model": {"provider": "example-provider", "model_id": "example-model", "version": "20251001",
                  "weights_digest": "sha256:" + "a3" * 32},
        "runtime": {"platform": "software-only", "measurement": "sha384:" + "c9" * 48,
                    "nonce": "challenge-1"},
        "policy": {"bundle_hash": "sha256:" + "b2" * 32, "enforcement_mode": "enforce", "version": "1.2.0"},
        "data_class": "confidential",
        "tool_transcript": {"hash": "sha256:" + "d4" * 32, "call_count": 3,
                            "transcript_uri": "https://registry.example.org/transcript/1"},
        "build_provenance": {"slsa_level": 2, "builder": "https://builder.example.org",
                             "digest": "sha256:" + "e5" * 32},
        "appraisal": {"status": "none", "verifier": "https://verifier.example.org"},
        "transparency": "https://registry.example.org/claim/1",
        "cnf": {"jwk": copy.deepcopy(jwk)},
    }
    rec.update(changes)
    return rec


def embedded(rec: dict, key=ED) -> bytes:
    body = {k: v for k, v in rec.items() if k != "signature"}
    signed = dict(body, signature=b64(key.sign(rfc8785.dumps(body))))
    return json.dumps(signed, ensure_ascii=False).encode("utf-8")


def ecdsa_raw(key, data: bytes) -> bytes:
    n = 32 if isinstance(key.curve, ec.SECP256R1) else 48
    r, s = decode_dss_signature(key.sign(data, ec.ECDSA(hashes.SHA256() if n == 32 else hashes.SHA384())))
    return r.to_bytes(n, "big") + s.to_bytes(n, "big")


def jws(rec: dict, alg: str = "EdDSA", key=None, header: dict | None = None,
        payload: bytes | None = None, raw_header: bytes | None = None) -> bytes:
    key = key if key is not None else KEYS.get(alg, (ED,))[0]
    h = b64(raw_header if raw_header is not None else
            json.dumps(header if header is not None else {"alg": alg}, separators=(",", ":")).encode())
    p = b64(payload if payload is not None else rfc8785.dumps(rec))
    signing_input = (h + "." + p).encode("ascii")
    if isinstance(key, Ed25519PrivateKey):
        sig = key.sign(signing_input)
    else:
        sig = ecdsa_raw(key, signing_input)
    return (h + "." + p + "." + b64(sig)).encode("ascii")


def verify(data, keys=None, **kw):
    kw.setdefault("now", NOW)
    return verify_trace_record(data, trusted_keys=keys if keys is not None else [ed_jwk()], **kw)


def failed(verdict) -> list:
    return [c.name for c in verdict.result.checks if c.ok is not True]


# ----------------------------------------------------------------------------------------------
# The two binding forms and the three algorithms (3.2, 3.2.1, 3.2.2).
# ----------------------------------------------------------------------------------------------

def test_embedded_ed25519_record_verifies():
    v = verify(embedded(record(ed_jwk())))
    assert exit_code(v) == 0 and v.ok
    assert v.form == "embedded" and v.alg == "EdDSA"
    assert v.profile == TRACE_PROFILE_V0_2 and v.accepted_profiles == (TRACE_PROFILE_V0_2,)
    assert v.trusted_key_thumbprint == jwk_thumbprint(ed_jwk())


@pytest.mark.parametrize("alg", ["EdDSA", "ES256", "ES384"])
def test_compact_jws_verifies_for_each_permitted_alg(alg):
    key, jwk = KEYS[alg]
    v = verify(jws(record(jwk), alg, key), keys=[jwk])
    assert exit_code(v) == 0, failed(v)
    assert v.form == "jws-compact" and v.alg == alg


def test_es256_second_spelling_verifies_like_the_first():
    """Both (r, s) and (r, n - s) verify, the house rule for ES256 (finding D1, 2026-09-26)."""
    token = jws(record(ec_jwk(P256)), "ES256", P256)
    h, p, s = token.decode().split(".")
    sig = base64.urlsafe_b64decode(s + "==")
    other = sig[:32] + (P256_N - int.from_bytes(sig[32:], "big")).to_bytes(32, "big")
    flipped = f"{h}.{p}.{b64(other)}".encode()
    assert exit_code(verify(token, keys=[ec_jwk(P256)])) == 0
    assert exit_code(verify(flipped, keys=[ec_jwk(P256)])) == 0


@pytest.mark.parametrize("alg", ["none", "None", "NONE"])
def test_alg_none_is_refused_before_anything_else(alg):
    token = (b64(json.dumps({"alg": alg}).encode()) + "." + b64(rfc8785.dumps(record(ed_jwk()))) + ".x").encode()
    v = verify(token)
    assert exit_code(v) == 2 and failed(v) == ["jws-header"]


@pytest.mark.parametrize("alg", ["HS256", "RS256", "PS256", "ES512", "Ed25519", "", 1, None])
def test_an_alg_outside_the_three_is_refused(alg):
    v = verify(jws(record(ed_jwk()), header={"alg": alg}, key=ED))
    assert exit_code(v) == 2 and "jws-header" in failed(v)


def test_header_without_alg_is_refused():
    v = verify(jws(record(ed_jwk()), header={"typ": "JWT"}, key=ED))
    assert exit_code(v) == 2


@pytest.mark.parametrize("extra", [{"crit": ["exp"]}, {"b64": False}, {"jwk": ed_jwk()}, {"x5c": ["AA"]},
                                   {"jku": "https://x.example"}, {"cty": "JWT"}, {"zzz": 1}])
def test_a_header_member_this_profile_does_not_read_is_refused_and_named(extra):
    v = verify(jws(record(ed_jwk()), header=dict({"alg": "EdDSA"}, **extra), key=ED))
    assert exit_code(v) == 2 and "jws-header" in failed(v)
    name = next(iter(extra))
    assert (f"header.{name}", False) in v.unknown_fields


def test_typ_and_kid_are_read_and_do_not_select_the_key():
    v = verify(jws(record(ed_jwk()), header={"alg": "EdDSA", "typ": "JWT", "kid": "not-a-trusted-kid"}, key=ED))
    assert exit_code(v) == 0


def test_an_embedded_ecdsa_record_is_not_verifiable_here_and_says_so():
    v = verify(embedded(record(ed_jwk())), keys=[ec_jwk(P256)])
    assert exit_code(v) == 2 and "verifier-config" in failed(v)


def test_the_es384_primitive_verifies_and_never_raises():
    from proofbundle.signature import verify_ecdsa_p384

    nums = P384.public_key().public_numbers()
    point = b"\x04" + nums.x.to_bytes(48, "big") + nums.y.to_bytes(48, "big")
    sig = ecdsa_raw(P384, b"message")
    assert verify_ecdsa_p384(point, sig, b"message") is True
    assert verify_ecdsa_p384(point, sig, b"messagf") is False
    assert verify_ecdsa_p384(point, bytes([sig[0] ^ 1]) + sig[1:], b"message") is False
    assert verify_ecdsa_p384(b"\x04" + bytes(96), sig, b"message") is False          # not on the curve
    for bad in (None, 1, "x", [], point[:-1], b"\x02" + point[1:49]):
        assert verify_ecdsa_p384(bad, sig, b"message") is False
        assert verify_ecdsa_p384(point, bad, b"message") is False
    assert verify_ecdsa_p384(point, sig, None) is False


# ----------------------------------------------------------------------------------------------
# Keys come from the relying party; the record's cnf must name the verifying key (3.2.2).
# ----------------------------------------------------------------------------------------------

def test_a_record_signed_by_another_key_fails():
    other = ed_jwk(ED_OTHER)
    assert exit_code(verify(embedded(record(other), ED_OTHER))) == 1
    assert exit_code(verify(jws(record(other), key=ED_OTHER))) == 1


def test_the_record_cannot_supply_its_own_trust():
    """Signed by ED_OTHER and naming ED_OTHER in cnf: internally consistent, and still refused."""
    v = verify(embedded(record(ed_jwk(ED_OTHER)), ED_OTHER), keys=[ed_jwk()])
    assert exit_code(v) == 1 and failed(v) == ["signature"]


def test_cnf_naming_a_different_key_fails_the_binding():
    v = verify(embedded(record(ed_jwk(ED_OTHER)), ED))
    assert exit_code(v) == 1 and failed(v) == ["cnf-binding"]
    v = verify(jws(record(ed_jwk(ED_OTHER)), key=ED))
    assert exit_code(v) == 1 and failed(v) == ["cnf-binding"]


def test_alg_confusion_between_key_types_fails():
    """An EdDSA signature presented as ES256 against a relying party holding only a P-256 key."""
    good = jws(record(ec_jwk(P256)), "EdDSA", ED).decode().split(".")
    header = b64(json.dumps({"alg": "ES256"}).encode())
    v = verify(f"{header}.{good[1]}.{good[2]}".encode(), keys=[ec_jwk(P256)])
    assert exit_code(v) == 1 and failed(v) == ["signature"]
    v = verify(jws(record(ed_jwk()), "EdDSA", ED), keys=[ec_jwk(P256)])
    assert exit_code(v) == 1 and failed(v) == ["signature"]
    v = verify(jws(record(ec_jwk(P384)), "ES384", P384), keys=[ec_jwk(P256)])
    assert exit_code(v) == 1


def test_a_cnf_jwk_member_outside_the_schema_is_reported_and_permitted():
    jwk = dict(ed_jwk(), use="sig", alg="EdDSA")
    v = verify(embedded(record(jwk)))
    assert exit_code(v) == 0
    assert ("cnf.jwk.use", True) in v.unknown_fields and ("cnf.jwk.alg", True) in v.unknown_fields


@pytest.mark.parametrize("kty", [[], {}, ["OKP"], {"a": 1}, None, 1])
def test_an_unhashable_or_foreign_kty_is_a_failing_check_not_a_raise(kty):
    jwk = dict(ed_jwk(), kty=kty)
    v = verify(embedded(record(jwk)))
    assert exit_code(v) == 1 and "cnf-binding" in failed(v) and "structure" in failed(v)
    v = verify(jws(record(ed_jwk()), header={"alg": [kty] if kty is not None else []}, key=ED))
    assert exit_code(v) == 2 and failed(v) == ["jws-header"]


def test_a_cnf_jwk_carrying_private_key_material_fails():
    jwk = dict(ed_jwk(), d=b64(bytes(32)))
    v = verify(embedded(record(jwk)))
    assert exit_code(v) == 1 and "cnf-binding" in failed(v) and "structure" in failed(v)


@pytest.mark.parametrize("bad", [
    [], None, {}, "key", [{"kty": "OKP", "crv": "Ed25519", "x": "AA"}],
    [dict(ed_jwk(), d=b64(bytes(32)))],
    [{"kty": "OKP", "crv": "Ed25519", "x": b64(bytes(32))}],               # the low-order identity point
    [{"kty": "EC", "crv": "P-256", "x": b64(bytes(32)), "y": b64(bytes(32))}],  # not on the curve
    [{"kty": "RSA", "n": "AQAB", "e": "AQAB"}],
    [{"kty": "oct", "k": "AAAA"}],
])
def test_unusable_trust_material_is_exit_2_and_reads_nothing(bad):
    for data in (embedded(record(ed_jwk())), jws(record(ec_jwk(P256)), "ES256", P256),
                 jws(record(ed_jwk()), "EdDSA", ED)):
        v = verify_trace_record(data, trusted_keys=bad, now=NOW)
        assert exit_code(v) == 2 and failed(v) == ["verifier-config"]


@pytest.mark.parametrize("kw", [
    {"accepted_profiles": ["tag:agentrust.io,2026:trace-v0.1"]},
    {"accepted_profiles": [TRACE_PROFILE_V0_2, "tag:agentrust.io,2026:trace-v0.1"]},
    {"accepted_profiles": ["tag:example.org,2026:other"]},
    {"accepted_profiles": []},
    {"accepted_profiles": TRACE_PROFILE_V0_2},
    {"max_age_seconds": None}, {"max_age_seconds": -1}, {"max_age_seconds": True},
    {"max_future_skew_seconds": -5}, {"now": True}, {"now": 1.5},
    {"expected_policy_hashes": ["sha256:abc"]}, {"expected_policy_hashes": []},
    {"expected_policy_hashes": "sha256:" + "b2" * 32},
    {"expected_transcript_hash": "md5:00"}, {"expected_subjects": []}, {"expected_nonce": 7},
])
def test_an_unusable_relying_party_configuration_is_refused(kw):
    v = verify(embedded(record(ed_jwk())), **kw)
    assert exit_code(v) == 2 and failed(v) == ["verifier-config"]


# ----------------------------------------------------------------------------------------------
# Every signed field changed once fails the signature (3.2.2).
# ----------------------------------------------------------------------------------------------

def _leaves(obj, path=()):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _leaves(v, path + (k,))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _leaves(v, path + (i,))
    else:
        yield path


def _changed(value):
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return value + 1
    return value[:-1] + ("0" if value[-1:] != "0" else "1")


def _mutate(rec, path):
    out = copy.deepcopy(rec)
    cur = out
    for step in path[:-1]:
        cur = cur[step]
    cur[path[-1]] = _changed(cur[path[-1]])
    return out


BASE = record(ed_jwk())
LEAVES = [p for p in _leaves(BASE)]


@pytest.mark.parametrize("path", LEAVES, ids=[".".join(map(str, p)) for p in LEAVES])
def test_every_signed_field_changed_once_fails_embedded(path):
    good = json.loads(embedded(BASE))
    tampered = _mutate(good, path)
    v = verify(json.dumps(tampered).encode())
    assert exit_code(v) == 1 and "signature" in failed(v)


@pytest.mark.parametrize("path", LEAVES, ids=[".".join(map(str, p)) for p in LEAVES])
def test_every_signed_field_changed_once_fails_jws(path):
    h, _, s = jws(BASE).decode().split(".")
    p = b64(rfc8785.dumps(_mutate(BASE, path)))
    v = verify(f"{h}.{p}.{s}".encode())
    assert exit_code(v) == 1 and "signature" in failed(v)


def test_a_member_added_after_signing_fails():
    good = json.loads(embedded(BASE))
    good["data_class"] = "public"
    assert exit_code(verify(json.dumps(good).encode())) == 1
    good = json.loads(embedded(BASE))
    good["references"] = [{"rel": "behavior-trace", "id": "x", "resolver": "https://r.example"}]
    assert exit_code(verify(json.dumps(good).encode())) == 1


def test_the_signature_value_itself_changed_fails():
    good = json.loads(embedded(BASE))
    sig = base64.urlsafe_b64decode(good["signature"] + "==")
    good["signature"] = b64(bytes([sig[0] ^ 1]) + sig[1:])
    assert exit_code(verify(json.dumps(good).encode())) == 1


# ----------------------------------------------------------------------------------------------
# Canonical form and the signature member (3.2.2).
# ----------------------------------------------------------------------------------------------

def test_a_jws_payload_that_is_not_the_canonical_form_fails():
    rec = record(ed_jwk())
    for payload in (json.dumps(rec).encode(), json.dumps(rec, sort_keys=True, indent=1).encode(),
                    rfc8785.dumps(rec).replace(b'"iat":%d' % (NOW - 60), b'"iat":%d.0' % (NOW - 60))):
        v = verify(jws(rec, payload=payload))
        assert exit_code(v) == 1 and failed(v) == ["canonical-payload"], payload[:40]


def test_a_jws_payload_carrying_a_signature_member_fails():
    rec = dict(record(ed_jwk()), signature=b64(bytes(64)))
    v = verify(jws(rec))
    assert exit_code(v) == 1 and "structure" in failed(v)


def test_an_embedded_record_without_signature_fails():
    v = verify(json.dumps(record(ed_jwk())).encode())
    assert exit_code(v) == 1 and failed(v) == ["signature"]


def test_a_non_canonical_base64url_signature_fails():
    good = json.loads(embedded(BASE))
    sig = good["signature"]
    last = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    respelled = sig[:-1] + last[last.index(sig[-1]) + 1]       # same bytes, a non-zero unused bit
    for spelled in (respelled, sig + "==", sig.replace("-", "+").replace("_", "/")):
        if spelled == sig:
            continue
        bad = dict(good, signature=spelled)
        v = verify(json.dumps(bad).encode())
        assert exit_code(v) == 1 and "signature" in failed(v)


def test_a_number_is_decided_by_value_in_the_embedded_form():
    rec = record(ed_jwk())
    text = embedded(rec).decode().replace(f'"iat": {NOW - 60}', f'"iat": {NOW - 60}.0')
    assert f'"iat": {NOW - 60}.0' in text
    assert exit_code(verify(text.encode())) == 0
    text = embedded(rec).decode().replace(f'"iat": {NOW - 60}', '"iat": 1.79199994e9')
    assert exit_code(verify(text.encode())) == 0


def test_a_fractional_integer_member_fails():
    good = json.loads(embedded(BASE))
    good["build_provenance"]["slsa_level"] = 1.5
    assert exit_code(verify(json.dumps(good).encode())) == 1


@pytest.mark.parametrize("literal", ["9007199254740992", "1e21", "-9007199254740992", "9.007199254740993e15"])
def test_an_integer_outside_the_safe_range_has_no_canonical_form(literal):
    text = embedded(BASE).decode().replace('"call_count": 3', f'"call_count": {literal}')
    v = verify(text.encode())
    assert exit_code(v) == 2 and failed(v) == ["readable"]


@pytest.mark.parametrize("literal", ["NaN", "Infinity", "-Infinity", "1e400"])
def test_a_non_finite_number_is_not_json_here(literal):
    text = embedded(BASE).decode().replace('"call_count": 3', f'"call_count": {literal}')
    v = verify(text.encode())
    assert exit_code(v) == 2 and failed(v) == ["readable"]


# ----------------------------------------------------------------------------------------------
# Reading: duplicate members, encodings, the JWS shape. All exit 2.
# ----------------------------------------------------------------------------------------------

def test_a_duplicate_member_is_refused_at_every_place():
    text = embedded(BASE).decode()
    assert exit_code(verify(text.replace('"data_class": "confidential"',
                                         '"data_class": "confidential", "data_class": "public"').encode())) == 2
    assert exit_code(verify(text.replace('"enforcement_mode": "enforce"',
                                         '"enforcement_mode": "enforce", "enforcement_mode": "silent"').encode())) == 2
    canonical = rfc8785.dumps(BASE)
    doubled = canonical.replace(b'"data_class":"confidential"', b'"data_class":"confidential","data_class":"x"')
    assert exit_code(verify(jws(BASE, payload=doubled))) == 2
    assert exit_code(verify(jws(BASE, raw_header=b'{"alg":"EdDSA","alg":"ES256"}'))) == 2


@pytest.mark.parametrize("data", [
    b"", b"   ", b"[1,2]", b"null", b"a.b", b"a.b.c.d", b"a..c", b"\xff\xfe{}",
    "﻿{}".encode("utf-8"), '{"a":"\\ud800"}'.encode(), "{\"a\": \"\xe9\"}".encode("latin-1"),
])
def test_unreadable_bytes_are_exit_2(data):
    v = verify(data)
    assert exit_code(v) == 2 and failed(v) == ["readable"]


def test_a_parsed_object_is_refused():
    v = verify(json.loads(embedded(BASE)))
    assert exit_code(v) == 2


def test_a_jws_segment_with_padding_or_a_foreign_alphabet_is_refused():
    h, p, s = jws(BASE).decode().split(".")
    for token in (f"{h}=.{p}.{s}", f"{h}.{p}.{s}=", f"{h}.{p}.{s.replace('-', '+')}" if "-" in s else f"{h}.{p}+.{s}",
                  f" {h}.{p}.{s}", f"{h}.{p}.{s}\n"):
        assert exit_code(verify(token.encode())) == 2, token[-8:]


# ----------------------------------------------------------------------------------------------
# Profile and structure (3.1, 3.3, the pinned schema). All exit 1.
# ----------------------------------------------------------------------------------------------

def test_the_v01_profile_is_refused():
    v = verify(embedded(record(ed_jwk(), eat_profile="tag:agentrust.io,2026:trace-v0.1")))
    assert exit_code(v) == 1 and "profile" in failed(v) and v.profile is None


@pytest.mark.parametrize("member", ["eat_profile", "iat", "subject", "model", "runtime", "policy",
                                    "data_class", "build_provenance", "appraisal", "cnf"])
def test_every_required_member_is_required(member):
    rec = record(ed_jwk())
    del rec[member]
    v = verify(embedded(rec))
    assert exit_code(v) == 1


@pytest.mark.parametrize("member", ["tool_transcript", "transparency"])
def test_members_the_schema_leaves_optional_may_be_absent(member):
    rec = record(ed_jwk())
    del rec[member]
    assert exit_code(verify(embedded(rec))) == 0


@pytest.mark.parametrize("path,value", [
    (("exp",), NOW + 3600), (("iss",), "x"), (("runtime", "quote"), "AAAA"),
    (("policy", "rules"), []), (("appraisal", "extra"), True), (("cnf", "kid"), "k1"),
    (("model", "license"), "MIT"),
])
def test_an_unknown_member_is_reported_and_refused(path, value):
    rec = record(ed_jwk())
    cur = rec
    for step in path[:-1]:
        cur = cur[step]
    cur[path[-1]] = value
    v = verify(embedded(rec))
    assert exit_code(v) == 1 and "structure" in failed(v)
    assert (".".join(path), False) in v.unknown_fields


@pytest.mark.parametrize("changes", [
    {"iat": 1699999999},
    {"subject": "https://not-a-workload"},
    {"subject": "spiffe://trust.example.org/agent\n"},
    {"runtime": {"platform": "z80", "measurement": "sha256:" + "a" * 64}},
    {"runtime": {"platform": "intel-tdx", "measurement": "sha256:" + "A" * 64}},
    {"policy": {"bundle_hash": "sha512:" + "b" * 128, "enforcement_mode": "enforce"}},
    {"policy": {"bundle_hash": "sha256:" + "b" * 64, "enforcement_mode": "off"}},
    {"data_class": 5},
    {"build_provenance": {"slsa_level": 4, "digest": "sha256:" + "e" * 64}},
    {"appraisal": {"status": "affirming", "verifier": "not a uri"}},
    {"appraisal": {"status": "none", "verifier": "https://v.example", "method": "re-execution"}},
    {"appraisal": {"status": "none", "verifier": "https://v.example",
                   "re_execution": {"outcome": "reproduced"}}},
    {"transparency": ""},
    {"references": [{"rel": "", "id": "x", "resolver": "r"}]},
    {"references": [{"rel": "a", "id": "x", "resolver": "r", "retention": "P1Y2X"}]},
    {"origin": {"kind": "imported", "producer": "siem"}},
])
def test_a_schema_violation_fails(changes):
    v = verify(embedded(record(ed_jwk(), **changes)), now=changes.get("iat", NOW))
    assert exit_code(v) == 1 and failed(v) == ["structure"], v.result.checks


def test_origin_not_self_needs_software_only_and_holds_with_it():
    rec = record(ed_jwk(), origin={"kind": "third-party-control-plane", "producer": "vendor-x"})
    rec["runtime"]["platform"] = "intel-tdx"
    assert exit_code(verify(embedded(rec))) == 1
    rec["runtime"]["platform"] = "software-only"
    assert exit_code(verify(embedded(rec))) == 0


def test_platform_measurement_rules_of_section_3_1_5():
    pm = {"measurement": "sha384:" + "c9" * 48, "layers": {"pcr:0": {"outcome": "established"}}}
    rec = record(ed_jwk(), appraisal={"status": "warning", "verifier": "https://v.example", "platform_measurement": pm})
    rec["runtime"]["platform"] = "tpm2"
    assert exit_code(verify(embedded(rec))) == 0
    bad = copy.deepcopy(rec)
    bad["appraisal"]["platform_measurement"]["measurement"] = "sha384:" + "00" * 48
    assert exit_code(verify(embedded(bad))) == 1
    bad = copy.deepcopy(rec)
    bad["appraisal"]["platform_measurement"]["layers"] = {"pcr:24": {"outcome": "established"}}
    assert exit_code(verify(embedded(bad))) == 1
    bad = copy.deepcopy(rec)
    bad["appraisal"]["status"] = "none"
    assert exit_code(verify(embedded(bad))) == 1
    bad = copy.deepcopy(rec)
    bad["appraisal"]["platform_measurement"]["layers"] = {"pcr:1": {"outcome": "not-established"}}
    assert exit_code(verify(embedded(bad))) == 1
    bad["appraisal"]["platform_measurement"]["layers"]["pcr:1"]["reason"] = "layer-not-measured"
    assert exit_code(verify(embedded(bad))) == 0
    bad["appraisal"]["platform_measurement"]["layers"]["pcr:1"]["reason"] = None
    assert exit_code(verify(embedded(bad))) == 1


@pytest.mark.parametrize("uri,ok", [
    ("https://v.example.org/a?b=c#d", True), ("urn:uuid:1234", True), ("mailto:", True),
    ("https://[::1]:8443/x", True), ("https://[v1.fe]/", True), ("https://[::1%eth0]/", False),
    ("https://[zz::1]/", False), ("https://v.example.org/a b", False), ("//v.example.org", False),
    ("relative/path", False), ("https://v.example.org/é", False), ("https://v.example.org/%zz", False),
    ("1http://x", False),
])
def test_uri_members_follow_rfc_3986(uri, ok):
    rec = record(ed_jwk(), appraisal={"status": "none", "verifier": uri})
    assert (exit_code(verify(embedded(rec))) == 0) is ok


# ----------------------------------------------------------------------------------------------
# The relying party's window and expectations (3.2.2, 3.3 step 5). All exit 3 when unmet.
# ----------------------------------------------------------------------------------------------

def test_freshness_window_edges():
    rec = record(ed_jwk(), iat=NOW - 86400)
    assert exit_code(verify(embedded(rec))) == 0
    rec = record(ed_jwk(), iat=NOW - 86401)
    v = verify(embedded(rec))
    assert exit_code(v) == 3 and failed(v) == ["freshness"]
    rec = record(ed_jwk(), iat=NOW + 300)
    assert exit_code(verify(embedded(rec))) == 0
    rec = record(ed_jwk(), iat=NOW + 301)
    v = verify(embedded(rec))
    assert exit_code(v) == 3 and failed(v) == ["freshness"]


def test_the_window_is_the_relying_partys():
    rec = record(ed_jwk(), iat=NOW - 600)
    assert exit_code(verify(embedded(rec), max_age_seconds=599)) == 3
    assert exit_code(verify(embedded(rec), max_age_seconds=600)) == 0
    assert exit_code(verify(embedded(rec), now=NOW - 600 - 86401)) == 3     # iat far in that clock's future


def test_the_clock_is_the_default():
    rec = record(ed_jwk(), iat=NOW - 60)
    v = verify_trace_record(embedded(rec), trusted_keys=[ed_jwk()])
    assert exit_code(v) == 3 and failed(v) == ["freshness"]


def test_nonce():
    data = embedded(record(ed_jwk()))
    assert exit_code(verify(data, expected_nonce="challenge-1")) == 0
    v = verify(data, expected_nonce="challenge-2")
    assert exit_code(v) == 3 and failed(v) == ["nonce"] and v.policy == "FAIL"
    rec = record(ed_jwk())
    del rec["runtime"]["nonce"]
    assert exit_code(verify(embedded(rec), expected_nonce="challenge-1")) == 3


def test_policy_hash():
    data = embedded(record(ed_jwk()))
    v = verify(data, expected_policy_hashes=["sha256:" + "b2" * 32])
    assert exit_code(v) == 0 and v.policy == "OK"
    v = verify(data, expected_policy_hashes=["sha256:" + "b3" * 32, "sha384:" + "b2" * 48])
    assert exit_code(v) == 3 and failed(v) == ["policy-hash"] and v.policy == "FAIL"


def test_transcript_hash():
    data = embedded(record(ed_jwk()))
    assert exit_code(verify(data, expected_transcript_hash="sha256:" + "d4" * 32)) == 0
    v = verify(data, expected_transcript_hash="sha256:" + "d5" * 32)
    assert exit_code(v) == 3 and failed(v) == ["transcript-hash"]
    rec = record(ed_jwk())
    del rec["tool_transcript"]
    assert exit_code(verify(embedded(rec), expected_transcript_hash="sha256:" + "d4" * 32)) == 3


def test_an_expectation_compares_any_record_value_without_raising():
    rec = record(ed_jwk())
    rec["tool_transcript"]["hash"] = "sha256:\u00e9" + "d4" * 31
    rec["runtime"]["nonce"] = "\u00e9\U0001F600"
    v = verify(embedded(rec), expected_transcript_hash="sha256:" + "d4" * 32, expected_nonce="challenge-1")
    assert exit_code(v) == 1 and "structure" in failed(v) and "transcript-hash" in failed(v)
    v = verify(embedded(record(ed_jwk())), expected_nonce="\ud800")
    assert exit_code(v) == 2 and failed(v) == ["verifier-config"]


def test_subject_scope():
    data = embedded(record(ed_jwk()))
    assert exit_code(verify(data, expected_subjects=["spiffe://trust.example.org/agent/payments/prod"])) == 0
    v = verify(data, expected_subjects=["spiffe://trust.example.org/agent/payments/dev"])
    assert exit_code(v) == 3 and failed(v) == ["subject"]


def test_an_integrity_failure_dominates_an_unmet_expectation():
    good = json.loads(embedded(record(ed_jwk(), iat=NOW - 90000)))
    good["policy"]["bundle_hash"] = "sha256:" + "ff" * 32
    v = verify(json.dumps(good).encode(), expected_policy_hashes=["sha256:" + "b2" * 32])
    assert exit_code(v) == 1
    assert not any(c.name in ("freshness", "policy-hash") for c in v.result.checks)


# ----------------------------------------------------------------------------------------------
# What a pass is not.
# ----------------------------------------------------------------------------------------------

def test_a_verified_record_is_never_safe_for_automation():
    data = embedded(record(ed_jwk()))
    v = verify(data, expected_nonce="challenge-1", expected_policy_hashes=["sha256:" + "b2" * 32],
               expected_subjects=["spiffe://trust.example.org/agent/payments/prod"],
               expected_transcript_hash="sha256:" + "d4" * 32)
    assert exit_code(v) == 0 and v.policy == "OK"
    assert v.automation["safeForAutomation"] is False
    assert v.automation["automationBlockers"] == ["REFERENCES_NOT_RESOLVED"]
    plain = verify(data)
    assert plain.automation["safeForAutomation"] is False
    assert plain.automation["automationBlockers"] == ["POLICY_NOT_EVALUATED", "REFERENCES_NOT_RESOLVED"]


def test_the_verdict_names_what_was_not_checked_and_the_revision():
    d = verify(embedded(record(ed_jwk()))).as_dict()
    assert d["not_checked"] == list(NOT_CHECKED)
    assert d["revocation"] == "NOT_EVALUATED"
    assert d["specification"]["commit"] == SPEC_PIN["commit"]
    assert any("revocation" in item for item in d["not_checked"])


def test_the_profile_is_reported_only_for_a_verified_record():
    good = json.loads(embedded(BASE))
    good["data_class"] = "x"
    v = verify(json.dumps(good).encode())
    assert v.profile is None and v.accepted_profiles == (TRACE_PROFILE_V0_2,)


def test_never_raises_on_hostile_shapes():
    for data in (b"{" * 200 + b"}" * 200, b"[" * 100000, b"a." * 50000, b"\x00" * 10,
                 json.dumps({"eat_profile": {"a": [1, {"b": None}]}, "cnf": []}).encode()):
        assert exit_code(verify(data)) in (1, 2)


# ----------------------------------------------------------------------------------------------
# The command line.
# ----------------------------------------------------------------------------------------------

def _cli(tmp_path, data: bytes, *extra, keys=None):
    rec_path = tmp_path / "record"
    rec_path.write_bytes(data)
    key_path = tmp_path / "key.json"
    key_path.write_text(json.dumps(keys if keys is not None else ed_jwk()))
    return main(["verify-trace", str(rec_path), "--key", str(key_path), "--now", str(NOW), *extra])


def test_cli_exit_codes(tmp_path, capsys):
    data = embedded(record(ed_jwk()))
    assert _cli(tmp_path, data) == 0
    out = capsys.readouterr().out
    assert "POLICY: NOT_EVALUATED" in out and "safeForAutomation=false" in out and "REVOCATION: NOT_EVALUATED" in out
    good = json.loads(data)
    good["data_class"] = "x"
    assert _cli(tmp_path, json.dumps(good).encode()) == 1
    assert _cli(tmp_path, b"not a record") == 2
    assert _cli(tmp_path, data, "--policy-hash", "sha256:" + "00" * 32) == 3
    assert _cli(tmp_path, jws(record(ed_jwk())) + b"\n") == 0
    assert _cli(tmp_path, data, keys={"keys": [ec_jwk(P256), ed_jwk()]}) == 0
    assert _cli(tmp_path, data, keys={"keys": []}) == 2


@pytest.mark.parametrize("content", ["null", " null", "[]", "{}", '""', "0", "false", '{"keys": []}',
                                     '{"keys": null}', ""])
def test_cli_a_key_file_that_reads_as_absent_is_refused(tmp_path, content):
    rec_path = tmp_path / "record"
    rec_path.write_bytes(embedded(record(ed_jwk())))
    key_path = tmp_path / "key.json"
    key_path.write_text(content)
    assert main(["verify-trace", str(rec_path), "--key", str(key_path), "--now", str(NOW)]) == 2


def test_cli_json(tmp_path, capsys):
    assert _cli(tmp_path, embedded(record(ed_jwk())), "--json") == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["exit_code"] == 0 and doc["profile"] == TRACE_PROFILE_V0_2
    assert doc["automation"]["safeForAutomation"] is False


def test_cli_neutralises_control_characters_from_the_record(tmp_path, capsys):
    rec = record(ed_jwk())
    rec["x\nPOLICY: OK"] = 1
    assert _cli(tmp_path, embedded(rec)) == 1
    out = capsys.readouterr().out
    assert "\nPOLICY: OK" not in out


# ----------------------------------------------------------------------------------------------
# Independence from the TRACE reference code.
# ----------------------------------------------------------------------------------------------

def test_neither_the_verifier_nor_its_tests_import_the_trace_reference():
    here = Path(__file__).resolve()
    module = here.parent.parent / "src" / "proofbundle" / "adapters" / "trace_record.py"
    for path in (here, module):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            for name in names:
                assert name.split(".")[0] not in ("agentrust_trace", "trace_tests"), (path.name, name)
