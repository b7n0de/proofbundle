"""A ``cnf`` this verifier cannot read is still the issuer's binding (6.6.1).

RFC 7800 lets an issuer bind a credential to a holder key in several forms: a ``jwk`` of any key type, a
``jwe``, a ``kid`` or a ``jku``. proofbundle reads one of them, an OKP/Ed25519 ``cnf.jwk`` of 32 bytes. Until
6.6.0 every other form was treated as if the issuer had bound nothing: a bundle carrying such a credential
with no Key Binding JWT verified ``ok``, the policy rule ``require_key_binding_when_cnf_present`` said "no cnf
holder key bound", and ``verify_key_binding`` / ``verify_sdjwt_vc`` accepted a Key Binding JWT signed by a third
party under a holder key the caller supplied. Measured at 6.6.0 from the package index and at f170c168.

The rule: a ``cnf`` member that is present asks for proof of possession. Where this verifier cannot read the
bound key it cannot check that proof, so it refuses (fail-closed); a holder key supplied by the caller never
replaces the issuer's binding. A credential without ``cnf`` keeps its behaviour, and so does a readable
Ed25519 ``cnf.jwk``.

A ``cnf`` can also travel as a Disclosure. proofbundle reads ``cnf`` in the issuer-signed payload only, so a
presented Disclosure that gives the payload a top-level ``cnf`` is one more ``cnf`` it cannot read; until 6.6.0
it was ignored, with an Ed25519 key too (measured at 6.6.0 by a second session). A Disclosure the holder
withholds is visible to no verifier, and a property named ``cnf`` inside another object is no confirmation claim.

Only keys generated in this run. Every unreadable form is driven through every surface that reads ``cnf``. The forms
are those the builder measured and those a second session measured at 6.6.0 from the package index with scripts of
its own. The digests of the fixed Disclosure further down were computed outside Python.
"""
from __future__ import annotations

import base64
import functools
import hashlib
import json
import os
import pathlib

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa, x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import emit_bundle, generate_signer, verify_bundle
from proofbundle import kbjwt
from proofbundle.bundle import _issuer_requires_holder_binding
from proofbundle.kbjwt import holder_key_from_cnf, verify_key_binding
from proofbundle.policy import evaluate_policy
from proofbundle.sdjwt_vc import verify_sdjwt_vc

_VCT = "https://example.test/vct"
_IAT = 1_780_000_000
_UNREADABLE = "cnf) this verifier cannot read"
_NOT_RULED_OUT = "cannot be ruled out"
_POLICY = {"schema": "proofbundle-trust-policy/v0.1", "sd_jwt": {"require_key_binding_when_cnf_present": True}}


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _raw(key) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


@functools.lru_cache(maxsize=None)
def _keys():
    """The actors of every case: the issuer, the holder the readable control binds, and a third party that
    holds neither key and signs a Key Binding JWT of its own."""
    return {"issuer": generate_signer(), "holder": ed25519.Ed25519PrivateKey.generate(),
            "third": ed25519.Ed25519PrivateKey.generate()}


@functools.lru_cache(maxsize=None)
def _unreadable_forms() -> dict:
    """Every form of ``cnf`` that is present and that this verifier cannot read as a holder key."""
    holder_x = _raw(_keys()["holder"])
    p256 = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
    p384 = ec.generate_private_key(ec.SECP384R1()).public_key().public_numbers()
    k256 = ec.generate_private_key(ec.SECP256K1()).public_key().public_numbers()
    rsa_pub = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key().public_numbers()
    ed448_x = ed448.Ed448PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    x25519_x = x25519.X25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    okp = {"kty": "OKP", "crv": "Ed25519"}
    return {
        "jwk-ec-p256": {"jwk": {"kty": "EC", "crv": "P-256", "x": _b64u(p256.x.to_bytes(32, "big")),
                                "y": _b64u(p256.y.to_bytes(32, "big"))}},
        "jwk-rsa-2048": {"jwk": {"kty": "RSA", "n": _b64u(rsa_pub.n.to_bytes(256, "big")), "e": "AQAB"}},
        "jwk-okp-ed448": {"jwk": {"kty": "OKP", "crv": "Ed448", "x": _b64u(ed448_x)}},
        "jwk-okp-x25519": {"jwk": {"kty": "OKP", "crv": "X25519", "x": _b64u(x25519_x)}},
        "jwk-ed25519-x-of-31-bytes": {"jwk": {**okp, "x": _b64u(holder_x[:31])}},
        "jwk-ed25519-x-of-33-bytes": {"jwk": {**okp, "x": _b64u(holder_x + b"\x00")}},
        "jwk-ed25519-x-outside-the-alphabet": {"jwk": {**okp, "x": "!" * 43}},
        "jwk-ed25519-x-missing": {"jwk": dict(okp)},
        "jwk-ed25519-x-a-number": {"jwk": {**okp, "x": 5}},
        "jwk-ed25519-names-in-lower-case": {"jwk": {"kty": "okp", "crv": "ed25519", "x": _b64u(holder_x)}},
        "jwk-empty": {"jwk": {}},
        "jwk-a-string": {"jwk": _b64u(holder_x)},
        "kid-only": {"kid": "holder-key-1"},
        "jku-and-kid": {"jku": "https://issuer.example.test/keys.json", "kid": "holder-key-1"},
        "jwe-only": {"jwe": "e30.e30.e30.e30.e30"},
        "cnf-empty": {},
        "cnf-null": None,
        "cnf-a-string": "holder-key-1",
        "cnf-a-list": [],
        "cnf-false": False,
        "cnf-a-number": 5,
        "cnf-a-list-with-a-jwk": [{"jwk": {**okp, "x": _b64u(holder_x)}}],
        "jwk-ec-p384": {"jwk": {"kty": "EC", "crv": "P-384", "x": _b64u(p384.x.to_bytes(48, "big")),
                                "y": _b64u(p384.y.to_bytes(48, "big"))}},
        "jwk-ec-secp256k1": {"jwk": {"kty": "EC", "crv": "secp256k1", "x": _b64u(k256.x.to_bytes(32, "big")),
                                     "y": _b64u(k256.y.to_bytes(32, "big"))}},
        "jwk-ed25519-x-in-the-standard-alphabet-with-padding":
            {"jwk": {**okp, "x": base64.b64encode(holder_x).decode("ascii")}},
        "jwk-okp-without-crv": {"jwk": {"kty": "OKP", "x": _b64u(holder_x)}},
        "jwk-kty-ec-with-crv-ed25519": {"jwk": {"kty": "EC", "crv": "Ed25519", "x": _b64u(holder_x)}},
        "jkt-only": {"jkt": _b64u(hashlib.sha256(holder_x).digest())},
        "x5t-s256-only": {"x5t#S256": _b64u(hashlib.sha256(holder_x).digest())},
    }


_FORMS = sorted(_unreadable_forms())
_ABSENT = object()


def _readable_cnf() -> dict:
    return {"jwk": {"kty": "OKP", "crv": "Ed25519", "x": _b64u(_raw(_keys()["holder"]))}}


def _sd_jwt(cnf=_ABSENT) -> str:
    """A compact SD-JWT without disclosures and without a Key Binding JWT, genuinely signed by the issuer."""
    header = _b64u(json.dumps({"alg": "EdDSA", "typ": "dc+sd-jwt"}).encode())
    claims: dict = {"iss": "https://issuer.example.test", "vct": _VCT}
    if cnf is not _ABSENT:
        claims["cnf"] = cnf
    payload = _b64u(json.dumps(claims).encode())
    signature = _b64u(_keys()["issuer"].sign(f"{header}.{payload}".encode("ascii")))
    return f"{header}.{payload}.{signature}~"


def _with_key_binding(sd_part: str, signer, sd_hash_alg: str = "sha256") -> str:
    header = _b64u(json.dumps({"alg": "EdDSA", "typ": "kb+jwt"}).encode())
    payload = _b64u(json.dumps({"iat": _IAT, "aud": "https://rp.example.test", "nonce": "n-1",
                                "sd_hash": _b64u(hashlib.new(sd_hash_alg, sd_part.encode("ascii")).digest())}).encode())
    return f"{sd_part}{header}.{payload}.{_b64u(signer.sign(f'{header}.{payload}'.encode('ascii')))}"


def _bundle(compact: str, *, with_issuer_key: bool = True) -> dict:
    sd = {"compact": compact}
    if with_issuer_key:
        sd["issuer_public_key_b64"] = base64.b64encode(_raw(_keys()["issuer"])).decode("ascii")
    return emit_bundle(b'{"generic":"vc"}', generate_signer(), sd_jwt_vc=sd)


def _key_binding_checks(result) -> list:
    return [(c.ok, c.detail) for c in result.checks if c.name == "sd-jwt-key-binding"]


# --- the bundle, presented with no Key Binding JWT -------------------------------------------------------------

@pytest.mark.parametrize("form", _FORMS)
def test_a_bundle_without_key_binding_fails_when_the_issuer_bound_a_key_it_cannot_read(form):
    result = verify_bundle(_bundle(_sd_jwt(_unreadable_forms()[form])))
    checks = _key_binding_checks(result)
    assert result.ok is False, (form, [(c.name, c.ok) for c in result.checks])
    assert len(checks) == 1 and checks[0][0] is False and "NO Key Binding JWT" in checks[0][1], (form, checks)


def test_a_bundle_without_cnf_and_without_key_binding_still_verifies():
    result = verify_bundle(_bundle(_sd_jwt()))
    assert result.ok is True and _key_binding_checks(result) == [], [(c.name, c.ok, c.detail) for c in result.checks]


def test_a_bundle_with_a_readable_cnf_and_without_key_binding_fails_as_before():
    result = verify_bundle(_bundle(_sd_jwt(_readable_cnf())))
    checks = _key_binding_checks(result)
    assert result.ok is False and len(checks) == 1 and "NO Key Binding JWT" in checks[0][1], checks


@pytest.mark.parametrize("form", _FORMS)
def test_no_policy_judges_a_bundle_that_fails_on_an_unreadable_cnf(form):
    """The bundle fails at ``sd-jwt-key-binding``, so no policy judges it: ``policy_ok`` is None and no rule is
    evaluated. This holds what ``verify_bundle`` does. It does not reach the rule ``policy:key_binding_present``,
    which reads no ``cnf`` where the crypto result carries no key-binding line."""
    bundle = _bundle(_sd_jwt(_unreadable_forms()[form]))
    verdict = evaluate_policy(bundle, verify_bundle(bundle), _POLICY)
    assert verdict.get("policy_ok") is None and verdict.get("checks") == [], (form, verdict)
    assert "crypto verification did not pass" in str(verdict.get("reason")), (form, verdict)


def test_the_policy_rule_still_passes_a_credential_without_cnf():
    bundle = _bundle(_sd_jwt())
    verdict = evaluate_policy(bundle, verify_bundle(bundle), _POLICY)
    rule = [c for c in verdict["checks"] if c["name"] == "policy:key_binding_present"]
    assert verdict["policy_ok"] is True and len(rule) == 1 and rule[0]["ok"] is True, verdict


def test_the_policy_rule_says_so_where_the_bundle_carries_no_sd_jwt():
    """No SD-JWT, no payload to read: the rule passes and does not say that a payload binds no holder key."""
    bundle = emit_bundle(b'{"generic":"vc"}', generate_signer())
    verdict = evaluate_policy(bundle, verify_bundle(bundle), _POLICY)
    rule = [(c["ok"], c["detail"]) for c in verdict["checks"] if c["name"] == "policy:key_binding_present"]
    assert verdict["policy_ok"] is True and rule == [(True, "the bundle carries no SD-JWT; KB not required")], verdict


def _as_a_verifier_without_the_rule_would_report(bundle):
    """The result of ``verify_bundle`` without its ``sd-jwt-key-binding`` line, stamped as this process's own: what a
    verifier that had lost the rule would hand to a policy. ``verify_bundle`` itself produces no such result."""
    result = verify_bundle(bundle)
    result.checks[:] = [c for c in result.checks if c.name != "sd-jwt-key-binding"]
    result.stamp_origin()
    return result


@pytest.mark.parametrize("form", _FORMS + ["a-readable-ed25519-jwk"])
def test_the_policy_rule_reads_the_payload_and_does_not_rest_on_the_bundle_check(form):
    """Reached directly: a crypto result that passed and carries no key-binding line, over a credential whose issuer
    bound a holder key, presented with no Key Binding JWT. The rule reads the payload itself and refuses."""
    cnf = _readable_cnf() if form == "a-readable-ed25519-jwk" else _unreadable_forms()[form]
    bundle = _bundle(_sd_jwt(cnf))
    result = _as_a_verifier_without_the_rule_would_report(bundle)
    assert result.ok is True, (form, [(c.name, c.ok) for c in result.checks])
    verdict = evaluate_policy(bundle, result, _POLICY)
    rule = [c for c in verdict.get("checks", []) if c["name"] == "policy:key_binding_present"]
    assert verdict.get("policy_ok") is False and len(rule) == 1 and rule[0]["ok"] is False, (form, verdict)
    assert _NOT_RULED_OUT in rule[0]["detail"], (form, rule)


def test_the_policy_rule_reads_a_presented_cnf_disclosure_too():
    claims, disclosure = _top_level(_readable_cnf())
    bundle = _bundle(_sd_jwt_from(claims, [disclosure]))
    verdict = evaluate_policy(bundle, _as_a_verifier_without_the_rule_would_report(bundle), _POLICY)
    rule = [c for c in verdict.get("checks", []) if c["name"] == "policy:key_binding_present"]
    assert verdict.get("policy_ok") is False and len(rule) == 1 and rule[0]["ok"] is False, verdict


def test_the_policy_rule_passes_a_result_without_the_line_when_nothing_is_bound():
    """The control: over a credential without ``cnf`` the same kind of result passes the rule, as before."""
    bundle = _bundle(_sd_jwt())
    verdict = evaluate_policy(bundle, _as_a_verifier_without_the_rule_would_report(bundle), _POLICY)
    rule = [c for c in verdict["checks"] if c["name"] == "policy:key_binding_present"]
    assert verdict["policy_ok"] is True and len(rule) == 1 and rule[0]["ok"] is True, verdict
    assert rule[0]["detail"] == "no cnf holder key bound; KB not required", rule


# --- the bundle, presented with a Key Binding JWT a third party signed ----------------------------------------

@pytest.mark.parametrize("form", _FORMS)
def test_a_bundle_with_a_third_party_key_binding_names_the_unreadable_cnf(form):
    sd_part = _sd_jwt(_unreadable_forms()[form])
    result = verify_bundle(_bundle(_with_key_binding(sd_part, _keys()["third"])))
    checks = _key_binding_checks(result)
    assert result.ok is False and len(checks) == 1 and checks[0][0] is False, (form, checks)
    assert _UNREADABLE in checks[0][1], (form, checks)


# --- the bundle, with no issuer key ---------------------------------------------------------------------------

@pytest.mark.parametrize("form", _FORMS)
def test_a_bundle_without_issuer_key_refuses_an_unreadable_cnf_like_a_readable_one(form):
    result = verify_bundle(_bundle(_sd_jwt(_unreadable_forms()[form]), with_issuer_key=False))
    checks = _key_binding_checks(result)
    assert result.ok is False and len(checks) == 1 and "NO issuer key" in checks[0][1], (form, checks)


def test_a_bundle_without_issuer_key_and_without_cnf_adds_no_key_binding_check():
    result = verify_bundle(_bundle(_sd_jwt(), with_issuer_key=False))
    assert result.ok is False and _key_binding_checks(result) == [], [(c.name, c.ok) for c in result.checks]


# --- verify_key_binding, called directly ----------------------------------------------------------------------

@pytest.mark.parametrize("form", _FORMS)
def test_a_supplied_holder_key_never_replaces_a_cnf_the_verifier_cannot_read(form):
    third = _keys()["third"]
    presented = _with_key_binding(_sd_jwt(_unreadable_forms()[form]), third)
    verdict = verify_key_binding(presented, _raw(third))
    assert verdict["present"] is True and verdict["ok"] is False, (form, verdict)
    assert _UNREADABLE in verdict["detail"], (form, verdict["detail"])


@pytest.mark.parametrize("form", _FORMS)
def test_an_unreadable_cnf_fails_the_key_binding_without_a_supplied_key_too(form):
    presented = _with_key_binding(_sd_jwt(_unreadable_forms()[form]), _keys()["third"])
    verdict = verify_key_binding(presented)
    assert verdict["present"] is True and verdict["ok"] is False and _UNREADABLE in verdict["detail"], (form, verdict)


def test_without_cnf_the_supplied_holder_key_still_verifies_the_key_binding():
    third = _keys()["third"]
    verdict = verify_key_binding(_with_key_binding(_sd_jwt(), third), _raw(third))
    assert verdict["ok"] is True and verdict["detail"] == "key binding valid (supplied holder key)", verdict
    missing = verify_key_binding(_with_key_binding(_sd_jwt(), third))
    assert missing["ok"] is False and "no holder key" in missing["detail"], missing


def test_a_readable_cnf_still_decides_alone():
    holder, third = _keys()["holder"], _keys()["third"]
    sd_part = _sd_jwt(_readable_cnf())
    by_holder = verify_key_binding(_with_key_binding(sd_part, holder), _raw(third))
    assert by_holder["ok"] is True and by_holder["detail"] == "key binding valid (cnf.jwk)", by_holder
    by_third = verify_key_binding(_with_key_binding(sd_part, third), _raw(third))
    assert by_third["ok"] is False and by_third["detail"] == "KB-JWT signature invalid (cnf.jwk)", by_third


# --- verify_sdjwt_vc ------------------------------------------------------------------------------------------

@pytest.mark.parametrize("form", _FORMS)
def test_the_vc_profile_refuses_a_third_party_key_binding_under_an_unreadable_cnf(form):
    third = _keys()["third"]
    presented = _with_key_binding(_sd_jwt(_unreadable_forms()[form]), third)
    verdict = verify_sdjwt_vc(presented, {"vctAllowlist": [_VCT]}, issuer_pubkey=_raw(_keys()["issuer"]),
                              holder_pubkey=_raw(third))
    assert verdict["profile"]["ok"] is True and verdict["issuer"]["sig_ok"] is True, (form, verdict)
    assert verdict["ok"] is False and verdict["binding"]["ok"] is False, (form, verdict["binding"])
    assert _UNREADABLE in verdict["binding"]["detail"], (form, verdict["binding"])


def test_the_vc_profile_still_accepts_a_supplied_holder_key_without_cnf():
    third = _keys()["third"]
    verdict = verify_sdjwt_vc(_with_key_binding(_sd_jwt(), third), {"vctAllowlist": [_VCT]},
                              issuer_pubkey=_raw(_keys()["issuer"]), holder_pubkey=_raw(third))
    assert verdict["ok"] is True and verdict["binding"]["ok"] is True, verdict


def test_the_vc_profile_checks_no_binding_when_the_relying_party_asked_for_none():
    """The stated limit, unchanged: ``requireKeyBinding: false`` is the relying party's own opt-out. The profile then
    reads no ``cnf`` and reports no binding, for a readable ``cnf`` and for an unreadable one alike."""
    policy = {"vctAllowlist": [_VCT], "requireKeyBinding": False}
    for cnf in (_readable_cnf(), _unreadable_forms()["jwk-ec-p256"], _unreadable_forms()["kid-only"]):
        verdict = verify_sdjwt_vc(_sd_jwt(cnf), policy, issuer_pubkey=_raw(_keys()["issuer"]))
        assert verdict["ok"] is True and verdict["binding"] is None, (cnf, verdict)


# --- the one place that decides -------------------------------------------------------------------------------

@pytest.mark.parametrize("form", _FORMS)
def test_every_unreadable_form_is_present_and_yields_no_key(form):
    claims = {"vct": _VCT, "cnf": _unreadable_forms()[form]}
    assert holder_key_from_cnf(claims) is None, form
    assert kbjwt._cnf_present(claims) is True, form


def test_presence_is_the_member_and_nothing_else():
    assert kbjwt._cnf_present({"vct": _VCT}) is False
    assert kbjwt._cnf_present({"vct": _VCT, "CNF": _readable_cnf()}) is False     # another member name
    assert kbjwt._cnf_present({"vct": _VCT, "cnf": _readable_cnf()}) is True
    assert holder_key_from_cnf({"vct": _VCT, "cnf": _readable_cnf()}) == _raw(_keys()["holder"])


def test_what_is_no_json_object_asks_for_the_binding():
    """"No holder key bound" is said of a payload that was read as a JSON object and carries no ``cnf``, and of
    nothing else. What is no object is no claims set, so nothing in it says that the issuer bound no key."""
    for no_object in (None, 5, "cnf", ["cnf"], b"cnf", True):
        assert kbjwt._cnf_present(no_object) is True, no_object


def test_a_payload_that_is_no_json_value_asks_for_the_binding():
    class Other(dict):
        """A dict subclass holding a value JSON cannot write: what it binds cannot be read."""

    assert kbjwt._cnf_present(Other({"vct": _VCT, "extra": object()})) is True


# --- a cnf that travels as a Disclosure -----------------------------------------------------------------------

def _disclosure(name: str, value) -> str:
    return _b64u(json.dumps([_b64u(os.urandom(16)), name, value]).encode())


def _digest_of(disclosure: str) -> str:
    return _b64u(hashlib.sha256(disclosure.encode("ascii")).digest())


def _sd_jwt_from(claims: dict, presented=()) -> str:
    """A compact SD-JWT over ``claims`` (which carry their own ``_sd``), genuinely signed by the issuer, followed by
    the presented Disclosures and no Key Binding JWT."""
    header = _b64u(json.dumps({"alg": "EdDSA", "typ": "dc+sd-jwt"}).encode())
    payload = _b64u(json.dumps({"iss": "https://issuer.example.test", "vct": _VCT, **claims}).encode())
    signature = _b64u(_keys()["issuer"].sign(f"{header}.{payload}".encode("ascii")))
    return f"{header}.{payload}.{signature}~" + "".join(d + "~" for d in presented)


@functools.lru_cache(maxsize=None)
def _disclosed_cnf_values() -> dict:
    return {"an-ed25519-jwk": _readable_cnf(), "an-ec-p256-jwk": _unreadable_forms()["jwk-ec-p256"],
            "only-a-kid": _unreadable_forms()["kid-only"]}


_DISCLOSED = sorted(_disclosed_cnf_values())


def _top_level(value):
    """(claims, disclosure): ``cnf`` committed in the payload's own ``_sd``."""
    disclosure = _disclosure("cnf", value)
    return {"_sd": [_digest_of(disclosure)]}, disclosure


@pytest.mark.parametrize("kind", _DISCLOSED)
def test_a_presented_cnf_disclosure_asks_for_the_key_binding(kind):
    claims, disclosure = _top_level(_disclosed_cnf_values()[kind])
    result = verify_bundle(_bundle(_sd_jwt_from(claims, [disclosure])))
    checks = _key_binding_checks(result)
    assert result.ok is False, (kind, [(c.name, c.ok, c.detail) for c in result.checks])
    assert len(checks) == 1 and checks[0][0] is False and "NO Key Binding JWT" in checks[0][1], (kind, checks)


@pytest.mark.parametrize("kind", _DISCLOSED)
def test_a_presented_cnf_disclosure_is_never_replaced_by_a_supplied_key(kind):
    third = _keys()["third"]
    claims, disclosure = _top_level(_disclosed_cnf_values()[kind])
    presented = _with_key_binding(_sd_jwt_from(claims, [disclosure]), third)
    direct = verify_key_binding(presented, _raw(third))
    assert direct["present"] is True and direct["ok"] is False and _UNREADABLE in direct["detail"], (kind, direct)
    profile = verify_sdjwt_vc(presented, {"vctAllowlist": [_VCT]}, issuer_pubkey=_raw(_keys()["issuer"]),
                              holder_pubkey=_raw(third))
    assert profile["issuer"]["sig_ok"] is True and profile["issuer"]["structure_ok"] is True, (kind, profile["issuer"])
    assert profile["ok"] is False and _UNREADABLE in profile["binding"]["detail"], (kind, profile["binding"])
    in_bundle = _key_binding_checks(verify_bundle(_bundle(presented)))
    assert len(in_bundle) == 1 and in_bundle[0][0] is False and _UNREADABLE in in_bundle[0][1], (kind, in_bundle)


def test_a_disclosed_ed25519_cnf_is_not_read_as_a_holder_key():
    """The stated limit: this verifier reads no holder key from a Disclosure, so the holder's own Key Binding JWT under
    the disclosed key fails as well. It refuses; it does not accept a binding it has not checked."""
    holder = _keys()["holder"]
    claims, disclosure = _top_level(_readable_cnf())
    presented = _with_key_binding(_sd_jwt_from(claims, [disclosure]), holder)
    verdict = verify_key_binding(presented, _raw(holder))
    assert verdict["ok"] is False and _UNREADABLE in verdict["detail"], verdict


def test_a_withheld_cnf_disclosure_is_visible_to_no_verifier():
    """The stated limit: the digest alone says nothing, so the presentation verifies as one without ``cnf``."""
    claims, _withheld = _top_level(_readable_cnf())
    compact = _sd_jwt_from(claims)
    result = verify_bundle(_bundle(compact))
    assert result.ok is True and _key_binding_checks(result) == [], [(c.name, c.ok, c.detail) for c in result.checks]
    assert kbjwt._cnf_present({"vct": _VCT, **claims}, compact) is False


def test_a_property_named_cnf_inside_another_object_is_no_confirmation_claim():
    disclosure = _disclosure("cnf", {"note": "a field of the holder object, not RFC 7800"})
    claims = {"holder": {"_sd": [_digest_of(disclosure)]}}
    compact = _sd_jwt_from(claims, [disclosure])
    result = verify_bundle(_bundle(compact))
    assert result.ok is True and _key_binding_checks(result) == [], [(c.name, c.ok, c.detail) for c in result.checks]
    assert kbjwt._cnf_present({"vct": _VCT, **claims}, compact) is False


def test_a_cnf_disclosure_no_digest_commits_does_not_decide_the_binding():
    """It is refused where every presentation with an uncommitted Disclosure is refused, at the structure check."""
    disclosure = _disclosure("cnf", _readable_cnf())
    other = _disclosure("given_name", "Ada")
    claims = {"_sd": [_digest_of(other)]}
    compact = _sd_jwt_from(claims, [other, disclosure])
    assert kbjwt._cnf_present({"vct": _VCT, **claims}, compact) is False
    result = verify_bundle(_bundle(compact))
    structure = [c.ok for c in result.checks if c.name == "sd-jwt-disclosures"]
    assert result.ok is False and structure == [False], [(c.name, c.ok, c.detail) for c in result.checks]


def test_another_top_level_disclosure_does_not_ask_for_the_binding():
    other = _disclosure("given_name", "Ada")
    claims = {"_sd": [_digest_of(other)]}
    compact = _sd_jwt_from(claims, [other])
    result = verify_bundle(_bundle(compact))
    assert result.ok is True and _key_binding_checks(result) == [], [(c.name, c.ok, c.detail) for c in result.checks]
    assert kbjwt._cnf_present({"vct": _VCT, **claims}, compact) is False


def test_what_cannot_be_read_at_the_top_level_asks_for_the_binding():
    unreadable = _b64u(b'["salt", "cnf", {"jwk": {}, "jwk": {}}]')            # a duplicate name inside the value
    claims = {"vct": _VCT, "_sd": [_digest_of(unreadable)]}
    assert kbjwt._cnf_present(claims, _sd_jwt_from({"_sd": claims["_sd"]}, [unreadable])) is True
    crowd = [_disclosure("claim_%d" % i, i) for i in range(257)]               # more than verify_sd_jwt accepts
    crowded = {"vct": _VCT, "_sd": [_digest_of(d) for d in crowd]}
    assert kbjwt._cnf_present(crowded, _sd_jwt_from({"_sd": crowded["_sd"]}, crowd)) is True
    assert kbjwt._cnf_present(crowded, _sd_jwt_from({"_sd": crowded["_sd"]}, crowd[:256])) is False


def test_a_presentation_that_is_no_text_asks_for_the_binding():
    """Without a presentation the payload alone is asked. A presentation that is no text cannot be read, so no
    Disclosure in it can be ruled out."""
    claims = {"vct": _VCT, "_sd": [_digest_of(_disclosure("given_name", "Ada"))]}
    assert kbjwt._cnf_present(claims) is False
    assert kbjwt._cnf_present(claims, None) is False
    for no_text in (5, b"a.b.c~", ["a.b.c~"], {"compact": "a.b.c~"}, True):
        assert kbjwt._cnf_present(claims, no_text) is True, no_text


# --- a cnf Disclosure under each hash the profile reads, with digests computed outside Python ----------------

# One fixed Disclosure, ["2GLC42sKQveCfGfryNRN9w", "cnf", {"kid": "holder-key-1"}], and the digests of its ASCII text
# as sha256sum, sha384sum and sha512sum of coreutils printed them on 2026-11-23, written here as base64url.
_FIXED_CNF_DISCLOSURE = "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImNuZiIsIHsia2lkIjogImhvbGRlci1rZXktMSJ9XQ"
_FIXED_DIGEST = {
    "sha-256": "Tbz1JrhFiI-mAM7fot3RxflpXzt3YPEQBuWRTivg4D4",
    "sha-384": "qAsYJDhPm-bAzOuOaetHCBVFYgfrWaWmUD1IZSlwHtggBXzJ5uZiHlXi5b8_EcoZ",
    "sha-512": "NpqbdibFi6hg19WBXPZW9D02gLHXKAm6NcCy3lN3BNaBqzkdxbXPwv9eCLGOdBcbdQcLYS3Qds7tT8UF4jke_g",
}
_HASHLIB_NAME = {"sha-256": "sha256", "sha-384": "sha384", "sha-512": "sha512"}
_SD_ALGS = sorted(_FIXED_DIGEST)


def _structure(result) -> list:
    return [c.ok for c in result.checks if c.name == "sd-jwt-disclosures"]


def test_the_fixed_disclosure_is_the_cnf_claim_it_is_said_to_be():
    padded = _FIXED_CNF_DISCLOSURE + "=" * (-len(_FIXED_CNF_DISCLOSURE) % 4)
    assert json.loads(base64.urlsafe_b64decode(padded)) == ["2GLC42sKQveCfGfryNRN9w", "cnf", {"kid": "holder-key-1"}]


@pytest.mark.parametrize("sd_alg", _SD_ALGS)
def test_a_cnf_disclosure_is_found_under_each_hash_algorithm(sd_alg):
    claims = {"_sd_alg": sd_alg, "_sd": [_FIXED_DIGEST[sd_alg]]}
    compact = _sd_jwt_from(claims, [_FIXED_CNF_DISCLOSURE])
    assert kbjwt._cnf_present({"vct": _VCT, **claims}, compact) is True, sd_alg
    result = verify_bundle(_bundle(compact))
    checks = _key_binding_checks(result)
    assert _structure(result) == [True], (sd_alg, [(c.name, c.ok, c.detail) for c in result.checks])
    assert result.ok is False and len(checks) == 1 and checks[0][0] is False, (sd_alg, checks)
    assert "NO Key Binding JWT" in checks[0][1], (sd_alg, checks)
    third = _keys()["third"]
    direct = verify_key_binding(_with_key_binding(compact, third, _HASHLIB_NAME[sd_alg]), _raw(third))
    assert direct["present"] is True and direct["ok"] is False and _UNREADABLE in direct["detail"], (sd_alg, direct)


def test_a_cnf_disclosure_is_found_under_the_default_hash_algorithm():
    claims = {"_sd": [_FIXED_DIGEST["sha-256"]]}                               # no _sd_alg: sha-256
    compact = _sd_jwt_from(claims, [_FIXED_CNF_DISCLOSURE])
    assert kbjwt._cnf_present({"vct": _VCT, **claims}, compact) is True
    checks = _key_binding_checks(verify_bundle(_bundle(compact)))
    assert len(checks) == 1 and checks[0][0] is False and "NO Key Binding JWT" in checks[0][1], checks


@pytest.mark.parametrize("sd_alg", _SD_ALGS)
def test_a_digest_under_another_hash_algorithm_commits_nothing(sd_alg):
    """The digest is read under the payload's own ``_sd_alg``. One computed with another hash commits no Disclosure,
    here as in ``verify_sd_jwt``, which refuses the presentation at the structure check."""
    for other in sorted(set(_FIXED_DIGEST) - {sd_alg}):
        claims = {"_sd_alg": sd_alg, "_sd": [_FIXED_DIGEST[other]]}
        compact = _sd_jwt_from(claims, [_FIXED_CNF_DISCLOSURE])
        assert kbjwt._cnf_present({"vct": _VCT, **claims}, compact) is False, (sd_alg, other)
        result = verify_bundle(_bundle(compact))
        assert result.ok is False and _structure(result) == [False], (sd_alg, other, _structure(result))


def test_order_repetition_and_a_segment_in_between_do_not_hide_a_cnf_disclosure():
    other = _disclosure("given_name", "Ada")
    claims = {"_sd": [_digest_of(other), _FIXED_DIGEST["sha-256"]]}
    presentations = {
        "cnf last": [other, _FIXED_CNF_DISCLOSURE],
        "cnf first": [_FIXED_CNF_DISCLOSURE, other],
        "cnf twice": [_FIXED_CNF_DISCLOSURE, other, _FIXED_CNF_DISCLOSURE],
        "behind a segment shaped like a JWT": [other, "e30.e30.e30", _FIXED_CNF_DISCLOSURE],
    }
    for name, presented in presentations.items():
        compact = _sd_jwt_from(claims, presented)
        assert kbjwt._cnf_present({"vct": _VCT, **claims}, compact) is True, name
        result = verify_bundle(_bundle(compact))
        checks = _key_binding_checks(result)
        assert result.ok is False, (name, [(c.name, c.ok, c.detail) for c in result.checks])
        assert len(checks) == 1 and checks[0][0] is False and "NO Key Binding JWT" in checks[0][1], (name, checks)


def test_only_text_digests_in_a_list_commit_a_disclosure():
    with_one = {"_sd": [5, None, ["x"], {"d": 1}, _FIXED_DIGEST["sha-256"]]}
    assert kbjwt._cnf_present({"vct": _VCT, **with_one}, _sd_jwt_from(with_one, [_FIXED_CNF_DISCLOSURE])) is True
    claims = {"_sd": [5, None, ["x"], {"d": 1}]}                               # a list without a text digest
    compact = _sd_jwt_from(claims, [_FIXED_CNF_DISCLOSURE])
    assert kbjwt._cnf_present({"vct": _VCT, **claims}, compact) is False
    assert verify_bundle(_bundle(compact)).ok is False                         # refused: the Disclosure is not committed


@pytest.mark.parametrize("sd", ["digest", {"0": _FIXED_DIGEST["sha-256"]}, None, 5, {"_sd": [_FIXED_DIGEST["sha-256"]]}],
                         ids=["a-text", "an-object", "null", "a-number", "an-object-with-an-sd-of-its-own"])
def test_a_disclosure_presented_over_an_sd_that_is_no_list_asks_for_the_binding(sd):
    """An ``_sd`` that is no list commits nothing this helper can place. ``verify_sd_jwt`` reads it another way: it
    follows an object under ``_sd`` into that object's own ``_sd``. Where a Disclosure is presented over such an
    ``_sd``, the place it stands at cannot be told, so it cannot be told from a ``cnf``."""
    claims = {"_sd": sd}
    compact = _sd_jwt_from(claims, [_FIXED_CNF_DISCLOSURE])
    assert kbjwt._cnf_present({"vct": _VCT, **claims}, compact) is True, sd
    result = verify_bundle(_bundle(compact))
    checks = _key_binding_checks(result)
    assert result.ok is False, (sd, [(c.name, c.ok, c.detail) for c in result.checks])
    assert len(checks) == 1 and checks[0][0] is False, (sd, checks)


_NO_CLAIM = {"an-object": b'{"cnf": {"kid": "holder-key-1"}}', "a-list-of-four": b'["salt", "cnf", 1, 2]',
             "a-list-of-two": b'["salt", {"kid": "holder-key-1"}]', "a-name-that-is-no-text": b'["salt", 5, 1]',
             "a-text": b'"cnf"', "an-empty-list": b"[]"}


@pytest.mark.parametrize("form", sorted(_NO_CLAIM))
def test_a_committed_top_level_disclosure_that_is_no_claim_asks_for_the_binding(form):
    """Committed in the payload's own ``_sd`` and not of the form ``[salt, name, value]`` with a text name: what it
    names cannot be told, so it cannot be told from a ``cnf``. ``verify_sd_jwt`` refuses each of these at the
    structure check; the binding is asked for as well."""
    disclosure = _b64u(_NO_CLAIM[form])
    claims = {"_sd": [_digest_of(disclosure)]}
    compact = _sd_jwt_from(claims, [disclosure])
    assert kbjwt._cnf_present({"vct": _VCT, **claims}, compact) is True, form
    result = verify_bundle(_bundle(compact))
    checks = _key_binding_checks(result)
    assert result.ok is False and _structure(result) == [False], (form, [(c.name, c.ok) for c in result.checks])
    assert len(checks) == 1 and checks[0][0] is False, (form, checks)


def test_an_sd_that_is_no_list_commits_nothing_and_asks_for_no_binding():
    """Why this one place still answers "no holder key bound": with nothing presented there is no Disclosure that
    could give the payload a ``cnf``, whatever ``_sd`` holds. Such a credential verifies, and asking for the binding
    would fail it for a reason that has nothing to do with a holder key. With a Disclosure presented it is asked for
    (the test above)."""
    for sd in ("digest", {"0": _FIXED_DIGEST["sha-256"]}, None, 5):
        claims = {"_sd": sd}
        compact = _sd_jwt_from(claims)
        assert kbjwt._cnf_present({"vct": _VCT, **claims}, compact) is False, sd
        result = verify_bundle(_bundle(compact))
        assert _structure(result) == [True], (sd, [(c.name, c.ok, c.detail) for c in result.checks])
        assert result.ok is True and _key_binding_checks(result) == [], (sd, [(c.name, c.ok) for c in result.checks])


def test_more_disclosures_than_the_verifier_accepts_fail_the_bundle():
    crowd = [_disclosure("claim_%d" % i, i) for i in range(257)]
    claims = {"_sd": [_digest_of(d) for d in crowd]}
    result = verify_bundle(_bundle(_sd_jwt_from(claims, crowd)))
    checks = _key_binding_checks(result)
    assert result.ok is False and _structure(result) == [False], [(c.name, c.ok, c.detail) for c in result.checks]
    assert len(checks) == 1 and checks[0][0] is False, checks                  # a binding it cannot rule out


def test_exactly_as_many_disclosures_as_the_verifier_accepts_are_read_by_the_bundle():
    """The limit is 256 Disclosures and the bundle meets it at its public surface: 256 are read and 257 are refused (the
    test above). Without a ``cnf`` among the 256 no binding is asked for; with one in the last place it is found."""
    crowd = [_disclosure("claim_%d" % i, i) for i in range(256)]
    claims = {"_sd": [_digest_of(d) for d in crowd]}
    result = verify_bundle(_bundle(_sd_jwt_from(claims, crowd)))
    assert _structure(result) == [True], [(c.name, c.ok, c.detail) for c in result.checks]
    assert result.ok is True and _key_binding_checks(result) == [], [(c.name, c.ok, c.detail) for c in result.checks]
    with_cnf = crowd[:255] + [_FIXED_CNF_DISCLOSURE]
    claims = {"_sd": [_digest_of(d) for d in with_cnf]}
    result = verify_bundle(_bundle(_sd_jwt_from(claims, with_cnf)))
    checks = _key_binding_checks(result)
    assert _structure(result) == [True], [(c.name, c.ok, c.detail) for c in result.checks]
    assert result.ok is False and len(checks) == 1 and checks[0][0] is False, checks
    assert "NO Key Binding JWT" in checks[0][1], checks


def test_an_sd_alg_that_cannot_be_hashed_never_reaches_the_hash_table():
    """``_cnf_disclosed`` looks ``_sd_alg`` up in a module-level table only after ``is_member`` let it through. Under a
    value that cannot be hashed, or that names no known algorithm, no digest can be computed, so a presented Disclosure
    cannot be told from a committed ``cnf``: the binding is asked for, and nothing is raised. Where nothing is presented,
    or nothing is committed at the top level, there is nothing to tell apart and no binding is asked for."""
    for sd_alg in (["sha-256"], {"alg": "sha-256"}, 256, None, True, "sha-1", "SHA-256"):
        claims = {"_sd_alg": sd_alg, "_sd": [_FIXED_DIGEST["sha-256"]]}
        compact = _sd_jwt_from(claims, [_FIXED_CNF_DISCLOSURE])
        assert kbjwt._cnf_present({"vct": _VCT, **claims}, compact) is True, sd_alg
        assert kbjwt._cnf_present({"vct": _VCT, **claims}, _sd_jwt_from(claims)) is False, sd_alg
        for nothing in ({}, {"_sd": []}, {"_sd": [5, None, {"d": 1}]}):         # no text digest at the top level
            uncommitted = {"_sd_alg": sd_alg, **nothing}
            with_nothing_committed = _sd_jwt_from(uncommitted, [_FIXED_CNF_DISCLOSURE])
            assert kbjwt._cnf_present({"vct": _VCT, **uncommitted}, with_nothing_committed) is False, (sd_alg, nothing)
        result = verify_bundle(_bundle(compact))
        checks = _key_binding_checks(result)
        assert result.ok is False and _structure(result) == [False], (sd_alg, _structure(result))
        assert len(checks) == 1 and checks[0][0] is False and _NOT_RULED_OUT in checks[0][1], (sd_alg, checks)


# --- what the binding check does not decide -------------------------------------------------------------------

@pytest.mark.parametrize("form", ["jwk-ec-p256", "kid-only", "cnf-null"])
def test_under_an_issuer_key_that_does_not_verify_the_bundle_fails_at_the_issuer_signature(form):
    """The binding is judged only over a payload the issuer signature authenticated. Under a key that does not verify
    it, the bundle fails at the issuer signature and no key-binding check is added, for a readable ``cnf`` too."""
    for cnf in (_unreadable_forms()[form], _readable_cnf()):
        sd = {"compact": _sd_jwt(cnf), "issuer_public_key_b64": base64.b64encode(_raw(_keys()["third"])).decode("ascii")}
        bundle = emit_bundle(b'{"generic":"vc"}', generate_signer(), sd_jwt_vc=sd)
        result = verify_bundle(bundle)
        issuer = [c.ok for c in result.checks if c.name == "sd-jwt-issuer-signature"]
        assert result.ok is False and issuer == [False], (form, [(c.name, c.ok, c.detail) for c in result.checks])
        assert _key_binding_checks(result) == [], (form, _key_binding_checks(result))


def test_a_payload_that_is_no_object_fails_everywhere():
    header = _b64u(json.dumps({"alg": "EdDSA", "typ": "dc+sd-jwt"}).encode())
    payload = _b64u(b'["cnf"]')
    signature = _b64u(_keys()["issuer"].sign(f"{header}.{payload}".encode("ascii")))
    compact = f"{header}.{payload}.{signature}~"
    assert verify_bundle(_bundle(compact)).ok is False
    third = _keys()["third"]
    verdict = verify_key_binding(_with_key_binding(compact, third), _raw(third))
    assert verdict["present"] is True and verdict["ok"] is False, verdict
    assert verdict["detail"] == "malformed KB-JWT or issuer JWT", verdict


# --- a payload the bundle cannot read -------------------------------------------------------------------------

@functools.lru_cache(maxsize=None)
def _unreadable_payloads() -> dict:
    """Compact forms whose issuer-signed payload cannot be read as a JSON object. ``verify_sd_jwt`` refuses each before
    its signature check; none of them says that the issuer bound no key."""
    header = _b64u(json.dumps({"alg": "EdDSA", "typ": "dc+sd-jwt"}).encode())
    payload = _b64u(json.dumps({"iss": "https://issuer.example.test", "vct": _VCT}).encode())
    signature = _b64u(bytes(64))
    no_json, a_list, a_number = _b64u(b"no json"), _b64u(b'["cnf"]'), _b64u(b"5")
    a_name_twice = _b64u(b'{"vct": 1, "vct": 2}')
    return {
        "no-dot-in-the-first-segment": "abc~",
        "the-empty-text": "",
        "a-payload-outside-ascii": f"{header}.{payload[:-2]}\u00e4a.{signature}~",
        "a-payload-outside-base64url": f"{header}.!!!!.{signature}~",
        "a-payload-that-is-no-json": f"{header}.{no_json}.{signature}~",
        "a-payload-that-is-a-json-list": f"{header}.{a_list}.{signature}~",
        "a-payload-that-is-a-json-number": f"{header}.{a_number}.{signature}~",
        "a-payload-with-a-name-twice": f"{header}.{a_name_twice}.{signature}~",
    }


_UNREADABLE_PAYLOADS = sorted(_unreadable_payloads())


@pytest.mark.parametrize("with_issuer_key", [True, False])
@pytest.mark.parametrize("form", _UNREADABLE_PAYLOADS)
def test_a_payload_the_bundle_cannot_read_never_says_that_nothing_is_bound(form, with_issuer_key):
    compact = _unreadable_payloads()[form]
    sd_part, _kb = kbjwt.split_key_binding(compact)
    assert _issuer_requires_holder_binding(sd_part) is True, form
    result = verify_bundle(_bundle(compact) if with_issuer_key else _bundle(compact, with_issuer_key=False))
    checks = _key_binding_checks(result)
    assert result.ok is False, (form, [(c.name, c.ok, c.detail) for c in result.checks])
    assert len(checks) == 1 and checks[0][0] is False and _NOT_RULED_OUT in checks[0][1], (form, checks)


def test_a_payload_that_was_read_and_binds_nothing_asks_for_nothing():
    """The one path that says "no holder key bound": a payload read as a JSON object, without ``cnf``."""
    sd_part, _kb = kbjwt.split_key_binding(_sd_jwt())
    assert _issuer_requires_holder_binding(sd_part) is False
    assert _issuer_requires_holder_binding(kbjwt.split_key_binding(_sd_jwt(_readable_cnf()))[0]) is True


def test_a_readable_cnf_refused_before_the_signature_check_is_not_said_to_lack_an_issuer_key():
    """With an issuer key supplied and the SD-JWT refused before its signature check (here: an ``_sd_alg`` no digest
    can be computed under), the detail no longer says that no issuer key was supplied."""
    compact = _sd_jwt_from({"_sd_alg": "sha-1", "cnf": _readable_cnf()})
    keyed = _key_binding_checks(verify_bundle(_bundle(compact)))
    assert len(keyed) == 1 and keyed[0][0] is False, keyed
    assert _NOT_RULED_OUT in keyed[0][1] and "NO issuer key" not in keyed[0][1], keyed
    unkeyed = _key_binding_checks(verify_bundle(_bundle(compact, with_issuer_key=False)))
    assert len(unkeyed) == 1 and unkeyed[0][0] is False and "NO issuer key" in unkeyed[0][1], unkeyed


def test_the_conformance_vector_fails_at_the_key_binding_check_and_nowhere_else():
    case = (pathlib.Path(__file__).resolve().parent.parent / "conformance" / "bundle"
            / "sd-jwt-cnf-not-readable-without-key-binding")
    result = verify_bundle(json.loads((case / "bundle.json").read_text(encoding="utf-8")))
    failed = [(c.name, c.detail) for c in result.checks if c.ok is False]
    assert result.ok is False and [name for name, _ in failed] == ["sd-jwt-key-binding"], failed
    assert "NO Key Binding JWT" in failed[0][1], failed
