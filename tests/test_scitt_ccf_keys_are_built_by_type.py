"""The scitt-ccf reader builds a key only by the constructor of its own type, and refuses every other
type before a key object exists. Needs the [scitt] extra.

MEASURED 2026-09-26 on pull request 278, merged with main ef832a9. The reader loaded every
relying-party key through `load_der_public_key` and every x5chain end-entity key through
`Certificate.public_key()`. Both return a live key object of whatever type the bytes name, Ed25519
included, and the reader checked the type only afterwards. The sweep of pull request 280 found the
first of the two by name; the second is the same class under a name that sweep does not model.

Owner decision A1 (Nachtrag 5): EC P-256, EC P-384 and RSA are built by their own constructors, from
the point or from modulus and exponent; anything else is refused while it is still bytes. Each case
below watches every way `cryptography` hands out a public key object: the generic loaders, a
certificate's `public_key()`, and the two constructors by type. A verified type must be built by its
own constructor and by nothing else; a refused type must leave no key object at all.
"""
from __future__ import annotations

import datetime
import importlib.util

import pytest

pytestmark = pytest.mark.skipif(importlib.util.find_spec("cbor2") is None,
                                reason="the scitt-ccf reader needs the [scitt] extra")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import (  # noqa: E402
    dsa, ec, ed448, ed25519, padding, rsa, utils, x448, x25519)
from cryptography.x509.oid import NameOID  # noqa: E402

from proofbundle import scitt_ccf as S  # noqa: E402

PAYLOAD = bytes(range(32))
CA_KEY = ec.generate_private_key(ec.SECP256R1())
RP_P256 = ec.generate_private_key(ec.SECP256R1())


def _spki(public) -> bytes:
    return public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _rsa_pss_spki(public) -> bytes:
    """An RSA key under the RFC 4055 id-RSASSA-PSS OID instead of rsaEncryption: RSA arithmetic, a type
    v1 does not take. Built by hand, since cryptography does not write this form."""
    der = _spki(public)
    rsa_alg_id = bytes.fromhex("300d06092a864886f70d0101010500")
    assert der.count(rsa_alg_id) == 1
    body = bytes.fromhex("300b06092a864886f70d01010a") + der[der.index(rsa_alg_id) + len(rsa_alg_id):]
    return b"\x30" + _der_len(len(body)) + body


def _cert(public) -> bytes:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "statement signer")])
    t = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(public)
            .serial_number(7).not_valid_before(t).not_valid_after(t + datetime.timedelta(days=365))
            .sign(CA_KEY, hashes.SHA256()).public_bytes(serialization.Encoding.DER))


def _statement(alg: int, chain: list, sign) -> bytes:
    import cbor2  # noqa: PLC0415
    prot = cbor2.dumps({1: alg, 258: -16, 259: "application/json", 15: {1: "did:example:signer"},
                        33: chain})
    tbs = cbor2.dumps(["Signature1", prot, b"", PAYLOAD])
    return cbor2.dumps(cbor2.CBORTag(18, [prot, {}, PAYLOAD, sign(tbs)]))


def _ecdsa(key, n: int, h):
    def sign(tbs: bytes) -> bytes:
        r, s = utils.decode_dss_signature(key.sign(tbs, ec.ECDSA(h)))
        return r.to_bytes(n, "big") + s.to_bytes(n, "big")
    return sign


def _pss(key):
    return lambda tbs: key.sign(tbs, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                                hashes.SHA256())


@pytest.fixture
def built(monkeypatch):
    """Every public key object cryptography hands out while a case runs, as (how, key)."""
    seen: list = []

    def recording(how, real):
        def call(*args, **kwargs):
            key = real(*args, **kwargs)
            seen.append((how, key))
            return key
        return call

    for name in ("load_der_public_key", "load_pem_public_key", "load_ssh_public_key"):
        monkeypatch.setattr(serialization, name, recording(name, getattr(serialization, name)))
    monkeypatch.setattr(ec.EllipticCurvePublicKey, "from_encoded_point",
                        recording("by type", ec.EllipticCurvePublicKey.from_encoded_point))
    real_numbers = rsa.RSAPublicNumbers

    class Numbers:
        def __init__(self, e, n):
            self._real = real_numbers(e, n)

        def public_key(self, *args):
            return recording("by type", self._real.public_key)(*args)
    monkeypatch.setattr(rsa, "RSAPublicNumbers", Numbers)

    class Cert:
        def __init__(self, real):
            self._real = real

        def __getattr__(self, name):
            return getattr(self._real, name)

        def public_key(self):
            return recording("Certificate.public_key", self._real.public_key)()
    real_load = x509.load_der_x509_certificate
    monkeypatch.setattr(x509, "load_der_x509_certificate", lambda data: Cert(real_load(data)))
    return seen


# ------------------------------------------------------------------------------------------------
# The three types v1 verifies: each confirms, and each is built by its own constructor only
# ------------------------------------------------------------------------------------------------
_P256 = ec.generate_private_key(ec.SECP256R1())
_P384 = ec.generate_private_key(ec.SECP384R1())
_RSA = rsa.generate_private_key(public_exponent=65537, key_size=2048)
VERIFIED = {
    "EC P-256": (_P256, -7, _ecdsa(_P256, 32, hashes.SHA256()), ec.EllipticCurvePublicKey),
    "EC P-384": (_P384, -35, _ecdsa(_P384, 48, hashes.SHA384()), ec.EllipticCurvePublicKey),
    "RSA": (_RSA, -37, _pss(_RSA), rsa.RSAPublicKey),
}


@pytest.mark.parametrize("kind", sorted(VERIFIED))
def test_a_verified_type_is_built_by_its_own_constructor_and_confirms(kind, built):
    key, alg, sign, cls = VERIFIED[kind]
    ts = _statement(alg, [_cert(key.public_key()), _cert(CA_KEY.public_key())], sign)
    assert S.verify_statement_signature(ts, statement_keys=[_spki(key.public_key())]) == ("confirmed", True)
    assert built, "no key object seen; this case would measure nothing"
    assert {how for how, _k in built} == {"by type"}, built
    assert all(isinstance(k, cls) and _spki(k) == _spki(key.public_key()) for _h, k in built), built


# ------------------------------------------------------------------------------------------------
# Every other type: refused while it is bytes, on each path a key enters by
# ------------------------------------------------------------------------------------------------
REFUSED = {
    "Ed25519": (ed25519.Ed25519PrivateKey.generate().public_key(), "1.3.101.112"),
    "Ed448": (ed448.Ed448PrivateKey.generate().public_key(), "1.3.101.113"),
    "X25519": (x25519.X25519PrivateKey.generate().public_key(), "1.3.101.110"),
    "X448": (x448.X448PrivateKey.generate().public_key(), "1.3.101.111"),
    "EC P-521": (ec.generate_private_key(ec.SECP521R1()).public_key(), "P-256 and P-384"),
    "EC secp256k1": (ec.generate_private_key(ec.SECP256K1()).public_key(), "P-256 and P-384"),
    "EC brainpoolP256r1": (ec.generate_private_key(ec.BrainpoolP256R1()).public_key(), "P-256 and P-384"),
    "DSA": (dsa.generate_private_key(key_size=1024).public_key(), "1.2.840.10040.4.1"),
    "RSA under id-RSASSA-PSS": (_RSA.public_key(), "1.2.840.113549.1.1.10"),
}


def _refused_spki(kind: str) -> bytes:
    public, _why = REFUSED[kind]
    return _rsa_pss_spki(public) if kind == "RSA under id-RSASSA-PSS" else _spki(public)


@pytest.mark.parametrize("kind", sorted(REFUSED))
def test_a_relying_party_key_of_another_type_is_refused_before_a_key_object_exists(kind, built):
    usable, ignored = S._normalize_keys([_refused_spki(kind)])
    assert usable == []
    assert len(ignored) == 1 and REFUSED[kind][1] in ignored[0], ignored
    assert S._verify(-7, _refused_spki(kind), b"tbs", bytes(64)) is False
    assert built == [], built


# cryptography writes no certificate for an RSA key under the PSS OID; that type enters by the
# relying-party path only, above.
_CERT_KINDS = sorted(k for k in REFUSED if k != "RSA under id-RSASSA-PSS")


@pytest.mark.parametrize("kind", _CERT_KINDS)
def test_an_x5chain_end_entity_key_of_another_type_is_refused_before_a_key_object_exists(kind, built):
    chain = [_cert(REFUSED[kind][0]), _cert(CA_KEY.public_key())]
    ts = _statement(-7, chain, _ecdsa(RP_P256, 32, hashes.SHA256()))
    selector = S._statement_key_selector(S.decode_cose_sign1(ts, role="statement"))
    assert selector[:2] == ("x5chain", None) and REFUSED[kind][1] in selector[2], selector
    assert built == [], built
    # through the public surface: the relying party's own P-256 key is built, by its type, and nothing else
    assert S.verify_statement_signature(ts, statement_keys=[_spki(RP_P256.public_key())]) == (
        "needs_rp_trust", None)
    assert built and {how for how, _k in built} == {"by type"}, built
    assert all(_spki(k) == _spki(RP_P256.public_key()) for _h, k in built), built
