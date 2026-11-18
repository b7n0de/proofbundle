"""`verify_sigstore_bundle` reads every field of a trusted-root CA certificate inside its boundary.

Deep gate 6.6.0 at d8881edc, iteration 1, finding Z8: the leaf-side fix of 6.6.0 read the leaf's dates and names
inside the reader's boundary, but `_chain_problem` read the dates of the trusted root's CA certificates outside any
boundary, so a CA whose notAfter is a GeneralizedTime of year 0000 raised a bare ValueError ("year 0 is out of
range") out of `verify_sigstore_bundle`. Such a trusted root is now one that cannot be read: exit 2, no exception.
The bundle is built with real signatures so that the control reaches a verified certificate chain.
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

from proofbundle.adapters.sigstore_bundle import exit_code, verify_sigstore_bundle
from proofbundle.dsse import pae


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _wire(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def _date(year: int) -> datetime:
    return datetime(year, 1, 1, tzinfo=timezone.utc)


_CA_KEY = Ed25519PrivateKey.from_private_bytes(b"\x04" * 32)
_LEAF_KEY = Ed25519PrivateKey.from_private_bytes(b"\x05" * 32)
_LOG_KEY = Ed25519PrivateKey.from_private_bytes(b"\x06" * 32)
_CA_NAME = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
_SAN = "urn:test:workflow"

_CA = (x509.CertificateBuilder().subject_name(_CA_NAME).issuer_name(_CA_NAME).public_key(_CA_KEY.public_key())
       .serial_number(1).not_valid_before(_date(2000)).not_valid_after(_date(2099))
       .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
       .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, None, None), True)
       .sign(_CA_KEY, None))
_LEAF = (x509.CertificateBuilder().subject_name(x509.Name([])).issuer_name(_CA_NAME)
         .public_key(_LEAF_KEY.public_key()).serial_number(2).not_valid_before(_date(2020))
         .not_valid_after(_date(2030))
         .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, None, None), True)
         .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), False)
         .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(_SAN)]), True)
         .add_extension(x509.UnrecognizedExtension(ObjectIdentifier("1.3.6.1.4.1.57264.1.1"),
                                                   b"https://token.actions.githubusercontent.com"), False)
         .sign(_CA_KEY, None))
_LOG_DER = _LOG_KEY.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
_LOG_ID = hashlib.sha256(_LOG_DER).digest()
_PAYLOAD = b"{}"
_PTYPE = "application/vnd.in-toto+json"
_SIG = _LEAF_KEY.sign(pae(_PTYPE, _PAYLOAD))
_BODY = _wire({"apiVersion": "0.0.1", "kind": "dsse", "spec": {
    "envelopeHash": {"algorithm": "sha256", "value": "0" * 64},
    "payloadHash": {"algorithm": "sha256", "value": hashlib.sha256(_PAYLOAD).hexdigest()},
    "signatures": [{"signature": _b64(_SIG), "verifier": _b64(_LEAF.public_bytes(Encoding.PEM))}]}})
_TIME = 1767225600
_SET = _wire({"body": _b64(_BODY), "integratedTime": _TIME, "logID": _LOG_ID.hex(), "logIndex": 0})
_BUNDLE = _wire({
    "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
    "verificationMaterial": {
        "x509CertificateChain": {"certificates": [{"rawBytes": _b64(_LEAF.public_bytes(Encoding.DER))}]},
        "tlogEntries": [{"logIndex": "0", "logId": {"keyId": _b64(_LOG_ID)},
                         "kindVersion": {"kind": "dsse", "version": "0.0.1"}, "integratedTime": str(_TIME),
                         "canonicalizedBody": _b64(_BODY),
                         "inclusionPromise": {"signedEntryTimestamp": _b64(_LOG_KEY.sign(_SET))}}]},
    "dsseEnvelope": {"payload": _b64(_PAYLOAD), "payloadType": _PTYPE, "signatures": [{"sig": _b64(_SIG)}]}})


def _root(ca_der: bytes) -> bytes:
    return _wire({
        "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
        "tlogs": [{"baseUrl": "https://log.example", "hashAlgorithm": "SHA2_256", "logId": {"keyId": _b64(_LOG_ID)},
                   "publicKey": {"rawBytes": _b64(_LOG_DER), "keyDetails": "PKIX_ED25519",
                                 "validFor": {"start": "2000-01-01T00:00:00Z"}}}],
        "certificateAuthorities": [{"uri": "https://ca.example",
                                    "certChain": {"certificates": [{"rawBytes": _b64(ca_der)}]},
                                    "validFor": {"start": "2000-01-01T00:00:00Z"}}]})


def _verify(ca_der: bytes):
    return verify_sigstore_bundle(_BUNDLE, trusted_root=_root(ca_der), artifact_digest="sha256:" + "0" * 64,
                                  profile="github-artifact-attestation", identity={"san": _SAN})


def test_the_control_reaches_a_verified_certificate_chain():
    verdict = _verify(_CA.public_bytes(Encoding.DER))
    assert any(c.name == "certificate-chain" and c.ok is True for c in verdict.result.checks)


def _ca_from(year: int) -> bytes:
    """A CA valid from `year`; a year from 2050 on is written as GeneralizedTime (RFC 5280 section 4.1.2.5)."""
    return (x509.CertificateBuilder().subject_name(_CA_NAME).issuer_name(_CA_NAME).public_key(_CA_KEY.public_key())
            .serial_number(1).not_valid_before(_date(year)).not_valid_after(_date(2099))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, None, None), True)
            .sign(_CA_KEY, None)).public_bytes(Encoding.DER)


@pytest.mark.parametrize("der, needle", [(_CA.public_bytes(Encoding.DER), b"20990101000000Z"),
                                         (_ca_from(2050), b"20500101000000Z")], ids=["notAfter", "notBefore"])
def test_a_ca_date_of_year_0000_is_unreadable_trust_material_not_an_exception(der, needle):
    assert der.count(needle) == 1
    bad = der.replace(needle, b"0000" + needle[4:], 1)
    verdict = _verify(bad)  # must not raise
    assert verdict.ok is False
    assert exit_code(verdict) == 2


# ── deep gate 6.6.0 at c3472f6f, L6 Z8: one set of read errors for every certificate reader ───────────────────────
def _version_3(der: bytes) -> bytes:
    """The certificate with its explicit version value 2 (v3) replaced by 3, which no X.509 version names; the DER
    lengths stay the same."""
    marker = b"\xa0\x03\x02\x01\x02"
    at = der.find(marker)
    assert 0 <= at <= 16, "the fixture names its version where RFC 5280 puts it"
    return der[:at + 4] + b"\x03" + der[at + 5:]


def _root_with(kind: str, chain: list) -> bytes:
    root = json.loads(_root(_CA.public_bytes(Encoding.DER)))
    entry = {"uri": "https://authority.example", "certChain": {"certificates": [{"rawBytes": _b64(c)} for c in chain]},
             "validFor": {"start": "2000-01-01T00:00:00Z"}}
    root[kind] = [entry]
    return _wire(root)


@pytest.mark.parametrize("kind", ["certificateAuthorities", "timestampAuthorities"])
@pytest.mark.parametrize("where", [0, 1], ids=["only", "second"])
def test_a_certificate_version_no_x509_version_names_is_unreadable_trust_material(kind, where):
    """L6 Z8: the leaf reader caught `InvalidVersion`, the reader of the trusted root's chains did not."""
    good = _CA.public_bytes(Encoding.DER)
    bad = _version_3(good)
    with pytest.raises(x509.InvalidVersion):
        x509.load_der_x509_certificate(bad)
    verdict = verify_sigstore_bundle(_BUNDLE, trusted_root=_root_with(kind, [good] * where + [bad]),
                                     artifact_digest="sha256:" + "0" * 64, profile="github-artifact-attestation",
                                     identity={"san": _SAN})  # must not raise
    assert verdict.ok is False
    assert exit_code(verdict) == 2
    assert any(c.name == "verifier-config" and c.ok is False for c in verdict.result.checks)


def _bundle_with_leaf(der: bytes) -> bytes:
    doc = json.loads(_BUNDLE)
    doc["verificationMaterial"]["x509CertificateChain"]["certificates"][0]["rawBytes"] = _b64(der)
    return _wire(doc)


def _every_byte(der: bytes):
    """GENERATOR, NOT A POINT FIXTURE: every byte of the certificate replaced by four values, the version byte and a
    length byte among them. Each mutant must come back as a verdict; which check refuses it is not this property."""
    for at in range(len(der)):
        for value in {0x00, 0x03, 0xFF, der[at] ^ 0x01}:
            if value != der[at]:
                yield der[:at] + bytes([value]) + der[at + 1:]


def test_no_byte_of_a_trusted_ca_certificate_raises_out_of_the_verifier():
    good = _CA.public_bytes(Encoding.DER)
    raised = []
    for mutant in _every_byte(good):
        try:
            _verify(mutant)
        except Exception as exc:  # noqa: BLE001 -- the property under test is that nothing leaves
            raised.append((type(exc).__name__, str(exc)[:80]))
    assert not raised, raised[:5]


def test_no_byte_of_the_leaf_certificate_raises_out_of_the_verifier():
    root = _root(_CA.public_bytes(Encoding.DER))
    raised = []
    for mutant in _every_byte(_LEAF.public_bytes(Encoding.DER)):
        try:
            verify_sigstore_bundle(_bundle_with_leaf(mutant), trusted_root=root, artifact_digest="sha256:" + "0" * 64,
                                   profile="github-artifact-attestation", identity={"san": _SAN})
        except Exception as exc:  # noqa: BLE001
            raised.append((type(exc).__name__, str(exc)[:80]))
    assert not raised, raised[:5]
