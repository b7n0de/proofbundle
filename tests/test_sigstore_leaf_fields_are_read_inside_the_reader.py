"""Every field of the leaf certificate that `verify_sigstore_bundle` reads before the signature is read
inside the reader's own failure boundary.

WHERE THIS COMES FROM. The deep gate of 6.5.0, iteration 1 (tag note of v6.5.0, "Known limitations of
this release"): `_read_leaf` read the subject of the leaf with ``len(cert.subject)`` outside its error
handling. cryptography parses a certificate's Name only when it is first asked for, so a subject
UTF8String with invalid UTF-8 (and a TeletexString with bytes it does not take) loaded as a
certificate and then raised a bare ``ValueError`` out of `verify_sigstore_bundle`, before any chain or
signature check.

THE CLASS. An untrusted field was decoded outside the reader's failure boundary: a field that the
parser decodes lazily raises at its first reading, wherever that reading stands.

THE NEIGHBOUR. The same question asked of every other field `_read_leaf` reads before the signature:
the validity times are converted to a Python datetime when first read, and a GeneralizedTime of year
0000 parses as ASN.1 and raises ``ValueError: year 0 is out of range`` there. Extensions, version, the
SAN, the Fulcio extension values and the public key were already read inside the boundary.
"""
from __future__ import annotations

import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from proofbundle.adapters import sigstore_bundle as sb
from proofbundle.adapters.sigstore_bundle import exit_code, verify_sigstore_bundle

FIX = Path(__file__).resolve().parent / "fixtures" / "sigstore_bundle"
PLACEHOLDER = b"\x0c\x0aPLACEHOLDR"   # UTF8String, 10 bytes


def _generator():
    spec = importlib.util.spec_from_file_location("sigstore_vector_generator_leaf", FIX / "generate_vectors.py")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except TypeError as exc:  # a cryptography release without deterministic ECDSA (before 44)
        pytest.skip(f"the generator needs deterministic ECDSA from cryptography: {exc}")
    return module


def _positive_arguments() -> dict:
    cases = json.loads((FIX / "synthetic_cases.json").read_text(encoding="utf-8"))["cases"]
    case = next(c for c in cases if c["caseId"] == "pos-github-v03-dsse")
    return {"trusted_root": (FIX / case["trustedRoot"]).read_bytes(), "artifact_digest": case["artifactDigest"],
            "profile": case["profile"], "identity": case["identity"]}


#: Replacements of the subject's one attribute value, each the same length as the placeholder.
SUBJECTS = {
    "utf8-invalid": b"\x0c\x0a\xff\xfe" + b"A" * 8,
    "utf8-lone-continuation": b"\x0c\x0a" + b"A" * 9 + b"\x80",
    "teletex-high-bytes": b"\x14\x0a" + b"\xff" * 10,
}


def _with_subject(gen, replacement: bytes) -> tuple:
    leaf = gen.leaf_cert(gen.EXTENSIONS, gen.WORKFLOW_URI,
                         subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PLACEHOLDR")]))
    der = leaf.public_bytes(serialization.Encoding.DER)
    assert der.count(PLACEHOLDER) == 1

    def edit(raw: bytes) -> bytes:
        return raw.replace(PLACEHOLDER, replacement)

    return leaf, edit


@pytest.mark.parametrize("kind", sorted(SUBJECTS))
def test_a_subject_that_does_not_decode_is_a_certificate_failure(kind: str) -> None:
    gen = _generator()
    leaf, edit = _with_subject(gen, SUBJECTS[kind])
    with pytest.raises(sb._Fail) as caught:
        sb._read_leaf(edit(leaf.public_bytes(serialization.Encoding.DER)))
    assert caught.value.check == "certificate"
    assert str(caught.value).startswith("the leaf certificate is not a well-formed X.509 certificate: ")


@pytest.mark.parametrize("kind", sorted(SUBJECTS))
def test_verify_sigstore_bundle_refuses_such_a_leaf_with_a_reason_and_raises_nothing(kind: str) -> None:
    gen = _generator()
    leaf, edit = _with_subject(gen, SUBJECTS[kind])
    data = gen.bundle(cert=leaf, cert_edit=edit)
    out = verify_sigstore_bundle(data, **_positive_arguments())
    assert exit_code(out) == 1
    failed = [c for c in out.result.checks if c.ok is not True]
    assert [c.name for c in failed] == ["certificate"]
    assert "not a well-formed X.509 certificate" in failed[0].detail
    assert not any(c.name == "signature" for c in out.result.checks), "the run went past the certificate"


def test_a_subject_that_decodes_is_still_refused_as_not_empty() -> None:
    """The message of a readable subject stays what it was."""
    gen = _generator()
    leaf, _ = _with_subject(gen, PLACEHOLDER)
    with pytest.raises(sb._Fail) as caught:
        sb._read_leaf(leaf.public_bytes(serialization.Encoding.DER))
    assert str(caught.value) == "the leaf's subject is not empty; Fulcio names the identity in the SAN only"


def _with_year_zero(gen, which: str) -> tuple:
    leaf = gen.leaf_cert(gen.EXTENSIONS, gen.WORKFLOW_URI, not_before=datetime(2051, 1, 1, tzinfo=timezone.utc))
    der = leaf.public_bytes(serialization.Encoding.DER)
    when = leaf.not_valid_before_utc if which == "notBefore" else leaf.not_valid_after_utc
    # GeneralizedTime (tag 0x18, 15 bytes) for years from 2050 on (RFC 5280 section 4.1.2.5).
    time = b"\x18\x0f" + when.strftime("%Y%m%d%H%M%SZ").encode("ascii")
    assert der.count(time) == 1, which

    def edit(raw: bytes) -> bytes:
        return raw.replace(time, b"\x18\x0f0000" + time[6:])

    return leaf, edit


@pytest.mark.parametrize("which", ["notBefore", "notAfter"])
def test_a_validity_time_without_a_datetime_is_a_certificate_failure(which: str) -> None:
    gen = _generator()
    leaf, edit = _with_year_zero(gen, which)
    with pytest.raises(sb._Fail) as caught:
        sb._read_leaf(edit(leaf.public_bytes(serialization.Encoding.DER)))
    assert caught.value.check == "certificate"
    assert str(caught.value).startswith("the leaf certificate is not a well-formed X.509 certificate: ")


@pytest.mark.parametrize("which", ["notBefore", "notAfter"])
def test_verify_sigstore_bundle_refuses_a_year_zero_leaf_and_raises_nothing(which: str) -> None:
    gen = _generator()
    leaf, edit = _with_year_zero(gen, which)
    out = verify_sigstore_bundle(gen.bundle(cert=leaf, cert_edit=edit), **_positive_arguments())
    assert exit_code(out) == 1
    assert [c.name for c in out.result.checks if c.ok is not True] == ["certificate"]
