"""Provider-attested inference: a provider's own signature is not an enclave attestation.

The evidence shape used here is the real one returned by a production inference provider on every
chat completion (measured 2026-09-02 across 25 requests and five models): an ``api_version``, a
``text`` field holding two SHA-256 digests joined by a colon, an ECDSA ``signature``, the signer's
address, and a nested receipt. Using the real shape matters — a made-up shape would let the module
pass tests that the field it actually meets would fail.
"""

from __future__ import annotations

import warnings

import pytest

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from proofbundle.errors import BundleFormatError
    from proofbundle.experimental.attested_inference import (
        ASSURANCE_PROVIDER_DECLARED,
        binding_present,
        evidence_digest,
        normalise_provider_evidence,
    )

BINDING = "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG0"

REAL_SHAPE = {
    "api_version": "aci/1",
    "text": ("cf2311d20672340340b966f46f15dbf398ee59e61f9d8c0e68860cc30f7494bb:"
             "72004a5f712da2e371121847031a5bf30a59fff9816862d26b54ec2cd7bb4ebc"),
    "signature": "0x71d0f2baa728c88f0c9fd2e9501565ce770ebcd90bfd3443d7c9fadac78abf24",
    "signing_address": "0x79a5061efe5a46b0d1f33b11cf1c5adbedae6b79",
    "signing_algo": "ecdsa",
    "receipt": {"api_version": "aci/1", "chat_id": "req_f74d2af5", "endpoint": "/v1/chat/completions"},
}


def test_assurance_is_capped_and_has_no_lever():
    """There must be no argument that raises the level. A level a caller can assert measures nothing."""
    import inspect
    out = normalise_provider_evidence(REAL_SHAPE, provider="example")
    assert out["assurance"] == ASSURANCE_PROVIDER_DECLARED
    params = set(inspect.signature(normalise_provider_evidence).parameters)
    for forbidden in ("assurance", "assurance_level", "tier", "attested", "trusted"):
        assert forbidden not in params, params


def test_unbound_evidence_says_so_in_plain_words():
    """The measured real case: the caller nonce never reached the signed structure."""
    out = normalise_provider_evidence(REAL_SHAPE, provider="example", expected_binding=BINDING)
    assert out["binding_present"] is False
    assert "NOT bound" in out["detail"]


def test_bound_evidence_is_recognised():
    ev = dict(REAL_SHAPE, receipt=dict(REAL_SHAPE["receipt"], caller_nonce=BINDING))
    out = normalise_provider_evidence(ev, provider="example", expected_binding=BINDING)
    assert out["binding_present"] is True
    assert "confirmed" in out["detail"]


@pytest.mark.parametrize("binding", ["", "short", None, 42, []])
def test_an_absent_or_tiny_binding_is_never_present(binding):
    """Otherwise a caller who forgot the binding would trivially satisfy the check — which is the
    exact failure mode this function exists to prevent."""
    assert binding_present(REAL_SHAPE, binding) is False


def test_credentials_never_survive_into_the_record():
    ev = dict(REAL_SHAPE, api_key="SECRET", Authorization="Bearer SECRET",
              nested={"x-secret-token": "SECRET", "keep": 1})
    out = normalise_provider_evidence(ev, provider="example")
    assert "SECRET" not in str(out)
    assert out["reported"]["nested"] == {"keep": 1}


def test_the_digest_ignores_key_order_but_not_content():
    a = evidence_digest({"b": 2, "a": 1})
    assert a == evidence_digest({"a": 1, "b": 2})
    assert a != evidence_digest({"a": 1, "b": 3})


def test_the_digest_is_taken_after_credential_removal():
    """Otherwise the digest would change when a credential changes, leaking that it changed."""
    assert evidence_digest({"a": 1, "api_key": "one"}) == evidence_digest({"a": 1, "api_key": "two"})


def test_a_non_dict_is_a_format_error_not_a_silent_pass():
    with pytest.raises(BundleFormatError):
        normalise_provider_evidence("not a dict", provider="example")
    with pytest.raises(BundleFormatError):
        evidence_digest(None)


def test_the_module_points_at_the_real_attestation_path():
    """A module that caps assurance owes the reader the way to a higher one."""
    from proofbundle.experimental import attested_inference as mod
    assert "verify_enclave_attestation" in (mod.__doc__ or "")
    assert "verify_enclave_attestation" in (normalise_provider_evidence.__doc__ or "")
