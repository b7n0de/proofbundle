"""The SD-JWT producers write only a signature of the 64 bytes their EdDSA header names.

THE NEIGHBOUR of the `emit_bundle` finding of Codex pre-review 5 of the class fix after 6.5.0. `emit_bundle` measured
its budget with placeholders of the Ed25519 lengths, and a signer of another kind returned other lengths after it;
the fix checks the lengths on what the signer returns. `issue_sd_jwt` and `present_with_key_binding` check their
payload segment before signing and then wrote the signer's output, unchecked, as the last segment, which
`verify_sd_jwt` and `verify_key_binding` read too. The invariant is the same: a producer writes only what its own
verifier reads. Both now read the signature once as the bytes it holds and refuse, with the ValueError each already
uses for a refusal, a signature that is not 64 bytes.
"""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import kbjwt
from proofbundle.emit import generate_signer
from proofbundle.evalclaim import build_eval_claim, issuer_fingerprint
from proofbundle.sdjwt import verify_sd_jwt
from proofbundle.sdjwt_issue import issue_sd_jwt, present_with_key_binding

ROOT_B64 = "cm9vdA=="
IAT = 1792000000


class _Signer:
    """A signer of another kind: it signs with the real key unless told to return something else."""

    def __init__(self, inner, sig=None):
        self.inner, self.sig = inner, sig

    def sign(self, data):
        return self.inner.sign(data) if self.sig is None else self.sig

    def public_key(self):
        return self.inner.public_key()


def _raw(signer) -> bytes:
    return signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


@pytest.fixture(scope="module")
def keys_and_claim():
    issuer, holder = generate_signer(), generate_signer()
    claim, _ = build_eval_claim(suite="safety", suite_version="v1", metric="accuracy", comparator=">=",
                                threshold="0.65", score="0.92", n=500, model_id="acme/model-x",
                                dataset_id="acme/set", issuer=issuer_fingerprint(issuer),
                                timestamp="2026-07-01T12:00:00Z", model_salt=b"0" * 16, dataset_salt=b"1" * 16)
    return issuer, holder, claim


ANDERE = [("6,500,000 bytes, a segment past the 8 MiB of the verifier", b"s" * 6_500_000),
          ("65 bytes", b"s" * 65), ("63 bytes", b"s" * 63), ("no bytes", "s" * 64)]


@pytest.mark.parametrize("fall,sig", ANDERE, ids=[a[0] for a in ANDERE])
def test_the_issuer_refuses_a_signature_of_another_length(keys_and_claim, fall, sig):
    issuer, holder, claim = keys_and_claim
    with pytest.raises(ValueError, match="no 64-byte Ed25519 signature"):
        issue_sd_jwt(claim, _Signer(issuer, sig), root_b64=ROOT_B64, holder_public_key=_raw(holder))


@pytest.mark.parametrize("fall,sig", ANDERE, ids=[a[0] for a in ANDERE])
def test_the_holder_refuses_a_signature_of_another_length(keys_and_claim, fall, sig):
    issuer, holder, claim = keys_and_claim
    compact = issue_sd_jwt(claim, issuer, root_b64=ROOT_B64, holder_public_key=_raw(holder))
    with pytest.raises(ValueError, match="no 64-byte Ed25519 signature"):
        present_with_key_binding(compact, _Signer(holder, sig), iat=IAT, aud="https://rp.example", nonce="n1")


def test_control_a_signer_of_another_kind_with_an_ed25519_signature_is_written_and_verifies(keys_and_claim):
    issuer, holder, claim = keys_and_claim
    compact = issue_sd_jwt(claim, _Signer(issuer), root_b64=ROOT_B64, holder_public_key=_raw(holder))
    assert compact == issue_sd_jwt(claim, issuer, root_b64=ROOT_B64, holder_public_key=_raw(holder))
    assert verify_sd_jwt(compact, _raw(issuer))["sig_ok"] is True
    presented = present_with_key_binding(compact, _Signer(holder), iat=IAT, aud="https://rp.example", nonce="n1")
    out = kbjwt.verify_key_binding(presented, _raw(holder), expected_aud="https://rp.example",
                                   expected_nonce="n1", now=IAT)
    assert out["ok"] is True, out["detail"]
