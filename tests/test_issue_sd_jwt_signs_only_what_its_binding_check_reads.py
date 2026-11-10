"""`issue_sd_jwt` signs only a payload that `check_binds_bundle` and `verify_sd_jwt` can read.

WHERE THIS COMES FROM. The deep gate of 6.5.0, iteration 1 (tag note of v6.5.0, "Known limitations of
this release"): `issue_sd_jwt` accepted a `vct` of 1,000,001 characters and emitted a compact
serialization that `check_binds_bundle` then refused, the same in 6.4.0. Measured again at ac4129f7,
together with two more inputs of the same class: a `vct` of 900,000 characters outside the BMP (each
written as a pair of `\\u` escapes, so the payload text passes 8 MiB) and a `root_b64` of 1,000,001
characters.

THE CLASS. The issuer produced what its own checker refuses: `check_binds_bundle` reads the payload
with `loads_strict` under `DEFAULT_BUDGET` (`string_len` 1,000,000 characters per string, `input_bytes`
8 MiB per document, and the node and depth bounds), and `issue_sd_jwt` signed without that reading.

`verify_sd_jwt`, the package's other verifier of the same serialization, first refuses a base64url segment
longer than the same 8 MiB (`sdjwt._b64url_decode`), so a `vct` of 600,000 characters outside the BMP
(7.2 MB of payload text, 9.6 million characters of segment) was bound by `check_binds_bundle` and refused
by `verify_sd_jwt`.

THE FIX. The issuer reads the payload segment it is about to sign as both verifiers read it, with
`sdjwt._b64url_decode` and the very reader of `check_binds_bundle` (`sdjwt_issue._read_payload_text`),
under the same budget, before the signature, and refuses with a ValueError what they refuse. At the
bounds the three agree.
"""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle.budget import DEFAULT_BUDGET
from _lastdeckel import KOSTEN_JE_ELEMENT, gedeckelt  # noqa: E402  (LAUF11-L3: a load built from a budget is capped)
from proofbundle.emit import generate_signer
from proofbundle.evalclaim import build_eval_claim, issuer_fingerprint
from proofbundle.sdjwt import verify_sd_jwt
from proofbundle.sdjwt_issue import check_binds_bundle, issue_sd_jwt

ROOT_B64 = "cm9vdA=="
LIMIT = gedeckelt(DEFAULT_BUDGET.string_len, bytes_je_element=KOSTEN_JE_ELEMENT["string_len"])


@pytest.fixture(scope="module")
def signer_and_claim():
    signer = generate_signer()
    claim, _ = build_eval_claim(suite="safety", suite_version="v1", metric="accuracy", comparator=">=",
                                threshold="0.65", score="0.92", n=500, model_id="acme/model-x",
                                dataset_id="acme/set", issuer=issuer_fingerprint(signer),
                                timestamp="2026-07-01T12:00:00Z", model_salt=b"0" * 16, dataset_salt=b"1" * 16)
    return signer, claim


REFUSED = {
    "vct one over string_len": {"vct": "v" * (LIMIT + 1)},
    "vct whose payload text passes input_bytes": {"vct": "\U0001F600" * 900_000},
    "root_b64 one over string_len": {"root_b64": "r" * (LIMIT + 1)},
    "vct whose segment passes the pre-decode bound": {"vct": "\U0001F600" * 600_000},
}


@pytest.mark.parametrize("label", sorted(REFUSED))
def test_the_issuer_refuses_before_signing_what_the_binding_check_cannot_read(label, signer_and_claim):
    signer, claim = signer_and_claim
    kwargs = dict(REFUSED[label])
    root = kwargs.pop("root_b64", ROOT_B64)
    with pytest.raises(ValueError, match="check_binds_bundle"):
        issue_sd_jwt(claim, signer, root_b64=root, **kwargs)


@pytest.mark.parametrize("label", sorted(REFUSED))
def test_no_signature_is_made_for_a_refused_payload(label, signer_and_claim, monkeypatch):
    signer, claim = signer_and_claim
    kwargs = dict(REFUSED[label])
    root = kwargs.pop("root_b64", ROOT_B64)
    signed = []

    class Counting:
        def __init__(self, inner):
            self._inner = inner

        def sign(self, data):
            signed.append(len(data))
            return self._inner.sign(data)

        def public_key(self):
            return self._inner.public_key()

    with pytest.raises(ValueError):
        issue_sd_jwt(claim, Counting(signer), root_b64=root, **kwargs)
    assert signed == []


@pytest.mark.parametrize("kwargs", [{"vct": "v" * LIMIT}, {"root_b64": "r" * LIMIT}],
                         ids=["vct-at-the-bound", "root-at-the-bound"])
def test_at_the_bound_the_issuer_signs_and_the_binding_check_binds(kwargs, signer_and_claim):
    signer, claim = signer_and_claim
    kwargs = dict(kwargs)
    root = kwargs.pop("root_b64", ROOT_B64)
    compact = issue_sd_jwt(claim, signer, root_b64=root, **kwargs)
    assert check_binds_bundle(compact, claim, root) is True
    raw = signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    assert verify_sd_jwt(compact, raw)["sig_ok"] is True


def test_an_ordinary_vct_is_signed_as_before(signer_and_claim):
    signer, claim = signer_and_claim
    compact = issue_sd_jwt(claim, signer, root_b64=ROOT_B64, vct="https://example.org/vct/x")
    assert check_binds_bundle(compact, claim, ROOT_B64) is True
