"""`present_with_key_binding` signs only a KB-JWT that `verify_key_binding` can read.

THE NEIGHBOUR of the SD-JWT finding of the 6.5.0 deep gate, the same class at the holder: `verify_key_binding`
reads the KB-JWT payload with `kbjwt._b64url_decode` and the strict reader under `DEFAULT_BUDGET`, and
`present_with_key_binding` signed without that reading. Measured at ac4129f7: an `aud` or a `nonce` of
1,000,001 characters was signed, and `verify_key_binding` answered ok False with the reason `string_len`.
"""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import kbjwt
from proofbundle.budget import DEFAULT_BUDGET
from _lastdeckel import KOSTEN_JE_ELEMENT, gedeckelt  # noqa: E402  (LAUF11-L3: a load built from a budget is capped)
from proofbundle.emit import generate_signer
from proofbundle.evalclaim import build_eval_claim, issuer_fingerprint
from proofbundle.sdjwt_issue import issue_sd_jwt, present_with_key_binding

ROOT_B64 = "cm9vdA=="
LIMIT = gedeckelt(DEFAULT_BUDGET.string_len, bytes_je_element=KOSTEN_JE_ELEMENT["string_len"])
IAT = 1792000000


def _raw(signer) -> bytes:
    return signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


@pytest.fixture(scope="module")
def issued():
    issuer, holder = generate_signer(), generate_signer()
    claim, _ = build_eval_claim(suite="safety", suite_version="v1", metric="accuracy", comparator=">=",
                                threshold="0.65", score="0.92", n=500, model_id="acme/model-x",
                                dataset_id="acme/set", issuer=issuer_fingerprint(issuer),
                                timestamp="2026-07-01T12:00:00Z", model_salt=b"0" * 16, dataset_salt=b"1" * 16)
    compact = issue_sd_jwt(claim, issuer, root_b64=ROOT_B64, holder_public_key=_raw(holder))
    return compact, issuer, holder


@pytest.mark.parametrize("member", ["aud", "nonce"])
def test_a_member_over_string_len_is_refused_before_the_holder_signs(member, issued):
    compact, _, holder = issued
    values = {"aud": "https://rp.example", "nonce": "n1", member: "x" * (LIMIT + 1)}
    with pytest.raises(ValueError, match="verify_key_binding cannot read"):
        present_with_key_binding(compact, holder, iat=IAT, **values)


@pytest.mark.parametrize("member", ["aud", "nonce"])
def test_a_member_at_the_bound_is_signed_and_verifies(member, issued):
    compact, issuer, holder = issued
    values = {"aud": "https://rp.example", "nonce": "n1", member: "x" * LIMIT}
    presented = present_with_key_binding(compact, holder, iat=IAT, **values)
    out = kbjwt.verify_key_binding(presented, _raw(holder), expected_aud=values["aud"],
                                   expected_nonce=values["nonce"], now=IAT)
    assert out["ok"] is True, out["detail"]
