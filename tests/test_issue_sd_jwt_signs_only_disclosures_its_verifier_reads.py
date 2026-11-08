"""`issue_sd_jwt` signs only disclosures that `verify_sd_jwt` can read.

THE NEIGHBOUR of the payload finding of the 6.5.0 deep gate (tests/test_issue_sd_jwt_signs_only_what_its_binding_
check_reads.py), the same class in the same function: `verify_sd_jwt` reads each disclosure with
`sdjwt._b64url_decode` and the strict reader under `DEFAULT_BUDGET`, and `issue_sd_jwt` wrote the openings
unjudged. Measured at ac4129f7: a `model_id_opening` whose identifier has 1,000,001 characters was signed, and
`verify_sd_jwt` answered structure_ok False, "an SD-JWT disclosure refused: verification budget exceeded:
string_len". The issuer now reads each disclosure as `verify_sd_jwt` reads it, before the signature.
"""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle.budget import DEFAULT_BUDGET
from proofbundle.emit import generate_signer
from proofbundle.evalclaim import build_eval_claim, issuer_fingerprint
from proofbundle.sdjwt import verify_sd_jwt
from proofbundle.sdjwt_issue import issue_sd_jwt

ROOT_B64 = "cm9vdA=="
LIMIT = DEFAULT_BUDGET.string_len


@pytest.fixture(scope="module")
def signer_and_claim():
    signer = generate_signer()
    claim, _ = build_eval_claim(suite="safety", suite_version="v1", metric="accuracy", comparator=">=",
                                threshold="0.65", score="0.92", n=500, model_id="acme/model-x",
                                dataset_id="acme/set", issuer=issuer_fingerprint(signer),
                                timestamp="2026-07-01T12:00:00Z", model_salt=b"0" * 16, dataset_salt=b"1" * 16)
    return signer, claim


@pytest.mark.parametrize("name", ["model_id_opening", "dataset_id_opening"])
def test_an_opening_over_string_len_is_refused_before_signing(name, signer_and_claim):
    signer, claim = signer_and_claim
    with pytest.raises(ValueError, match=f"the {name} disclosure is one verify_sd_jwt cannot read"):
        issue_sd_jwt(claim, signer, root_b64=ROOT_B64, **{name: ("x" * (LIMIT + 1), "00")})


@pytest.mark.parametrize("name", ["model_id_opening", "dataset_id_opening"])
def test_an_opening_at_the_bound_is_signed_and_verifies(name, signer_and_claim):
    signer, claim = signer_and_claim
    compact = issue_sd_jwt(claim, signer, root_b64=ROOT_B64, **{name: ("x" * LIMIT, "00")})
    out = verify_sd_jwt(compact, signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    assert out["structure_ok"] is True and out["sig_ok"] is True, out
