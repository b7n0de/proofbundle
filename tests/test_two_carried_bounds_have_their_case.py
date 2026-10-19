"""Two bounds the change carries, each held by a case of its own.

The second reading of 4be8f120 took each fix of the change back one at a time in a copy, and two of 51 left
every test green. The freshness bound of `policy.evaluate_policy`: a `sd_jwt.max_iat_age_seconds` past the
integer budget raised `ValueError` out of the freshness check before, and fails it closed now. And
`anchors_chia_add._json_bytes`, which maps a proof without a JSON form to `ChiaRpcError`; the path to it needs a
running chia node, so the case calls the helper itself.
"""
from __future__ import annotations

import warnings

import pytest

from proofbundle import generate_signer, verify_bundle
from proofbundle.anchors_chia_add import ChiaRpcError, _json_bytes
from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt
from proofbundle.policy import evaluate_policy


def _bundle():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        claim, _ = build_eval_claim(suite="demo-suite", suite_version="1", metric="acc", comparator=">=",
                                    threshold="0.80", score="0.9", n=100, model_id="m", dataset_id="d",
                                    issuer="placeholder", timestamp="2026-07-09T10:00:00Z",
                                    assurance_level="reproduced")
        bundle = emit_eval_receipt(claim, generate_signer())
    return bundle, verify_bundle(bundle)


def _policy(age):
    return {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "p", "sd_jwt": {"max_iat_age_seconds": age}}


def test_a_freshness_bound_past_the_integer_budget_fails_the_check_closed():
    bundle, result = _bundle()
    verdict = evaluate_policy(bundle, result, _policy(10**5000))
    assert verdict["policy_ok"] is False
    freshness = [c for c in verdict["checks"] if c["name"] == "policy:freshness"]
    assert len(freshness) == 1 and freshness[0]["ok"] is False, freshness
    assert "past the integer budget" in freshness[0]["detail"], freshness[0]["detail"]


def test_a_negative_bound_past_the_integer_budget_is_a_verdict_too():
    bundle, result = _bundle()
    assert evaluate_policy(bundle, result, _policy(-(10**5000)))["policy_ok"] is False


@pytest.mark.parametrize("proof", [{"network": 10**5000}, {"network": b"x"}, {"network": {1}}],
                         ids=["integer past the digit cap", "bytes", "set"])
def test_a_proof_without_a_json_form_is_the_rpc_error(proof):
    with pytest.raises(ChiaRpcError):
        _json_bytes(proof)


def test_a_proof_with_a_json_form_is_its_bytes():
    assert _json_bytes({"network": "mainnet"}) == b'{"network": "mainnet"}'
