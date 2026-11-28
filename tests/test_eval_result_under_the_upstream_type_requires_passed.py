"""Under the type URI of the upstream eval-result draft, the library demands `passed` in every claim, as the CLI does.

The upstream draft (in-toto/attestation#575, mirrored in docs/upstream/eval-result.md) writes `passed` in every
claim, "the producer's signed threshold verdict"; our v0.1 (https://b7n0de.com/attestation/eval-result/v0.1) leaves
it optional. Measured at 65bd4b7a and again at 121cd089: `verify_eval_result_dsse` with `expected_predicate_type`
set to the upstream URI returned ok True for a claim without `passed`, while `proofbundle intoto --verify` refused
the same signed statement with exit 1. Library and CLI are now equally strict.

Unchanged and held here as controls: our v0.1 without `passed` still verifies in both, the upstream statement with
`passed` still verifies in the library when the caller expects that type, and the CLI still refuses the upstream
type (exit 1), with or without `passed`, because it reads only our two types.
"""
from __future__ import annotations

import base64
import copy
import io
import json
from contextlib import redirect_stderr, redirect_stdout

import pytest

from proofbundle import dsse, intoto
from proofbundle.cli import main
from proofbundle.emit import generate_signer

UPSTREAM = "https://in-toto.io/attestation/eval-result/v0.1"


def _statement(predicate_type: str, *, passed: bool) -> dict:
    claim = {"metric": "m", "comparator": ">=", "threshold": "0.5"}
    if passed:
        claim["passed"] = True
    return {"_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "artifact", "digest": {"sha256": "a" * 64}}],
            "predicateType": predicate_type,
            "predicate": {"verifier": {"id": "https://b7n0de.com/proofbundle"}, "evaluatedAt": "2026-10-17T12:00:00Z",
                          "suite": {"name": "s", "version": "1"}, "claims": [claim, dict(claim, metric="n")],
                          "sampleSize": 1,
                          "commitments": {"model": {"alg": "sha256-salted-v1", "value": "a1" * 32, "salted": True},
                                          "dataset": {"alg": "sha256-salted-v1", "value": "b2" * 32, "salted": True}},
                          "assuranceLevel": "self_attested", "subjectProfile": "receipt"}}


@pytest.fixture(scope="module")
def signer():
    return generate_signer()


def _sign(signer, statement: dict) -> dict:
    body = json.dumps(statement, separators=(",", ":"), sort_keys=True).encode()
    return dsse.sign_envelope(body, signer, payload_type=intoto.INTOTO_STATEMENT_PAYLOAD_TYPE)


def _pub(signer) -> bytes:
    return signer.public_key().public_bytes_raw()


def _cli(signer, env: dict, tmp_path) -> tuple[int, str]:
    f = tmp_path / "e.json"
    f.write_text(json.dumps(env), encoding="utf-8")
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = main(["intoto", str(f), "--verify", "--pub", base64.b64encode(_pub(signer)).decode()])
    return rc, out.getvalue() + err.getvalue()


def test_the_library_refuses_an_upstream_claim_without_passed(signer):
    r = intoto.verify_eval_result_dsse(_sign(signer, _statement(UPSTREAM, passed=False)), _pub(signer),
                                       expected_predicate_type=UPSTREAM)
    assert r["signature_ok"] is True, r
    assert r["ok"] is False, r
    assert r["predicate_claim_ok"] is False, r
    assert r["predicate_member_detail"].startswith("predicate claims[0].passed:"), r


def test_the_library_refuses_it_also_without_a_type_check(signer):
    # The contract follows the type the signed statement declares, not the type the caller expected.
    r = intoto.verify_eval_result_dsse(_sign(signer, _statement(UPSTREAM, passed=False)), _pub(signer),
                                       expected_predicate_type=None)
    assert r["ok"] is False, r
    assert "passed" in r["predicate_member_detail"], r


def test_one_claim_without_passed_is_enough(signer):
    st = _statement(UPSTREAM, passed=True)
    del st["predicate"]["claims"][1]["passed"]
    r = intoto.verify_eval_result_dsse(_sign(signer, st), _pub(signer), expected_predicate_type=UPSTREAM)
    assert r["ok"] is False, r
    assert r["predicate_member_detail"].startswith("predicate claims[1].passed:"), r


def test_control_the_upstream_claim_with_passed_verifies_in_the_library(signer):
    r = intoto.verify_eval_result_dsse(_sign(signer, _statement(UPSTREAM, passed=True)), _pub(signer),
                                       expected_predicate_type=UPSTREAM)
    assert r["ok"] is True, r


def test_control_our_v01_without_passed_still_verifies_in_both(signer, tmp_path):
    env = _sign(signer, _statement(intoto.EVAL_RESULT_PREDICATE_TYPE, passed=False))
    assert intoto.verify_eval_result_dsse(env, _pub(signer))["ok"] is True
    rc, text = _cli(signer, env, tmp_path)
    assert rc == 0, text


@pytest.mark.parametrize("passed", [False, True])
def test_the_cli_refuses_the_upstream_type_as_before(signer, tmp_path, passed):
    rc, text = _cli(signer, _sign(signer, _statement(UPSTREAM, passed=passed)), tmp_path)
    assert rc == 1, text


def test_library_and_cli_agree_on_an_upstream_claim_without_passed(signer, tmp_path):
    env = _sign(signer, _statement(UPSTREAM, passed=False))
    lib_ok = intoto.verify_eval_result_dsse(copy.deepcopy(env), _pub(signer), expected_predicate_type=UPSTREAM)["ok"]
    rc, text = _cli(signer, env, tmp_path)
    assert (lib_ok, rc != 0) == (False, True), text
