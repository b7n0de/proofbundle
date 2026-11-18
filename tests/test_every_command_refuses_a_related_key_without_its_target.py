"""`decision verify`, `outcome verify` and `relation-statement verify` refuse a `--related-pub` without its
`--with-related` target, exit 2.

Deep gate 6.6.0 at d8881edc, iteration 1, finding Z6: B22 refused such a key in `decision verify` only. The two other
commands read the same options through the same reader, `_load_related`, and ended with exit 0, also for a value
that is no Base64, which docs/predicates/relation.md calls malformed input with exit 2. The check now lives in the
reader.
"""
from __future__ import annotations

import base64
import contextlib
import io
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import cli
from proofbundle.decision import emit_decision_receipt
from proofbundle.outcome import emit_outcome_receipt

_KEY = Ed25519PrivateKey.from_private_bytes(b"\x02" * 32)
_PUB64 = base64.b64encode(_KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode("ascii")

_DECISION = {"schemaVersion": "0.1.0", "decisionId": "urn:test:p", "decisionType": "preActionAuthorization",
             "decidedAt": "2026-01-01T00:00:00Z", "decisionMaker": {"id": "urn:test:maker"},
             "agent": {"id": "urn:test:agent"}, "principal": {"id": "urn:test:principal"},
             "proposedAction": {"actionType": "tool.call", "parametersDigest": {"sha256": "0" * 64}},
             "inputSnapshot": [], "policyBoundary": {"policyEngine": "t", "policyId": "urn:t", "decisionPath": "allow"},
             "evidenceRefs": [], "decision": {"verdict": "DENY", "reasonCodes": ["test"]}}
_OUTCOME = {"schemaVersion": "0.1.0", "outcomeId": "urn:test:outcome", "decisionRef": {"sha256": "0" * 64},
            "executor": {"id": "urn:test:executor"}, "requestedActionDigest": {"sha256": "0" * 64},
            "status": "refused", "performedAt": "2026-01-01T00:00:00Z"}


def _run(argv: list[str]) -> int:
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return cli.main(argv)


@pytest.fixture()
def receipts(tmp_path):
    decision = tmp_path / "decision.json"
    decision.write_text(json.dumps(emit_decision_receipt(_DECISION, _KEY, strict=False)), encoding="utf-8")
    outcome = tmp_path / "outcome.json"
    outcome.write_text(json.dumps(emit_outcome_receipt(_OUTCOME, _KEY)), encoding="utf-8")
    return {"decision": decision, "outcome": outcome}


@pytest.mark.parametrize("command", ["decision", "outcome"])
@pytest.mark.parametrize("value", ["%%%invalid-base64%%%", _PUB64], ids=["not-base64", "a-valid-key"])
def test_a_related_key_without_its_target_is_refused(receipts, command, value):
    base = [command, "verify", str(receipts[command]), "--pub", _PUB64, "--json"]
    assert _run(base) == 0
    assert _run(base + ["--related-pub", value]) == 2


@pytest.mark.parametrize("value", ["%%%invalid-base64%%%", _PUB64], ids=["not-base64", "a-valid-key"])
def test_the_shared_reader_refuses_a_related_key_without_its_target(value):
    """`relation-statement verify` reads the options through the same reader as the two commands above."""
    related, errors = cli._load_related([], base64.b64decode(_PUB64), [value])
    assert related == {} and errors and "--related-pub given for 0 --with-related" in errors[0]


def test_the_shared_reader_takes_no_key_and_no_target():
    assert cli._load_related([], base64.b64decode(_PUB64), []) == ({}, [])
