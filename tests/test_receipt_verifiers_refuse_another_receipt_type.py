"""A correctly signed receipt of one type is refused by the verifier of another, explicitly chosen type.

`decision verify`, `outcome verify` and `relation-statement verify` each name the one predicate they read.
Each verifier gets the three envelopes, all signed under the same throwaway key so that the signature
holds in every pair. The verifier of the matching type verifies; for the other two it answers exit 2
with ``ok`` false and ``predicate_type_ok`` false, and its errors name the predicateType it found, so the
refusal comes from the type and not only from the members the other predicate lacks. No verifier
guesses the type from the shape of the payload.
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import json
from pathlib import Path

import pytest

from proofbundle.cli import main
from proofbundle.decision import emit_decision_receipt
from proofbundle.emit import generate_signer
from proofbundle.outcome import emit_outcome_receipt
from proofbundle.relation_statement import emit_relation_statement

_EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "decision_receipt_allow.json"
_TYPES = ("decision", "outcome", "relation-statement")
_PREDICATE = {
    "decision": "decision-receipt/v0.1",
    "outcome": "action-outcome/v0.1",
    "relation-statement": "relation-statement/v0.1",
}
# Inside the decision's validity window, so that the decision verifies under its own verifier.
_AT = "2026-07-09T11:16:00Z"


def _run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = main(argv)
        except SystemExit as exc:  # argparse
            rc = exc.code
    return int(rc or 0), out.getvalue(), err.getvalue()


@pytest.fixture(scope="module")
def envelopes(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, str]:
    d = tmp_path_factory.mktemp("receipt_types")
    key = generate_signer()
    pub = base64.b64encode(key.public_key().public_bytes_raw()).decode()
    p = json.loads(_EXAMPLE.read_text())
    p["validity"] = {"audience": ["observer-1"], "nonce": "n-1", "expiresAt": "2026-07-09T11:20:00Z"}
    dec = emit_decision_receipt(p, key)
    root = hashlib.sha256(base64.b64decode(dec["payload"])).hexdigest()
    out = emit_outcome_receipt({
        "schemaVersion": "0.1.0", "outcomeId": "o-1", "decisionRef": {"sha256": root},
        "executor": {"id": "forge:agent-bot"}, "requestedActionDigest": {"sha256": "ab" * 32},
        "status": "executed", "performedAt": _AT, "effectDigest": {"sha256": "cd" * 32}}, key)
    rs = emit_relation_statement({
        "schemaVersion": "0.1.0", "statementId": "rs-1",
        "relationships": [{"relation": "supersedes",
                           "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": root}}]}, key)
    for name, env in zip(_TYPES, (dec, out, rs)):
        (d / f"{name}.json").write_text(json.dumps(env))
    return d, pub


def _verify(cmd: str, name: str, envelopes: tuple[Path, str]) -> tuple[int, dict]:
    d, pub = envelopes
    argv = [cmd, "verify", str(d / f"{name}.json"), "--pub", pub, "--json"]
    if cmd != "relation-statement":
        argv += ["--verification-time", _AT]
    rc, so, se = _run(argv)
    return rc, json.loads(so)


@pytest.mark.parametrize("cmd", _TYPES)
def test_the_verifier_of_the_matching_type_verifies(cmd: str, envelopes: tuple[Path, str]) -> None:
    rc, j = _verify(cmd, cmd, envelopes)
    assert (rc, j["ok"], j["predicate_type_ok"]) == (0, True, True), j


@pytest.mark.parametrize("cmd,name", [(c, n) for c in _TYPES for n in _TYPES if c != n])
def test_a_signed_receipt_of_another_type_is_refused_for_its_type(
        cmd: str, name: str, envelopes: tuple[Path, str]) -> None:
    rc, j = _verify(cmd, name, envelopes)
    assert rc == 2, j
    assert j["ok"] is False
    assert j["predicate_type_ok"] is False
    found = [e for e in j["errors"] if str(e).startswith("predicateType is ")]
    assert len(found) == 1, j["errors"]
    assert _PREDICATE[name] in found[0] and f"expected {_PREDICATE[cmd]}" in found[0]
