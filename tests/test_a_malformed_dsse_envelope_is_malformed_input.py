"""An envelope that cannot be decoded is malformed input (exit 2), not a crypto failure (exit 1).

`decision verify`, `outcome verify` and `relation-statement verify` state one exit contract in their help:
"1 crypto/verification failure · 2 malformed input or predicateType confusion". SPEC section 3 says the
same of a bundle: "a Base64 field that does not decode" is malformed (exit 2), and `verify` names the
case where "crypto could not even be evaluated" as the malformed-input path (exit 2).

Measured on main 65bd4b7a: an envelope whose `payload` is base64 without its padding (vector F95 of the
test package of the audit decision receipts draft, revision 07: V2-good with the two "=" at the end of `payload`
removed) ended `decision verify` with exit 1, "CRYPTO: FAIL" and "This receipt did NOT verify (crypto
failure)". The library had not checked any signature: `dsse._verify_and_load` refused the envelope before
the signature loop, and the verdict carried `crypto_ok` None. Every other refusal at the same place did
the same, under all three commands: a payload with a character outside the alphabet, a payload that is no
string or is absent, a payloadType that is absent, signatures that are empty, absent, no list or more than
the budget admits, and an envelope that is no JSON object.

THE PROPERTY: an envelope refused before any signature is checked ends with exit 2, prints
"CRYPTO: NOT_EVALUATED" and no crypto-failure line, and `--json` reports `crypto_ok` null. A signature that
was checked and does not verify stays a crypto failure (exit 1), and that includes a `sig` in another
base64 form, which is a signature that does not verify, and a payloadType other than the one pinned.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from proofbundle.cli import main
from proofbundle.decision import emit_decision_receipt
from proofbundle.emit import generate_signer
from proofbundle.outcome import emit_outcome_receipt
from proofbundle.relation_statement import emit_relation_statement

REPO = Path(__file__).resolve().parent.parent
_SIGNER = generate_signer()
_PUB = base64.b64encode(_SIGNER.public_key().public_bytes_raw()).decode("ascii")
_FREMD = base64.b64encode(generate_signer().public_key().public_bytes_raw()).decode("ascii")


def _mit_padding(make) -> dict:
    """A signed envelope whose payload ends in base64 padding, so that a case can take it away."""
    for laenge in range(1, 64):
        env = make("x" * laenge)
        if env["payload"].endswith("="):
            return env
    raise AssertionError("no envelope with a padded payload")


def _decision(n: str) -> dict:
    p = json.loads((REPO / "examples" / "decision_receipt_deny.json").read_text(encoding="utf-8"))
    p["decisionId"] = "dec-" + n
    return emit_decision_receipt(p, _SIGNER, strict=False)


def _outcome(n: str) -> dict:
    return emit_outcome_receipt(
        {"schemaVersion": "0.1.0", "outcomeId": "o-" + n, "decisionRef": {"sha256": "e" * 64},
         "executor": {"id": "executor:x", "keyId": "kid"}, "requestedActionDigest": {"sha256": "b" * 64},
         "status": "executed", "performedAt": "2026-07-14T10:00:00Z", "effectDigest": {"sha256": "c" * 64}},
        _SIGNER)


def _relation(n: str) -> dict:
    return emit_relation_statement(
        {"schemaVersion": "0.1.0", "statementId": "urn:uuid:" + n, "relationships": [
            {"relation": "retracts", "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": "d" * 64},
             "reasonCode": "withdrawal", "reason": "x", "declaredAt": "2026-09-29T00:00:00Z"}]},
        _SIGNER)


BEFEHLE = {
    "decision": (["decision", "verify"], _mit_padding(_decision)),
    "outcome": (["outcome", "verify"], _mit_padding(_outcome)),
    "relation-statement": (["relation-statement", "verify"], _mit_padding(_relation)),
}


def _ohne(env: dict, name: str) -> dict:
    return {k: v for k, v in env.items() if k != name}


# Each case: a name and how it changes the signed envelope. Every one is refused before a signature is checked.
FORMFEHLER = {
    "F95 payload without its padding": lambda g: dict(g, payload=g["payload"].rstrip("=")),
    "payload with a character outside the alphabet": lambda g: dict(g, payload="!" + g["payload"][1:]),
    "payload that is no string": lambda g: dict(g, payload=12),
    "payload absent": lambda g: _ohne(g, "payload"),
    "payloadType absent": lambda g: _ohne(g, "payloadType"),
    "signatures empty": lambda g: dict(g, signatures=[]),
    "signatures absent": lambda g: _ohne(g, "signatures"),
    "signatures no list": lambda g: dict(g, signatures=g["signatures"][0]),
    "signatures beyond the budget": lambda g: dict(g, signatures=[g["signatures"][0]] * 513),
    "envelope no JSON object": lambda g: [g],
}


def _lauf(tmp_path, befehl: str, env, *extra: str, pub: str = _PUB) -> tuple[int, str, str]:
    pfad = tmp_path / "env.json"
    pfad.write_text(json.dumps(env), encoding="utf-8")
    argv = BEFEHLE[befehl][0] + [str(pfad), "--pub", pub, *extra]
    import io  # noqa: PLC0415
    from contextlib import redirect_stderr, redirect_stdout  # noqa: PLC0415
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = main(argv)
    assert "Traceback" not in err.getvalue()
    return rc, out.getvalue(), err.getvalue()


@pytest.mark.parametrize("fall", sorted(FORMFEHLER))
@pytest.mark.parametrize("befehl", sorted(BEFEHLE))
def test_an_envelope_refused_before_any_signature_check_is_malformed_input(tmp_path, befehl, fall):
    env = FORMFEHLER[fall](BEFEHLE[befehl][1])
    rc, out, err = _lauf(tmp_path, befehl, env)
    assert rc == 2, (out, err)
    assert "CRYPTO: NOT_EVALUATED" in out, out
    assert "CRYPTO: FAIL" not in out, out
    assert "crypto failure" not in out, out
    assert err.strip(), "the refusal names its reason"


@pytest.mark.parametrize("fall", sorted(FORMFEHLER))
@pytest.mark.parametrize("befehl", sorted(BEFEHLE))
def test_the_json_report_of_such_an_envelope_says_crypto_was_not_evaluated(tmp_path, befehl, fall):
    env = FORMFEHLER[fall](BEFEHLE[befehl][1])
    rc, out, _ = _lauf(tmp_path, befehl, env, "--json")
    assert rc == 2, out
    bericht = json.loads(out)
    assert bericht["crypto_ok"] is None, bericht
    assert bericht["structure_ok"] is False, bericht
    assert bericht["ok"] is False, bericht


# Controls: they hold at 65bd4b7a and must keep holding.

@pytest.mark.parametrize("befehl", sorted(BEFEHLE))
def test_control_the_intact_envelope_verifies(tmp_path, befehl):
    rc, out, err = _lauf(tmp_path, befehl, BEFEHLE[befehl][1])
    assert rc == 0, (out, err)
    assert "CRYPTO: OK" in out


@pytest.mark.parametrize("befehl", sorted(BEFEHLE))
def test_control_a_sig_in_another_base64_form_is_a_signature_that_does_not_verify(tmp_path, befehl):
    g = BEFEHLE[befehl][1]
    sig = g["signatures"][0]["sig"]
    assert sig.endswith("=")
    env = dict(g, signatures=[dict(g["signatures"][0], sig=sig.rstrip("="))])
    rc, out, err = _lauf(tmp_path, befehl, env)
    assert rc == 1, (out, err)
    assert "CRYPTO: FAIL" in out


@pytest.mark.parametrize("befehl", sorted(BEFEHLE))
def test_control_another_key_is_a_crypto_failure(tmp_path, befehl):
    rc, out, err = _lauf(tmp_path, befehl, BEFEHLE[befehl][1], pub=_FREMD)
    assert rc == 1, (out, err)
    assert "CRYPTO: FAIL" in out


@pytest.mark.parametrize("befehl", sorted(BEFEHLE))
def test_control_another_payload_type_is_a_crypto_failure(tmp_path, befehl):
    env = dict(BEFEHLE[befehl][1], payloadType="application/json")
    rc, out, err = _lauf(tmp_path, befehl, env)
    assert rc == 1, (out, err)
    assert "CRYPTO: FAIL" in out
