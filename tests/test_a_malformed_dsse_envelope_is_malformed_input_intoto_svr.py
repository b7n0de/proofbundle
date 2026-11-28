"""`intoto --verify` and `svr --verify`: an envelope refused before any signature is checked is malformed
input (exit 2), as under `decision verify`, `outcome verify` and `relation-statement verify`.

Measured on main 65bd4b7a: both commands end every verdict that is not a pass with exit 1, also when
`dsse._verify_and_load` refused the envelope before the signature loop (a payload without its base64
padding, vector OP20 of the HCTP delivery -3 and F95 of the audit decision receipts draft, revision 07, empty
signatures, OP17, and the other forms below). `svr --verify` already ends a malformed statement with exit 2.
The lines printed stay as they are, so the reason is named as before
(`tests/test_the_dsse_verify_commands_name_each_reason.py`); only the exit code changes.

A checked signature that does not verify stays exit 1, and so does a payload that decodes but is no JSON
statement: the signature was checked over it, and these two commands judge the statement layer in their
verdict.
"""
from __future__ import annotations

import base64
import io
import json
from contextlib import redirect_stderr, redirect_stdout

import pytest

from proofbundle import dsse, intoto
from proofbundle.cli import main
from proofbundle.emit import generate_signer

_SIGNER = generate_signer()
_PUB = base64.b64encode(_SIGNER.public_key().public_bytes_raw()).decode("ascii")
_EINTRAG = {"name": "artifact", "digest": {"sha256": "a" * 64}}
_PRAEDIKATE = {
    "intoto": (intoto.EVAL_RESULT_PREDICATE_TYPE, {
        "verifier": {"id": "https://b7n0de.com/proofbundle"}, "evaluatedAt": "2026-10-17T12:00:00Z",
        "suite": {"name": "s", "version": "1"},
        "claims": [{"metric": "m", "comparator": ">=", "threshold": "0.5", "passed": True}], "sampleSize": 1,
        "commitments": {"model": {"alg": "sha256-salted-v1", "value": "a1" * 32, "salted": True},
                        "dataset": {"alg": "sha256-salted-v1", "value": "b2" * 32, "salted": True}},
        "assuranceLevel": "self_attested", "subjectProfile": "receipt"}),
    "svr": (intoto.SVR_PREDICATE_TYPE, {"verifier": {"id": "https://example.invalid/v"},
                                        "timeCreated": "2026-10-17T12:00:00Z", "properties": []}),
}


def _legacy(st) -> bytes:
    return json.dumps(st, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _gut(befehl: str) -> dict:
    typ, praedikat = _PRAEDIKATE[befehl]
    st = {"_type": "https://in-toto.io/Statement/v1", "subject": [dict(_EINTRAG)], "predicateType": typ,
          "predicate": json.loads(json.dumps(praedikat))}
    while len(_legacy(st)) % 3 == 0:
        st["subject"][0]["name"] += "x"
    return dsse.sign_envelope(_legacy(st), _SIGNER, payload_type=intoto.INTOTO_STATEMENT_PAYLOAD_TYPE)


def _ohne(env: dict, name: str) -> dict:
    return {k: v for k, v in env.items() if k != name}


FORMFEHLER = {
    "F95 OP20 payload without its padding": lambda g: dict(g, payload=g["payload"].rstrip("=")),
    "payload with a character outside the alphabet": lambda g: dict(g, payload="!" + g["payload"][1:]),
    "payload that is no string": lambda g: dict(g, payload=12),
    "payload absent": lambda g: _ohne(g, "payload"),
    "payloadType absent": lambda g: _ohne(g, "payloadType"),
    "OP17 signatures empty": lambda g: dict(g, signatures=[]),
    "signatures absent": lambda g: _ohne(g, "signatures"),
    "signatures no list": lambda g: dict(g, signatures=g["signatures"][0]),
    "signatures beyond the budget": lambda g: dict(g, signatures=[g["signatures"][0]] * 513),
    "envelope no JSON object": lambda g: [g],
}


def _lauf(tmp_path, befehl: str, env) -> tuple[int, str]:
    pfad = tmp_path / "env.json"
    pfad.write_text(json.dumps(env), encoding="utf-8")
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = main([befehl, str(pfad), "--verify", "--pub", _PUB])
    assert "Traceback" not in err.getvalue()
    return rc, out.getvalue()


@pytest.mark.parametrize("fall", sorted(FORMFEHLER))
@pytest.mark.parametrize("befehl", sorted(_PRAEDIKATE))
def test_an_envelope_refused_before_any_signature_check_is_malformed_input(tmp_path, befehl, fall):
    rc, out = _lauf(tmp_path, befehl, FORMFEHLER[fall](_gut(befehl)))
    assert rc == 2, out
    assert "=> FAILED" in out and "no signature verifies" not in out, out


@pytest.mark.parametrize("befehl", sorted(_PRAEDIKATE))
def test_control_the_intact_envelope_passes(tmp_path, befehl):
    assert _lauf(tmp_path, befehl, _gut(befehl))[0] == 0


@pytest.mark.parametrize("befehl", sorted(_PRAEDIKATE))
def test_control_a_sig_in_another_base64_form_stays_exit_1(tmp_path, befehl):
    g = _gut(befehl)
    sig = g["signatures"][0]["sig"]
    rc, out = _lauf(tmp_path, befehl, dict(g, signatures=[dict(g["signatures"][0], sig=sig.rstrip("="))]))
    assert rc == 1, out


@pytest.mark.parametrize("befehl", sorted(_PRAEDIKATE))
def test_control_a_signed_payload_that_is_no_json_stays_exit_1(tmp_path, befehl):
    env = dsse.sign_envelope(b"not json", _SIGNER, payload_type=intoto.INTOTO_STATEMENT_PAYLOAD_TYPE)
    rc, out = _lauf(tmp_path, befehl, env)
    assert rc == 1, out
