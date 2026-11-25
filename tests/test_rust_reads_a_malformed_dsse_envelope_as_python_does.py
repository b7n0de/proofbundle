"""The Rust second verifier ends a DSSE envelope refused before any signature check as Python does.

`proofbundle decision verify`, `outcome verify` and `relation-statement verify` end an envelope that is
refused before any signature is checked with exit 2, malformed input ("1 crypto/verification failure ·
2 malformed input or predicateType confusion" in their help). `pb_verify_rs verify-relation` (the
decision and outcome path) and `verify-relation-statement` read the same envelope and promise the same
0/1/2/3 contract.

Measured with the two patches that set this contract in Python on 65bd4b7a: for all ten forms below,
under all three commands, Python ended with exit 2 and `pb_verify_rs` with exit 1 ("crypto: base64 decode
failed ..."). Thirty disagreements, and no differential of the repository held one, because the
relation corpus of `tools/pb_verify_rs/crosscheck.py` carries no envelope that is refused before the
signature. The same envelopes in the two base64 alphabets of DSSE were measured in the same run: the
standard (RFC 4648 §4) and the URL-safe (§5) alphabet, each with padding, verify in both; each without
padding is refused in both, by Python with exit 2 and by Rust with exit 1.

THE PROPERTY: for each form, each command and each base64 form of the payload, Python and Rust end with
the same exit code; the ten forms end with 2 in both, and the controls (another key, another payloadType,
a `sig` without its padding) stay a verification failure, 1, in both. `verify-dsse`, the type-agnostic
primitive, agrees with `dsse.verify_envelope` on the four payload forms.
"""
from __future__ import annotations

import base64
import io
import json
import subprocess
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest

from proofbundle import dsse
from proofbundle.cli import main
from proofbundle.decision import emit_decision_receipt
from proofbundle.emit import generate_signer
from proofbundle.outcome import emit_outcome_receipt
from proofbundle.relation_statement import emit_relation_statement

try:
    import _pb_verify_rs  # tests/_pb_verify_rs.py, the one way to the binary
except ModuleNotFoundError:  # `python -m unittest tests.<module>` puts the root on sys.path
    from tests import _pb_verify_rs

REPO = Path(__file__).resolve().parent.parent
_SIGNER = generate_signer()
_PUB_RAW = _SIGNER.public_key().public_bytes_raw()
_PUB = base64.b64encode(_PUB_RAW).decode("ascii")
_FREMD = base64.b64encode(generate_signer().public_key().public_bytes_raw()).decode("ascii")


def _zwei_alphabete(make) -> dict:
    """A signed envelope whose payload ends in padding and carries a "+" or "/" in the standard alphabet,
    so that its URL-safe form differs from it. Plain ASCII JSON yields "+" only from a "~" or ">" at the
    right offset, hence the "~~~" in the varied field."""
    for i in range(1, 400):
        env = make("x" * (i % 40 + 1) + "~~~" + str(i))
        p = env["payload"]
        if p.endswith("=") and ("+" in p or "/" in p):
            return env
    raise AssertionError("no envelope with a padded payload that differs between the alphabets")


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


# Python verb, Rust subcommand, signed envelope.
BEFEHLE = {
    "decision": (["decision", "verify"], "verify-relation", _zwei_alphabete(_decision)),
    "outcome": (["outcome", "verify"], "verify-relation", _zwei_alphabete(_outcome)),
    "relation-statement": (["relation-statement", "verify"], "verify-relation-statement",
                           _zwei_alphabete(_relation)),
}


def _ohne(env: dict, name: str) -> dict:
    return {k: v for k, v in env.items() if k != name}


def _url(p: str) -> str:
    return p.replace("+", "-").replace("/", "_")


# The ten forms, each refused before a signature is checked: (form, expected exit in both).
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

# The four forms of the payload: the two alphabets of DSSE, each with and without padding.
ALPHABETE = {
    "standard, padded": (lambda g: dict(g), 0),
    "URL-safe, padded": (lambda g: dict(g, payload=_url(g["payload"])), 0),
    "standard, unpadded": (lambda g: dict(g, payload=g["payload"].rstrip("=")), 2),
    "URL-safe, unpadded": (lambda g: dict(g, payload=_url(g["payload"]).rstrip("=")), 2),
}

# Signatures that are checked and do not verify: a verification failure on both sides.
KONTROLLEN = {
    "another key": (lambda g: g, _FREMD),
    "another payloadType": (lambda g: dict(g, payloadType="application/json"), _PUB),
    "sig without its padding": (lambda g: dict(g, signatures=[dict(g["signatures"][0],
                                                                    sig=g["signatures"][0]["sig"].rstrip("="))]),
                                _PUB),
}


def _python(befehl: str, pfad: Path, pub: str) -> "tuple[int, str]":
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = main(BEFEHLE[befehl][0] + [str(pfad), "--pub", pub])
    return rc, out.getvalue() + err.getvalue()


def _rust(befehl: str, pfad: Path, pub: str) -> "tuple[int, str]":
    binary = _pb_verify_rs.binary_or_skip()
    done = subprocess.run([str(binary), BEFEHLE[befehl][1], str(pfad), "--pub", pub],  # noqa: S603
                          capture_output=True, text=True, timeout=60)
    return done.returncode, done.stdout + done.stderr


def _beide(tmp_path: Path, befehl: str, env, pub: str = _PUB) -> "tuple[int, str, int, str]":
    pfad = tmp_path / "env.json"
    pfad.write_text(json.dumps(env), encoding="utf-8")
    py_rc, py_out = _python(befehl, pfad, pub)
    rs_rc, rs_out = _rust(befehl, pfad, pub)
    return py_rc, py_out, rs_rc, rs_out


def test_precondition_the_payload_differs_between_the_alphabets():
    for _, _, env in BEFEHLE.values():
        assert env["payload"].endswith("=")
        assert _url(env["payload"]) != env["payload"]


@pytest.mark.parametrize("fall", sorted(FORMFEHLER))
@pytest.mark.parametrize("befehl", sorted(BEFEHLE))
def test_rust_ends_an_envelope_refused_before_any_signature_check_as_python_does(tmp_path, befehl, fall):
    py_rc, py_out, rs_rc, rs_out = _beide(tmp_path, befehl, FORMFEHLER[fall](BEFEHLE[befehl][2]))
    assert (py_rc, rs_rc) == (2, 2), (py_out, rs_out)
    bericht = json.loads(rs_out.strip().splitlines()[-1])
    assert bericht["lineage"] is None, bericht
    assert bericht["reasons"] and not any(r.startswith("crypto:") for r in bericht["reasons"]), bericht


@pytest.mark.parametrize("form", sorted(ALPHABETE))
@pytest.mark.parametrize("befehl", sorted(BEFEHLE))
def test_rust_reads_both_alphabets_of_the_payload_as_python_does(tmp_path, befehl, form):
    mache, erwartet = ALPHABETE[form]
    py_rc, py_out, rs_rc, rs_out = _beide(tmp_path, befehl, mache(BEFEHLE[befehl][2]))
    assert (py_rc, rs_rc) == (erwartet, erwartet), (py_out, rs_out)


@pytest.mark.parametrize("fall", sorted(KONTROLLEN))
@pytest.mark.parametrize("befehl", sorted(BEFEHLE))
def test_control_a_signature_that_does_not_verify_stays_exit_1_in_both(tmp_path, befehl, fall):
    mache, pub = KONTROLLEN[fall]
    py_rc, py_out, rs_rc, rs_out = _beide(tmp_path, befehl, mache(BEFEHLE[befehl][2]), pub)
    assert (py_rc, rs_rc) == (1, 1), (py_out, rs_out)


@pytest.mark.parametrize("form", sorted(ALPHABETE))
def test_verify_dsse_agrees_with_verify_envelope_on_the_payload_forms(tmp_path, form):
    mache, erwartet = ALPHABETE[form]
    env = mache(BEFEHLE["decision"][2])
    try:
        py_rc = 0 if dsse.verify_envelope(env, _PUB_RAW) else 1
    except Exception:  # noqa: BLE001 - a typed refusal is the malformed verdict
        py_rc = 2
    pfad = tmp_path / "env.json"
    pfad.write_text(json.dumps(env), encoding="utf-8")
    done = subprocess.run([str(_pb_verify_rs.binary_or_skip()), "verify-dsse", str(pfad), _PUB],  # noqa: S603
                          capture_output=True, text=True, timeout=60)
    assert (py_rc, done.returncode) == (erwartet, erwartet), (done.stdout, done.stderr)
