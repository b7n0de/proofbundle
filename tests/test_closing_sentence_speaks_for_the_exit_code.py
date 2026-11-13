"""The closing sentence of `decision verify`, `outcome verify` and `relation-statement verify` speaks for the exit code.

Deep gate 6.6.0 at c3472f6f, lens L6, finding Z6: the sentence a verified receipt earns ("This proves the signed
decision claim has not been altered") was chosen by `crypto_ok` alone, so a signed FOREIGN predicate, which the command
correctly refuses with exit 2, was told what a verified decision receipt proves. The outcome and the relation-statement
commands chose their sentences the same way. Each command now prints its positive sentence only where it exits 0.
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import json

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle.cli import main
from proofbundle.decision import emit_decision_receipt
from proofbundle.dsse import sign_envelope

_SK = Ed25519PrivateKey.from_private_bytes(b"\x02" * 32)
_PUB = base64.b64encode(_SK.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode("ascii")
_POSITIV = {"decision": "This proves the signed decision claim has not been altered",
            "outcome": "This proves who signed what happened",
            "relation-statement": "This proves the issuer DECLARED the relation"}


def _cli(argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        code = main(argv)
    return code, out.getvalue()


def _foreign(tmp_path):
    statement = {"_type": "https://in-toto.io/Statement/v1",
                 "subject": [{"name": "foreign", "digest": {"sha256": hashlib.sha256(b"{}").hexdigest()}}],
                 "predicateType": "urn:example:foreign-predicate", "predicate": {}}
    path = tmp_path / "foreign.json"
    path.write_text(json.dumps(sign_envelope(rfc8785.dumps(statement), _SK,
                                             payload_type="application/vnd.in-toto+json")), encoding="utf-8")
    return path


@pytest.mark.parametrize("befehl", sorted(_POSITIV))
def test_a_signed_foreign_predicate_is_not_told_what_a_verified_receipt_proves(befehl, tmp_path):
    code, text = _cli([befehl, "verify", str(_foreign(tmp_path)), "--pub", _PUB])
    assert code == 2, text
    assert "CRYPTO: OK" in text
    assert _POSITIV[befehl] not in text, text
    assert "did not hold (exit 2)" in text


def test_a_verified_decision_receipt_keeps_its_sentence(tmp_path):
    """ANTI-PARITY: the sentence is not gone, it stands where the command exits 0."""
    code, text = _cli(["decision", "init"])
    assert code == 0
    predicate = json.loads(text)
    predicate["decisionMaker"]["version"] = {"proofbundle": "test"}
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(emit_decision_receipt(predicate, _SK)), encoding="utf-8")
    code, text = _cli(["decision", "verify", str(path), "--pub", _PUB])
    assert code == 0, text
    assert _POSITIV["decision"] in text


def test_a_receipt_under_another_key_keeps_the_crypto_sentence(tmp_path):
    other = base64.b64encode(Ed25519PrivateKey.from_private_bytes(b"\x09" * 32).public_key()
                             .public_bytes(Encoding.Raw, PublicFormat.Raw)).decode("ascii")
    code, text = _cli(["decision", "verify", str(_foreign(tmp_path)), "--pub", other])
    assert code == 1, text
    assert "did NOT verify (crypto failure)" in text
