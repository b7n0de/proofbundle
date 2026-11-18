"""An attached receipt of one of our types without a predicate fails the requested lineage check.

Deep gate 6.6.0 at c3472f6f, lens L6, finding Z4 (P1): the structure check of its own type, which the fix of the
6.6.0 deep gate at d8881edc gave every attached target, ran only for a predicate that is an object. A correctly signed
statement of one of our types WITHOUT a predicate, or with `predicate: null`, stayed verified, and an edge-free
`decision verify --with-related` exited 0 with ok true, while the same bytes alone exit 2. In-toto lets a statement of
a FOREIGN type carry no predicate, and that stays as it was (anti-parity below).
"""
from __future__ import annotations

import base64
import contextlib
import io
import json

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle.cli import _EIGENE_PRAEDIKATTYPEN, main
from proofbundle.decision import emit_decision_receipt
from proofbundle.dsse import sign_envelope

_SK = Ed25519PrivateKey.from_private_bytes(b"\x01" * 32)
_PUB = base64.b64encode(_SK.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode("ascii")


def _cli(argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        code = main(argv)
    return code, out.getvalue()


@pytest.fixture()
def eltern(tmp_path):
    code, text = _cli(["decision", "init"])
    assert code == 0
    predicate = json.loads(text)
    predicate["decisionMaker"]["version"] = {"proofbundle": "test"}
    path = tmp_path / "parent.json"
    path.write_text(json.dumps(emit_decision_receipt(predicate, _SK)), encoding="utf-8")
    args = ["decision", "verify", str(path), "--pub", _PUB, "--json"]
    code, text = _cli(args)
    assert code == 0 and json.loads(text)["ok"] is True, "the control: the parent alone verifies"
    return args


def _ziel(tmp_path, typ: str, form: str):
    statement = {"_type": "https://in-toto.io/Statement/v1",
                 "subject": [{"name": "target", "digest": {"sha256": "0" * 64}}], "predicateType": typ}
    if form == "null":
        statement["predicate"] = None
    path = tmp_path / f"{form}-{abs(hash(typ))}.json"
    path.write_text(json.dumps(sign_envelope(rfc8785.dumps(statement), _SK,
                                             payload_type="application/vnd.in-toto+json")), encoding="utf-8")
    return path


@pytest.mark.parametrize("form", ["missing", "null"])
@pytest.mark.parametrize("typ", _EIGENE_PRAEDIKATTYPEN, ids=lambda t: t.rsplit("/", 2)[-2])
def test_an_attached_receipt_of_our_type_without_a_predicate_fails(eltern, tmp_path, typ, form):
    ziel = _ziel(tmp_path, typ, form)
    befehl = {"decision-receipt": "decision", "action-outcome": "outcome",
              "relation-statement": "relation-statement"}[typ.rsplit("/", 2)[-2]]
    allein, _ = _cli([befehl, "verify", str(ziel), "--pub", _PUB, "--json"])
    assert allein == 2, "the same bytes alone are refused by the verifier of their type"
    code, text = _cli(eltern + ["--with-related", str(ziel)])
    bericht = json.loads(text) if text.strip() else {}
    assert code == 2, (code, bericht.get("errors"))
    assert bericht.get("ok") is False and bericht.get("lineage_ok") is False


@pytest.mark.parametrize("form", ["missing", "null"])
def test_a_foreign_statement_without_a_predicate_stays_a_statement_without_edges(eltern, tmp_path, form):
    """ANTI-PARITY: in-toto lets a statement of a foreign type carry no predicate; this place does not judge it."""
    code, text = _cli(eltern + ["--with-related", str(_ziel(tmp_path, "urn:example:foreign", form))])
    assert code == 0, text
    assert json.loads(text)["ok"] is True
