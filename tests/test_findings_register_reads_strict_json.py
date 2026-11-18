"""D2 of CODEX-KLASSENSUCHE-631-01 (class D, at f6ea5cc3): the signed findings register is read strictly.

Measured at f6ea5cc3: `verify_and_count` parsed the register with `json.loads`, which keeps the last of two members.
A valid register signed with a test key over a closed P1 list, with ``"findings":[{"id":"X","severity":"P1",
"status":"open"}],`` put in front as its first member, passed with ``ok=True`` and ``open_ids=[]``; a reader that keeps
the first member sees an open P1, and `loads_strict` refuses the same bytes. The register is built from the test
dictionary in an isolated tree under the path the checker reads, never copied from the production register. Controls:
the unique register passes with its test anchor and fails with a foreign one.
"""
from __future__ import annotations

import base64
import importlib.util
import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

REPO = Path(__file__).resolve().parents[1]
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))
from proofbundle import canonical  # noqa: E402

KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))              # the repository's test seed
PUB_B64 = base64.b64encode(KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
OPEN_P1 = '[{"id":"X","severity":"P1","status":"open"}]'


def _module():
    spec = importlib.util.spec_from_file_location("fr_strict", REPO / "scripts" / "findings_register.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


FR = _module()


def _register() -> dict:
    body = {"schema": "proofbundle.findings_register.v1", "version": "6.3.1",
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "findings": [{"id": "X", "severity": "P1", "status": "closed"}]}
    return {**body, "signature": {"alg": "ed25519", "public_key_b64": PUB_B64,
                                  "sig_b64": base64.b64encode(KEY.sign(canonical.canonicalize_statement(body))).decode()}}


def _verify(text: str, anchor: str = PUB_B64) -> dict:
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / FR.REGISTER_REL
        path.parent.mkdir(parents=True)
        path.write_text(text, encoding="utf-8")
        return FR.verify_and_count(Path(td), expected_version="6.3.1", authorised_pubkeys={anchor})


#: The member each case writes twice, counted in the text as the precondition.
MEMBER_TWICE = {"open findings before": "findings", "open findings after": "findings", "status twice": "status",
                "severity twice": "severity", "signature member twice": "sig_b64"}


def _twice(kind: str) -> str:
    """The register with one member twice, built ONCE. Building it twice read the clock twice: at a second boundary
    the two `generated_at` differed, the signature of the second build stood nowhere in the first, `replace` changed
    nothing, and the precondition still held, because it compared with a third build (CI of pull request 504,
    test 3.11, 2026-11-09T20:00:48Z; one fixed clock passes, a clock one second further on each call fails)."""
    register = _register()
    whole = json.dumps(register)
    if kind == "open findings before":
        return '{"findings":' + OPEN_P1 + ',' + whole[1:]
    if kind == "open findings after":
        return whole[:-1] + ',"findings":' + OPEN_P1 + '}'
    if kind == "status twice":
        return whole.replace('"status": "closed"', '"status": "open", "status": "closed"')
    if kind == "severity twice":
        return whole.replace('"severity": "P1"', '"severity": "P0", "severity": "P1"')
    signature = register["signature"]["sig_b64"]
    return whole.replace(f'"sig_b64": "{signature}"', f'"sig_b64": "AAAA", "sig_b64": "{signature}"')


@pytest.mark.parametrize("kind", sorted(MEMBER_TWICE))
def test_a_register_with_a_member_twice_is_refused(kind):
    text = _twice(kind)
    assert text.count(f'"{MEMBER_TWICE[kind]}"') == 2, "precondition: the member stands twice in the text"
    r = _verify(text)
    assert r["ok"] is False and "duplicate JSON key" in r["reason"], r


def test_control_the_unique_register_passes_with_its_test_anchor():
    r = _verify(json.dumps(_register()))
    assert r["ok"] is True and r["open_ids"] == [], r


def test_control_a_foreign_test_anchor_fails():
    foreign = Ed25519PrivateKey.from_private_bytes(bytes(range(2, 34)))
    anchor = base64.b64encode(foreign.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
    assert _verify(json.dumps(_register()), anchor)["ok"] is False
