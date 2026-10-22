"""D1 of CODEX-KLASSENSUCHE-631-01 (class D, at f6ea5cc3): the release attestation CLI reads its JSON strictly.

Measured at f6ea5cc3: `scripts/pre_tag_attestation.py main` parsed the envelope with `json.loads`, which keeps the last
of two members. The file made from a valid envelope by exactly ``'{"payload":"",' + json.dumps(envelope)[1:]`` passed
with ``ok=True``, ``signature_ok=True``, ``observed_result=PASSED`` and exit 0; neither the signature nor the external
anchor was changed. The repository's strict parser refuses the same bytes with ``duplicate JSON key 'payload'``. The
controls: the unique envelope passes the identical call; a wrong external commit gives exit 1 and commit_ok False.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import pathlib
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

_REPO = pathlib.Path(__file__).resolve().parents[1]
COMMIT, VERSION = "0123456789abcdef0123456789abcdef01234567", "3.8.0"
KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))              # the repository's test seed
PUB_HEX = KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def _pta():
    if str(_REPO / "src") not in sys.path:
        sys.path.insert(0, str(_REPO / "src"))
    spec = importlib.util.spec_from_file_location("_pta_strict", _REPO / "scripts" / "pre_tag_attestation.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PTA = _pta()


def _envelope() -> dict:
    return PTA.sign_statement(PTA.build_statement(
        commit=COMMIT, version=VERSION, verifier_id="https://b7n0de.com/proofbundle/pre-tag",
        time_verified="2026-08-16T21:00:00Z", policy_uri="https://b7n0de.com/proofbundle/policy/pre-tag-audit/v1"),
        KEY)


def _run(path: pathlib.Path, commit: str = COMMIT) -> tuple[int, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = PTA.main(["--envelope", str(path), "--pubkey-hex", PUB_HEX, "--expected-version", VERSION,
                         "--expected-commit", commit, "--json"])
    return code, out.getvalue() + err.getvalue()


def _duplicate(kind: str) -> str:
    env = _envelope()
    whole = json.dumps(env)
    if kind == "empty payload before":
        return '{"payload":"",' + whole[1:]
    if kind == "empty payload after":
        return whole[:-1] + ',"payload":""}'
    if kind == "payloadType twice":
        return '{"payloadType":"text/plain",' + whole[1:]
    signature = env["signatures"][0]["sig"]
    return whole.replace(f'"sig": "{signature}"', f'"sig": "", "sig": "{signature}"')


@pytest.mark.parametrize("kind", ["empty payload before", "empty payload after", "payloadType twice",
                                  "signature member twice"])
def test_an_envelope_with_a_member_twice_is_refused_at_the_file(tmp_path, kind):
    path = tmp_path / "env.json"
    path.write_text(_duplicate(kind), encoding="utf-8")
    code, text = _run(path)
    assert code == 2 and "duplicate JSON key" in text, (code, text)
    assert '"ok": true' not in text


def test_an_envelope_that_is_no_utf8_is_refused(tmp_path):
    path = tmp_path / "env.json"
    path.write_bytes(json.dumps(_envelope()).encode()[:-1] + b'\xff}')
    assert _run(path)[0] == 2


def test_control_the_unique_envelope_passes_the_identical_call(tmp_path):
    path = tmp_path / "env.json"
    path.write_text(json.dumps(_envelope()), encoding="utf-8")
    code, text = _run(path)
    assert code == 0 and json.loads(text)["ok"] is True, text


def test_control_a_wrong_external_commit_fails(tmp_path):
    path = tmp_path / "env.json"
    path.write_text(json.dumps(_envelope()), encoding="utf-8")
    code, text = _run(path, commit="f" * 40)
    assert code == 1 and json.loads(text)["commit_ok"] is False, text
