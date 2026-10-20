"""D3 of CODEX-KLASSENSUCHE-631-01 (class D, at f6ea5cc3): the readiness self-receipt is read strictly.

Measured at f6ea5cc3: `check` parsed the receipt with `json.loads`, which keeps the last of two members. An isolated
pack with a copy of `tests/fixtures/sdjwtvc/sdjwtvc_issuer_pubkey.json`, its real `compute_manifest` bytes and the
valid receipt `emit_bundle(manifest_bytes, test_key)`, with ``"payload_b64":""`` put in front of the real member,
gave ok=True, manifest_matches=True, receipt_verifies=True, problems=[] and exit 0 for `--check --json`. Only the path
constants PACK, MANIFEST, RECEIPT_DIR, RECEIPT (and PUBKEY) point to the scratch folder; the code that checks and the
data flow are unchanged. Control: the unique receipt over the same manifest bytes gives the same positive results.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import shutil
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO = Path(__file__).resolve().parents[1]
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))
from proofbundle.emit import emit_bundle  # noqa: E402

KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))              # the repository's test seed


@pytest.fixture()
def pack(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("rpm_strict", REPO / "scripts" / "readiness_pack_manifest.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    root = tmp_path / "readiness_pack"
    root.mkdir()
    shutil.copy(REPO / "tests" / "fixtures" / "sdjwtvc" / "sdjwtvc_issuer_pubkey.json", root)
    receipts = root / "proofbundle"
    monkeypatch.setattr(module, "PACK", root)
    monkeypatch.setattr(module, "MANIFEST", root / "MANIFEST.sha256")
    monkeypatch.setattr(module, "RECEIPT_DIR", receipts)
    monkeypatch.setattr(module, "RECEIPT", receipts / "readiness_pack.bundle.json")
    monkeypatch.setattr(module, "PUBKEY", receipts / "readiness_pack.pub.b64")
    manifest = module.compute_manifest()
    module.MANIFEST.write_text(manifest, encoding="utf-8")
    receipts.mkdir()
    return module, emit_bundle(manifest.encode("utf-8"), KEY)


def _main(module) -> int:
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return module.main(["--check", "--json"])


@pytest.mark.parametrize("where", ["before", "after"])
def test_a_receipt_with_payload_b64_twice_is_no_receipt(pack, where):
    module, bundle = pack
    whole = json.dumps(bundle)
    module.RECEIPT.write_text('{"payload_b64":"",' + whole[1:] if where == "before" else whole[:-1] + ',"payload_b64":""}',
                              encoding="utf-8")
    r = module.check()
    assert r["ok"] is False and r["receipt_verifies"] is None, r
    assert any("duplicate JSON key" in p for p in r["problems"]), r["problems"]
    assert _main(module) != 0


def test_control_the_unique_receipt_over_the_same_manifest_passes(pack):
    module, bundle = pack
    module.RECEIPT.write_text(json.dumps(bundle), encoding="utf-8")
    r = module.check()
    assert r == {"ok": True, "manifest_matches": True, "receipt_verifies": True, "problems": []}, r
    assert _main(module) == 0
