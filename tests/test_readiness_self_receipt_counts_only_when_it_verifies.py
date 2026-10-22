"""Beside D3 of CODEX-KLASSENSUCHE-631-01, found by the class search in the same function: the readiness self-receipt
counts only when it verifies and covers the recorded manifest.

Measured at 0e540436 (and at f6ea5cc3, where the same lines stand): `check` read the verdict as
``bool(r.get("ok")) if isinstance(r, dict) else bool(r)``. `verify_bundle` returns a VerificationResult, no dict, and
``bool()`` of it is always True, so a unique receipt whose ``payload_b64`` was changed after signing gave
receipt_verifies=True, ok=True and exit 0. A valid receipt over other bytes than MANIFEST.sha256 passed as well. The
control: the receipt over the recorded manifest passes.
"""
from __future__ import annotations

import base64
import json

from test_readiness_pack_manifest_reads_strict_json import KEY, _main, emit_bundle, pack  # noqa: F401


def test_a_receipt_whose_signature_does_not_verify_does_not_count(pack):  # noqa: F811
    module, bundle = pack
    bundle["payload_b64"] = base64.b64encode(b"tampered").decode()
    module.RECEIPT.write_text(json.dumps(bundle), encoding="utf-8")
    r = module.check()
    assert r["ok"] is False and r["receipt_verifies"] is False, r
    assert "proofbundle self-receipt does not verify" in r["problems"]
    assert _main(module) == 1


def test_a_valid_receipt_over_other_bytes_is_no_receipt_of_this_pack(pack):  # noqa: F811
    module, _bundle = pack
    module.RECEIPT.write_text(json.dumps(emit_bundle(b"other bytes", KEY)), encoding="utf-8")
    r = module.check()
    assert r["ok"] is False and r["receipt_verifies"] is False, r
    assert "the self-receipt covers other bytes than MANIFEST.sha256" in r["problems"]


def test_control_the_receipt_over_the_recorded_manifest_counts(pack):  # noqa: F811
    module, bundle = pack
    module.RECEIPT.write_text(json.dumps(bundle), encoding="utf-8")
    assert module.check() == {"ok": True, "manifest_matches": True, "receipt_verifies": True, "problems": []}
