"""Gate-2 qualification (makellose-500 Phase 3, reviewer F6): the pre-tag audit gate must grant ok=true
ONLY for a SIGNED, TREE-BOUND receipt, and reject every counter-example — a bare prose line, a receipt
bound to a different tree/version, an unsigned one, and one signed by an untrusted key.

Generator-hardened: each rejection is a PROPERTY of verify_receipt, exercised by mutating exactly one
binding of an otherwise-valid receipt. A positive control (the untouched receipt verifies) guards
against the guard degrading into a constant reject."""
import base64
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from pre_tag_receipt_lib import RECEIPT_SCHEMA, canonical_bytes, verify_receipt  # noqa: E402

_TREE = "a" * 40
_GATE = "b" * 64
_VER = "5.0.0"


def _keypair():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.generate()
    return priv, base64.b64encode(priv.public_key().public_bytes_raw()).decode()


def _valid_receipt(priv, pub_b64):
    r = {
        "schema": RECEIPT_SCHEMA, "version": _VER, "subject_tree_digest": _TREE,
        "gate_source_digest": _GATE, "audit_command": "pytest -q + type_confusion_gate --strict",
        "audit_exit_code": 0, "audit_output_digest": "c" * 64, "runner_identity": "ci",
        "produced_at": "2026-08-26T21:00:00Z",
    }
    r["signature"] = base64.b64encode(priv.sign(canonical_bytes(r))).decode()
    r["signer_pubkey"] = pub_b64
    return r


def _check(receipt, trusted, **over):
    kw = dict(trusted_pubkeys=trusted, expected_version=_VER,
              subject_tree_digest=_TREE, gate_source_digest=_GATE)
    kw.update(over)
    return verify_receipt(receipt, **kw)


class TestPreTagReceiptGate:
    def test_positive_control_a_valid_receipt_verifies(self):
        priv, pub = _keypair()
        ok, reason = _check(_valid_receipt(priv, pub), [pub])
        assert ok, reason

    def test_bare_line_is_not_a_receipt(self):
        # P6: a prose 'pre-tag-adversarial-audit: RUN | version=5.0.0' is not a dict receipt at all.
        ok, _ = _check("pre-tag-adversarial-audit: RUN | version=5.0.0", ["x"])
        assert not ok

    def test_wrong_tree_rejected(self):
        priv, pub = _keypair()
        ok, reason = _check(_valid_receipt(priv, pub), [pub], subject_tree_digest="d" * 40)
        assert not ok and "tree" in reason.lower()

    def test_wrong_version_rejected(self):
        priv, pub = _keypair()
        ok, reason = _check(_valid_receipt(priv, pub), [pub], expected_version="4.9.9")
        assert not ok and "version" in reason.lower()

    def test_wrong_gate_source_rejected(self):
        priv, pub = _keypair()
        ok, _ = _check(_valid_receipt(priv, pub), [pub], gate_source_digest="e" * 64)
        assert not ok

    def test_failed_audit_rejected(self):
        priv, pub = _keypair()
        r = _valid_receipt(priv, pub)
        r["audit_exit_code"] = 1
        r["signature"] = base64.b64encode(priv.sign(canonical_bytes(r))).decode()
        ok, _ = _check(r, [pub])
        assert not ok

    def test_no_trusted_key_fails_closed(self):
        priv, pub = _keypair()
        ok, reason = _check(_valid_receipt(priv, pub), [])
        assert not ok and "trust" in reason.lower()

    def test_untrusted_signer_rejected(self):
        priv, pub = _keypair()
        _, other_pub = _keypair()
        ok, _ = _check(_valid_receipt(priv, pub), [other_pub])  # signer's key not in the trusted set
        assert not ok

    def test_forged_resign_by_untrusted_key_rejected(self):
        # An attacker re-signs a tree-correct receipt with THEIR key and lists their pubkey — but their
        # key is not pinned as trusted, so it is rejected. This is the whole point of the trust anchor.
        priv, pub = _keypair()
        r = _valid_receipt(priv, pub)
        forger, forger_pub = _keypair()
        r["signature"] = base64.b64encode(forger.sign(canonical_bytes(r))).decode()
        r["signer_pubkey"] = forger_pub
        ok, _ = _check(r, [pub])  # only the honest key is trusted
        assert not ok

    def test_tampered_signature_rejected(self):
        priv, pub = _keypair()
        r = _valid_receipt(priv, pub)
        r["audit_command"] = "rm -rf /  # tampered after signing"
        ok, _ = _check(r, [pub])  # signature no longer matches the canonical bytes
        assert not ok

    def test_missing_signed_field_is_error_not_short_message(self):
        priv, pub = _keypair()
        r = _valid_receipt(priv, pub)
        del r["subject_tree_digest"]
        with pytest.raises(ValueError):
            canonical_bytes(r)
        ok, _ = _check(r, [pub])
        assert not ok
