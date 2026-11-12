"""A pre-tag receipt carries the signed fields, the signature and the signer, and nothing else.

DELTA2 N2 (2026-11-06). `canonical_bytes` signs the nine fields of `_SIGNED_FIELDS` and nothing
else, and `verify_receipt` never looked at the other members of the object. A member beside them
travelled unsigned under a VERIFIED receipt, and a reader of the file could not tell it from the
attested content. A container check names its members and refuses foreign ones, each by repr.
"""
import base64
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from pre_tag_receipt_lib import RECEIPT_SCHEMA, canonical_bytes, verify_receipt  # noqa: E402

_TREE, _GATE, _VER = "a" * 64, "b" * 64, "6.5.0"


def _signed():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.generate()
    pub = base64.b64encode(priv.public_key().public_bytes_raw()).decode()
    r = {"schema": RECEIPT_SCHEMA, "version": _VER, "subject_tree_digest": _TREE,
         "gate_source_digest": _GATE, "audit_command": "pytest", "audit_exit_code": 0,
         "audit_output_digest": "c" * 64, "runner_identity": "ci",
         "produced_at": "2026-11-06T00:00:00Z"}
    r["signature"] = base64.b64encode(priv.sign(canonical_bytes(r))).decode()
    r["signer_pubkey"] = pub
    return r, pub


def _check(receipt, pub):
    return verify_receipt(receipt, trusted_pubkeys=[pub], expected_version=_VER,
                          subject_tree_digest=_TREE, gate_source_digest=_GATE)


def test_positive_control_the_eleven_members_verify():
    r, pub = _signed()
    ok, reason = _check(r, pub)
    assert ok, reason


def test_a_foreign_member_is_refused_and_named():
    for name in ("extra", "_informational_not_signed", "audit_exit_code ", ""):
        r, pub = _signed()
        r[name] = {"note": "not signed"}
        ok, reason = _check(r, pub)
        assert not ok, f"{name!r}: an unsigned member travelled under a verified receipt"
        assert repr(name) in reason, reason
