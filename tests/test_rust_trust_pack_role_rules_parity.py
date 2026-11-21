"""Both verifiers apply the role rules of a trust pack to the values the Rust count reads.

Python's `validate_trust_pack_predicate` and `_validate_role` refuse a pack whose `revoked` is not a list
of known keyIds, whose root role names no non-empty list of known keyIds, or whose root threshold is not
an integer from 1 to the number of root keyIds that live keyIds can still meet. The Rust second verifier
read `revoked` and the root role without these rules. Measured on 21 November 2026 at 6.6.0 and at main
`b8ecc6f4`: with a root threshold of 0, `verify-trust-pack-threshold` met its threshold with no valid
signature (`OK`, exit 0) while Python refused the pack; at main the literal `-0` did the same, because
since pull request 544 Rust reads it as the integer 0, as Python does. A keyId that is not in `keys`, a
`revoked` that is no list of known keyIds, or a list of keyIds with a value that is no keyId met the
threshold there as well, and a threshold above the keyIds or out of reach after revocation failed it
(exit 1) where Python refuses the pack.

Each case below goes through both verifiers as the same bytes. Python must refuse the pack, and Rust must
refuse it as malformed (exit 2) with the first error Python reports. The controls must agree as well.
"""
from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle import dsse
from proofbundle import trust_pack as tp

try:
    import _pb_verify_rs  # tests/_pb_verify_rs.py, the one way to the binary
except ImportError:  # pragma: no cover - run as a package
    from tests import _pb_verify_rs

_NOW = datetime(2026, 11, 21, 12, 0, 0, tzinfo=timezone.utc)
_ROOT = Ed25519PrivateKey.generate()
_D = Ed25519PrivateKey.generate()


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _envelope(root: dict, revoked=None, *, literal: "tuple[bytes, bytes] | None" = None,
              wrong_signature: bool = False) -> dict:
    """A pack with the keys `r` (signs) and `d`, the given root role and `revoked` (absent when None).

    `literal` replaces one byte string of the payload, for a value `json` never writes (`-0`, `1.0`); the
    signature is made over the edited bytes, so it still counts unless `wrong_signature` is set."""
    keys = {"r": {"publicKey": _b64(_ROOT.public_key().public_bytes_raw())},
            "d": {"publicKey": _b64(_D.public_key().public_bytes_raw())}}
    predicate = {"schemaVersion": "0.1.0", "trustPackId": "role-rules-parity", "version": 1,
                 "expires": "2099-01-01T00:00:00Z", "prevVersionDigest": None, "roles": {"root": root},
                 "keys": keys, "nonClaims": ["names which keys hold which role, not that the holders are honest"]}
    if revoked is not None:
        predicate["revoked"] = revoked
    statement = {"_type": tp.STATEMENT_TYPE,
                 "subject": [{"name": "trust-pack:role-rules-parity:v1",
                              "digest": {"sha256": hashlib.sha256(tp._rfc8785_bytes(predicate)).hexdigest()}}],
                 "predicateType": tp.TRUST_PACK_PREDICATE_TYPE, "predicate": predicate}
    body = tp._rfc8785_bytes(statement)
    if literal is not None:
        old, new = literal
        assert body.count(old) == 1, (old, body)
        body = body.replace(old, new)
    msg = dsse.pae(tp.INTOTO_STATEMENT_PAYLOAD_TYPE, body)
    sig = _ROOT.sign(b"not the PAE of this payload" if wrong_signature else msg)
    return {"payload": _b64(body), "payloadType": tp.INTOTO_STATEMENT_PAYLOAD_TYPE,
            "signatures": [{"keyid": "r", "sig": _b64(sig)}]}


# name -> (root role, revoked, literal edit, wrong signature)
_REFUSED = {
    "threshold 0": ({"keyIds": ["r"], "threshold": 0}, None, None, False),
    "threshold 0, no valid signature": ({"keyIds": ["r"], "threshold": 0}, None, None, True),
    "threshold -0": ({"keyIds": ["r"], "threshold": 7}, None, (b'"threshold":7', b'"threshold":-0'), False),
    "threshold -0, no valid signature": ({"keyIds": ["r"], "threshold": 7}, None,
                                         (b'"threshold":7', b'"threshold":-0'), True),
    "threshold -1": ({"keyIds": ["r"], "threshold": -1}, None, None, False),
    "threshold true": ({"keyIds": ["r"], "threshold": True}, None, None, False),
    "threshold 1.0": ({"keyIds": ["r"], "threshold": 7}, None, (b'"threshold":7', b'"threshold":1.0'), False),
    "threshold as text": ({"keyIds": ["r"], "threshold": "1"}, None, None, False),
    "threshold missing": ({"keyIds": ["r"]}, None, None, False),
    "threshold above the keyIds": ({"keyIds": ["r"], "threshold": 2}, None, None, False),
    "threshold out of reach after revocation": ({"keyIds": ["r", "d"], "threshold": 2}, ["d"], None, False),
    "a root keyId not in keys": ({"keyIds": ["r", "x"], "threshold": 1}, None, None, False),
    "no root keyIds": ({"keyIds": [], "threshold": 1}, None, None, False),
    "keyIds missing": ({"threshold": 1}, None, None, False),
    "a number among the keyIds": ({"keyIds": ["r", 5], "threshold": 1}, None, None, False),
    "an empty keyId": ({"keyIds": ["r", ""], "threshold": 1}, None, None, False),
    "a revoked keyId not in keys": ({"keyIds": ["r"], "threshold": 1}, ["zz"], None, False),
    "revoked is text": ({"keyIds": ["r"], "threshold": 1}, "r", None, False),
    "revoked is null": ({"keyIds": ["r"], "threshold": 1}, None,
                        (b'"prevVersionDigest":null', b'"prevVersionDigest":null,"revoked":null'), False),
    "a number among the revoked": ({"keyIds": ["r"], "threshold": 1}, [5], None, False),
}

# name -> (root role, revoked, wrong signature, Rust exit, Python root_threshold_met)
_CONTROLS = {
    "threshold 1, signed": ({"keyIds": ["r"], "threshold": 1}, None, False, 0, True),
    "threshold 1, no valid signature": ({"keyIds": ["r"], "threshold": 1}, None, True, 1, False),
    "a revoked key that is not needed": ({"keyIds": ["r", "d"], "threshold": 1}, ["d"], False, 0, True),
    "a keyId named twice counts twice": ({"keyIds": ["r", "r"], "threshold": 2}, None, False, 1, False),
}


def _rust(binary: Path, envelope: dict) -> "tuple[int, str]":
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "pack.json"
        path.write_text(json.dumps(envelope), encoding="utf-8")
        done = subprocess.run([str(binary), "verify-trust-pack-threshold", str(path)],  # noqa: S603
                              capture_output=True, text=True, timeout=60)
    return done.returncode, done.stdout.strip()


class TestRustTrustPackRoleRules(unittest.TestCase):

    def test_a_pack_python_refuses_for_a_role_rule_is_malformed_in_rust_with_the_same_text(self):
        binary = _pb_verify_rs.binary_or_skip()
        for name, (root, revoked, literal, wrong) in _REFUSED.items():
            with self.subTest(case=name):
                env = _envelope(root, revoked, literal=literal, wrong_signature=wrong)
                py = tp.verify_trust_pack(env, now=_NOW)
                code, out = _rust(binary, env)
                self.assertIs(py["ok"], False)
                self.assertIsNone(py["root_threshold_met"], py["errors"])
                self.assertEqual(code, 2, out)
                self.assertEqual(out, f"MALFORMED: {py['errors'][0]}")

    def test_a_pack_whose_role_rules_hold_gets_the_same_count_in_both(self):
        binary = _pb_verify_rs.binary_or_skip()
        for name, (root, revoked, wrong, exit_code, met) in _CONTROLS.items():
            with self.subTest(case=name):
                env = _envelope(root, revoked, wrong_signature=wrong)
                py = tp.verify_trust_pack(env, now=_NOW)
                code, out = _rust(binary, env)
                self.assertIs(py["root_threshold_met"], met, py["errors"])
                self.assertEqual(code, exit_code, out)
                self.assertTrue(out.startswith(f"{'OK' if met else 'FAIL'} root_threshold_met={str(met).lower()}"),
                                out)


if __name__ == "__main__":
    unittest.main()
