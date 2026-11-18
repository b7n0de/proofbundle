"""Both verifiers apply the alias rule of a trust pack: no key part may occur in two keys (KR-01).

Python's `validate_trust_pack_predicate` refuses a pack in which a key part, classical or post-quantum,
occurs in two keys (pull request 537). The Rust second verifier did not reproduce that rule. Measured on
18 November 2026 with one Ed25519 root key at threshold 1, a pack whose two other keys share a part met
its threshold there (`OK`, exit 0) while Python refused it, both for two hybrid keys with one
post-quantum part and for two Ed25519 keys with one `publicKey`.

Each case below goes through both verifiers as the same bytes. A pack Python refuses for a shared part
must be refused by Rust as malformed (exit 2) with Python's own error text, so both name the same two
keys; the control pack must pass in both.

The post-quantum parts are 1952 bytes of fixed filler. The rule compares bytes at the length of their
algorithm and no ML-DSA signature is made or checked here, so this module needs no ML-DSA build of
`cryptography`. The root key signs with Ed25519.
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

_NOW = datetime(2026, 11, 18, 12, 0, 0, tzinfo=timezone.utc)
_ROOT = Ed25519PrivateKey.generate()
_ED = [Ed25519PrivateKey.generate() for _ in range(4)]


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _ed(i: int) -> str:
    return _b64(_ED[i].public_key().public_bytes_raw())


def _pq(filler: int) -> str:
    return _b64(bytes([filler]) * 1952)


def _hybrid(i: int, pq: str) -> dict:
    return {"alg": "hybrid-ed25519-mldsa65", "publicKey": _ed(i), "publicKeyPq": pq}


def _envelope(further: dict, revoked: list) -> dict:
    keys = {"r": {"publicKey": _b64(_ROOT.public_key().public_bytes_raw())}, **further}
    predicate = {"schemaVersion": "0.1.0", "trustPackId": "alias-parity", "version": 1,
                 "expires": "2099-01-01T00:00:00Z", "prevVersionDigest": None,
                 "roles": {"root": {"keyIds": ["r"], "threshold": 1}}, "keys": keys,
                 "nonClaims": ["names which keys hold which role, not that the holders are honest"]}
    if revoked:
        predicate["revoked"] = revoked
    statement = {"_type": tp.STATEMENT_TYPE,
                 "subject": [{"name": "trust-pack:alias-parity:v1",
                              "digest": {"sha256": hashlib.sha256(tp._rfc8785_bytes(predicate)).hexdigest()}}],
                 "predicateType": tp.TRUST_PACK_PREDICATE_TYPE, "predicate": predicate}
    body = tp._rfc8785_bytes(statement)
    msg = dsse.pae(tp.INTOTO_STATEMENT_PAYLOAD_TYPE, body)
    return {"payload": _b64(body), "payloadType": tp.INTOTO_STATEMENT_PAYLOAD_TYPE,
            "signatures": [{"keyid": "r", "sig": _b64(_ROOT.sign(msg))}]}


_PQ_A, _PQ_B = _pq(0x11), _pq(0x22)

# name -> (further keys, revoked, the key that shares a part, the key it shares with); None = control
_CASES = {
    "one PQ part in two hybrid keys": ({"h1": _hybrid(0, _PQ_A), "h2": _hybrid(1, _PQ_A)}, [], ("h2", "h1")),
    "one publicKey in two Ed25519 keys": ({"d1": {"publicKey": _ed(0)}, "d2": {"publicKey": _ed(0)}}, [],
                                          ("d2", "d1")),
    # The payload is RFC 8785, so its keys stand sorted and both verifiers read `h` before `m`.
    "an ML-DSA key as the PQ part of a hybrid": ({"m": {"alg": "mldsa65", "publicKey": _PQ_A},
                                                  "h": _hybrid(0, _PQ_A)}, [], ("m", "h")),
    "a revoked key shares a part": ({"d1": {"publicKey": _ed(0)}, "d2": {"publicKey": _ed(0)}}, ["d2"],
                                    ("d2", "d1")),
    "a key of an unknown algorithm names its publicKey": ({"d1": {"publicKey": _ed(0)},
                                                           "u": {"alg": "rsa4096", "publicKey": _ed(0)}}, [],
                                                          ("u", "d1")),
    "control: no part is shared": ({"h1": _hybrid(0, _PQ_A), "h2": _hybrid(1, _PQ_B),
                                    "d": {"publicKey": _ed(2)}}, [], None),
}


def _rust(binary: Path, envelope: dict) -> "tuple[int, str]":
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "pack.json"
        path.write_text(json.dumps(envelope), encoding="utf-8")
        done = subprocess.run([str(binary), "verify-trust-pack-threshold", str(path)],  # noqa: S603
                              capture_output=True, text=True, timeout=60)
    return done.returncode, done.stdout.strip()


class TestRustTrustPackKeyPartAlias(unittest.TestCase):

    def test_both_verifiers_give_the_same_verdict_and_name_the_same_keys(self):
        binary = _pb_verify_rs.binary_or_skip()
        for name, (further, revoked, shared) in _CASES.items():
            with self.subTest(case=name):
                env = _envelope(further, revoked)
                py = tp.verify_trust_pack(env, now=_NOW)
                code, out = _rust(binary, env)
                if shared is None:
                    self.assertIs(py["ok"], True, py["errors"])
                    self.assertEqual(code, 0, out)
                    self.assertTrue(out.startswith("OK root_threshold_met=true"), out)
                    continue
                kid, first = shared
                alias = [e for e in py["errors"] if "duplicates the key material" in e]
                self.assertIs(py["ok"], False)
                self.assertEqual(len(alias), 1, py["errors"])
                self.assertTrue(alias[0].startswith(f"keys[{kid!r}] duplicates the key material of "
                                                    f"keys[{first!r}]"), alias[0])
                self.assertEqual(code, 2, out)
                self.assertEqual(out, f"MALFORMED: {alias[0]}")


if __name__ == "__main__":
    unittest.main()
