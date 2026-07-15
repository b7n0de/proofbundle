"""Crypto agility for the Trust Pack root of trust (PB-2026-0715-08).

`trust_pack.py` used to structurally forbid any non-Ed25519 root key (a hardcoded 32-byte gate in
`validate_trust_pack_predicate` and a hardcoded `verify_ed25519` call in `verify_trust_pack`), even though
`pqsig.py` already ships real ML-DSA (FIPS 204) verification and `renewal.py` already dispatches on a
per-object `sig_alg` (ed25519 / hybrid-ed25519-mldsa65 / mldsa65) with the algorithm bound into the signed
bytes (downgrade defense). This module proves the additive fix: `keys[kid].alg` (default `ed25519`, fully
backward compatible) now selects the same three algorithms for a Trust Pack ROOT key, dispatched through
`_verify_signature_for_alg` (mirrors `renewal._verify_ats_signature`).

Downgrade protection (the finding's core ask): a hybrid key (`alg="hybrid-ed25519-mldsa65"`) is authenticated
only when BOTH legs verify. `test_hybrid_key_valid_with_only_ed25519_leg_signed` is the direct proof that an
Ed25519-only signature can NEVER satisfy a policy-declared hybrid key.
"""
from __future__ import annotations

import base64
import hashlib
import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

from proofbundle import dsse
from proofbundle.emit import generate_signer
from proofbundle.pqsig import generate_mldsa
from proofbundle.trust_pack import (
    INTOTO_STATEMENT_PAYLOAD_TYPE,
    build_trust_pack_statement,
    sign_trust_pack,
    validate_trust_pack_predicate,
    verify_trust_pack,
)

try:
    from cryptography.hazmat.primitives.asymmetric import mldsa  # noqa: F401
    _HAS_MLDSA = True
except ImportError:
    _HAS_MLDSA = False

_NOW = datetime(2026, 7, 14, 12, 0, 0, tzinfo=timezone.utc)
_NON_CLAIMS = ["names which keys hold which role, not that the holders are honest"]


def _pub_ed25519(sk) -> str:
    return base64.b64encode(sk.public_key().public_bytes_raw()).decode("ascii")


def _pub_mldsa(sk) -> str:
    return base64.b64encode(sk.public_key().public_bytes_raw()).decode("ascii")


def _digest(version: int) -> str:
    return hashlib.sha256(f"pack-v{version}".encode()).hexdigest()


def _manual_envelope(predicate: dict, signer_specs: dict) -> dict:
    """Build + sign a Trust Pack DSSE envelope WITHOUT `sign_trust_pack` (which only supports a single
    Ed25519-shaped `.sign(msg)` leg per signer, producing one `sig` field). Needed here for `mldsa65`-only
    and `hybrid-ed25519-mldsa65` (two-leg) signatures. ``signer_specs`` maps keyId -> either a single
    private key (Ed25519 or ML-DSA — both expose `.sign(msg) -> bytes`, producing one `sig` leg) or a
    2-tuple ``(ed25519_sk, mldsa65_sk)`` for a hybrid key, producing BOTH the `sig` and `sigPq` legs."""
    from proofbundle.trust_pack import _rfc8785_bytes  # noqa: PLC0415
    statement = build_trust_pack_statement(predicate)
    body = _rfc8785_bytes(statement)
    msg = dsse.pae(INTOTO_STATEMENT_PAYLOAD_TYPE, body)
    signatures = []
    for kid, spec in signer_specs.items():
        if isinstance(spec, tuple):
            ed_sk, m_sk = spec
            signatures.append({
                "keyid": kid,
                "sig": base64.b64encode(bytes(ed_sk.sign(msg))).decode("ascii"),
                "sigPq": base64.b64encode(bytes(m_sk.sign(msg))).decode("ascii"),
            })
        else:
            signatures.append({"keyid": kid, "sig": base64.b64encode(bytes(spec.sign(msg))).decode("ascii")})
    return {"payload": base64.b64encode(body).decode("ascii"),
            "payloadType": INTOTO_STATEMENT_PAYLOAD_TYPE, "signatures": signatures}


def _external_sign(env: dict, kid: str, sk) -> None:
    """Append a signature under ``kid`` over the envelope's exact PAE (an OLD-root key vouching for a
    rotation) — mirrors ``test_trust_pack.py::_external_sign``, redefined here so this module stays
    self-contained (no cross-test-module import; ``tests/`` is not a package)."""
    body = base64.b64decode(env["payload"])
    msg = dsse.pae(INTOTO_STATEMENT_PAYLOAD_TYPE, body)
    env["signatures"].append({"keyid": kid, "sig": base64.b64encode(sk.sign(msg)).decode("ascii")})


class TestEd25519DefaultBackwardCompat(unittest.TestCase):
    """R1: a `keys[kid]` entry WITHOUT an `alg` field must behave exactly as before (default ed25519)."""

    def test_keys_without_alg_field_are_ed25519_by_default(self):
        sk0, sk1 = generate_signer(), generate_signer()
        keys = {"root-0": {"publicKey": _pub_ed25519(sk0)}, "root-1": {"publicKey": _pub_ed25519(sk1)}}
        pred = {
            "schemaVersion": "0.1.0", "trustPackId": "tp-agility", "version": 1,
            "expires": "2099-01-01T00:00:00Z", "prevVersionDigest": None,
            "roles": {"root": {"keyIds": list(keys), "threshold": 2}},
            "keys": keys, "nonClaims": _NON_CLAIMS,
        }
        self.assertEqual(validate_trust_pack_predicate(pred), [])
        env = sign_trust_pack(pred, {"root-0": sk0, "root-1": sk1})
        r = verify_trust_pack(env, strict=True, now=_NOW)
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["root_signers"], ["root-0", "root-1"])

    def test_explicit_alg_ed25519_is_equivalent_to_absent(self):
        sk = generate_signer()
        keys = {"root-0": {"publicKey": _pub_ed25519(sk), "alg": "ed25519"}}
        pred = {
            "schemaVersion": "0.1.0", "trustPackId": "tp-agility", "version": 1,
            "expires": "2099-01-01T00:00:00Z", "prevVersionDigest": None,
            "roles": {"root": {"keyIds": ["root-0"], "threshold": 1}},
            "keys": keys, "nonClaims": _NON_CLAIMS,
        }
        self.assertEqual(validate_trust_pack_predicate(pred), [])
        env = sign_trust_pack(pred, {"root-0": sk})
        r = verify_trust_pack(env, strict=True, now=_NOW)
        self.assertTrue(r["ok"], r)


class TestKeyLengthValidationIsAlgAware(unittest.TestCase):
    def test_unknown_alg_rejected(self):
        sk = generate_signer()
        keys = {"root-0": {"publicKey": _pub_ed25519(sk), "alg": "rsa4096"}}
        errs = validate_trust_pack_predicate({
            "schemaVersion": "0.1.0", "trustPackId": "t", "version": 1, "expires": "2099-01-01T00:00:00Z",
            "prevVersionDigest": None, "roles": {"root": {"keyIds": ["root-0"], "threshold": 1}},
            "keys": keys, "nonClaims": _NON_CLAIMS,
        })
        self.assertTrue(any("alg must be one of" in e for e in errs), errs)

    def test_mldsa65_key_wrong_length_rejected(self):
        keys = {"root-0": {"publicKey": base64.b64encode(b"short").decode(), "alg": "mldsa65"}}
        errs = validate_trust_pack_predicate({
            "schemaVersion": "0.1.0", "trustPackId": "t", "version": 1, "expires": "2099-01-01T00:00:00Z",
            "prevVersionDigest": None, "roles": {"root": {"keyIds": ["root-0"], "threshold": 1}},
            "keys": keys, "nonClaims": _NON_CLAIMS,
        })
        self.assertTrue(any("1952-byte" in e for e in errs), errs)

    def test_hybrid_key_missing_publickeypq_rejected(self):
        sk = generate_signer()
        keys = {"root-0": {"publicKey": _pub_ed25519(sk), "alg": "hybrid-ed25519-mldsa65"}}
        errs = validate_trust_pack_predicate({
            "schemaVersion": "0.1.0", "trustPackId": "t", "version": 1, "expires": "2099-01-01T00:00:00Z",
            "prevVersionDigest": None, "roles": {"root": {"keyIds": ["root-0"], "threshold": 1}},
            "keys": keys, "nonClaims": _NON_CLAIMS,
        })
        self.assertTrue(any("publicKeyPq is required" in e for e in errs), errs)

    def test_publickeypq_forbidden_outside_hybrid(self):
        sk = generate_signer()
        keys = {"root-0": {"publicKey": _pub_ed25519(sk), "alg": "ed25519",
                           "publicKeyPq": base64.b64encode(b"x" * 1952).decode()}}
        errs = validate_trust_pack_predicate({
            "schemaVersion": "0.1.0", "trustPackId": "t", "version": 1, "expires": "2099-01-01T00:00:00Z",
            "prevVersionDigest": None, "roles": {"root": {"keyIds": ["root-0"], "threshold": 1}},
            "keys": keys, "nonClaims": _NON_CLAIMS,
        })
        self.assertTrue(any("only allowed for alg" in e for e in errs), errs)


@unittest.skipUnless(_HAS_MLDSA, "needs cryptography with FIPS 204 (ML-DSA) support")
class TestMldsaRootKeyVerifies(unittest.TestCase):
    """R2: an `alg='mldsa65'` root key threshold-verifies through the normal `sign_trust_pack` /
    `verify_trust_pack` path (a single ML-DSA leg needs no envelope-shape change — `sign_trust_pack`'s
    generic ``sk.sign(msg)`` already works for an ML-DSA private key object, same interface as Ed25519)."""

    @staticmethod
    def _pack():
        m_sk = generate_mldsa("mldsa65")
        keys = {"root-mldsa-0": {"publicKey": _pub_mldsa(m_sk), "alg": "mldsa65"}}
        pred = {
            "schemaVersion": "0.1.0", "trustPackId": "tp-agility", "version": 1,
            "expires": "2099-01-01T00:00:00Z", "prevVersionDigest": None,
            "roles": {"root": {"keyIds": ["root-mldsa-0"], "threshold": 1}},
            "keys": keys, "nonClaims": _NON_CLAIMS,
        }
        return pred, m_sk

    def test_mldsa_root_key_verifies(self):
        pred, m_sk = self._pack()
        self.assertEqual(validate_trust_pack_predicate(pred), [])
        env = sign_trust_pack(pred, {"root-mldsa-0": m_sk})
        r = verify_trust_pack(env, strict=True, now=_NOW)
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["root_signers"], ["root-mldsa-0"])

    def test_mldsa_wrong_signer_key_does_not_verify(self):
        # negative control: sign under the declared keyId but with a DIFFERENT ML-DSA private key -> the
        # signature must not verify against the declared publicKey (no false accept on the new alg path).
        pred, _m_sk = self._pack()
        other_sk = generate_mldsa("mldsa65")
        env = sign_trust_pack(pred, {"root-mldsa-0": other_sk})
        r = verify_trust_pack(env, strict=True, now=_NOW)
        self.assertFalse(r["root_threshold_met"])
        self.assertFalse(r["ok"], r)


class TestMldsaAlgDispatchAgainstAcvpVector(unittest.TestCase):
    """Best-effort reuse of the vendored NIST ACVP ML-DSA sigVer vectors (``tests/fixtures/mldsa_acvp/``,
    see ``test_mldsa_acvp_vectors.py``) — honestly scoped (No-Fake): those vectors are VERIFY-ONLY (a public
    key + signature + message triple, no private key), so they cannot SIGN an arbitrary Trust Pack predicate
    — that is why ``TestMldsaRootKeyVerifies`` above uses ``pqsig``'s test-key generator instead. What CAN be
    reused directly is the trust_pack `alg='mldsa65'` VERIFY DISPATCH itself: this feeds a real
    government-reference (pk, sig, msg) triple straight into ``trust_pack._verify_signature_for_alg`` and
    checks it agrees with NIST's verdict — proving the dispatch delegates to the same FIPS-204-conformant
    primitive as ``pqsig.verify_mldsa`` (already proven conformant against these vectors elsewhere)."""

    def setUp(self):
        path = Path(__file__).resolve().parent / "fixtures" / "mldsa_acvp" / "mldsa_sigver_slice.json"
        if not (_HAS_MLDSA and path.exists()):
            self.skipTest("mldsa_acvp fixtures not vendored, or cryptography build lacks ML-DSA")
        self.vectors = json.loads(path.read_text(encoding="utf-8"))["vectors"]

    def test_dispatch_matches_nist_verdict_for_mldsa65_vector(self):
        from proofbundle.trust_pack import _verify_signature_for_alg
        vec = next(v for v in self.vectors if v["parameterSet"] == "ML-DSA-65")
        pub = bytes.fromhex(vec["pk"])
        sig_b64 = base64.b64encode(bytes.fromhex(vec["signature"])).decode("ascii")
        msg = bytes.fromhex(vec["message"])
        got = _verify_signature_for_alg("mldsa65", pub, None, {"keyid": "k", "sig": sig_b64}, msg)
        self.assertEqual(got, vec["testPassed"],
                         f"trust_pack mldsa65 dispatch disagrees with NIST ACVP tc{vec['tcId']}")


@unittest.skipUnless(_HAS_MLDSA, "needs cryptography with FIPS 204 (ML-DSA) support")
class TestHybridRootThresholdRequiresBothLegs(unittest.TestCase):
    """R3: the downgrade-protection proof. A `hybrid-ed25519-mldsa65` root key is authenticated ONLY when
    BOTH the Ed25519 (`sig`) and the ML-DSA-65 (`sigPq`) legs verify — never by the classical leg alone."""

    @staticmethod
    def _hybrid_pack():
        ed_sk, m_sk = generate_signer(), generate_mldsa("mldsa65")
        keys = {"root-hybrid-0": {
            "publicKey": _pub_ed25519(ed_sk), "publicKeyPq": _pub_mldsa(m_sk),
            "alg": "hybrid-ed25519-mldsa65",
        }}
        pred = {
            "schemaVersion": "0.1.0", "trustPackId": "tp-agility", "version": 1,
            "expires": "2099-01-01T00:00:00Z", "prevVersionDigest": None,
            "roles": {"root": {"keyIds": ["root-hybrid-0"], "threshold": 1}},
            "keys": keys, "nonClaims": _NON_CLAIMS,
        }
        return pred, ed_sk, m_sk

    def test_hybrid_key_valid_with_only_ed25519_leg_signed(self):
        # THE downgrade-protection proof: an Ed25519-only signature (no sigPq at all) must NOT satisfy a
        # policy-declared hybrid root key.
        pred, ed_sk, _m_sk = self._hybrid_pack()
        self.assertEqual(validate_trust_pack_predicate(pred), [])
        env = _manual_envelope(pred, {"root-hybrid-0": ed_sk})  # single spec -> ONE leg, no "sigPq" field
        self.assertNotIn("sigPq", env["signatures"][0])
        r = verify_trust_pack(env, strict=True, now=_NOW)
        self.assertEqual(r["root_signers"], [])
        self.assertFalse(r["root_threshold_met"])
        self.assertFalse(r["ok"], r)

    def test_hybrid_key_valid_with_both_legs_signed(self):
        pred, ed_sk, m_sk = self._hybrid_pack()
        env = _manual_envelope(pred, {"root-hybrid-0": (ed_sk, m_sk)})
        r = verify_trust_pack(env, strict=True, now=_NOW)
        self.assertEqual(r["root_signers"], ["root-hybrid-0"])
        self.assertTrue(r["root_threshold_met"])
        self.assertTrue(r["ok"], r)

    def test_hybrid_key_fails_if_pq_leg_tampered(self):
        pred, ed_sk, m_sk = self._hybrid_pack()
        env = _manual_envelope(pred, {"root-hybrid-0": (ed_sk, m_sk)})
        sigpq = bytearray(base64.b64decode(env["signatures"][0]["sigPq"]))
        sigpq[0] ^= 0xFF
        env["signatures"][0]["sigPq"] = base64.b64encode(bytes(sigpq)).decode("ascii")
        r = verify_trust_pack(env, strict=True, now=_NOW)
        self.assertFalse(r["root_threshold_met"])
        self.assertFalse(r["ok"], r)

    def test_hybrid_key_fails_if_classical_leg_tampered(self):
        pred, ed_sk, m_sk = self._hybrid_pack()
        env = _manual_envelope(pred, {"root-hybrid-0": (ed_sk, m_sk)})
        sig = bytearray(base64.b64decode(env["signatures"][0]["sig"]))
        sig[0] ^= 0xFF
        env["signatures"][0]["sig"] = base64.b64encode(bytes(sig)).decode("ascii")
        r = verify_trust_pack(env, strict=True, now=_NOW)
        self.assertFalse(r["root_threshold_met"])
        self.assertFalse(r["ok"], r)


@unittest.skipUnless(_HAS_MLDSA, "needs cryptography with FIPS 204 (ML-DSA) support")
class TestRotationOldEd25519ToNewHybrid(unittest.TestCase):
    """R4: two-stage rotation across the algorithm boundary — an OLD classical ed25519 root vouches for a
    NEW hybrid-ed25519-mldsa65 root (the realistic crypto-agility migration path)."""

    @staticmethod
    def _old_pack(prefix: str, version: int):
        sks = {f"{prefix}-{i}": generate_signer() for i in range(2)}
        keys = {kid: {"publicKey": _pub_ed25519(sk)} for kid, sk in sks.items()}
        pred = {
            "schemaVersion": "0.1.0", "trustPackId": "tp-agility", "version": version,
            "expires": "2099-01-01T00:00:00Z",
            "prevVersionDigest": None if version == 1 else {"sha256": _digest(version - 1)},
            "roles": {"root": {"keyIds": list(keys), "threshold": 2}},
            "keys": keys, "nonClaims": _NON_CLAIMS,
        }
        return pred, sks

    @staticmethod
    def _new_hybrid_pack(prefix: str, version: int, prev_version: int):
        ed_sk, m_sk = generate_signer(), generate_mldsa("mldsa65")
        kid = f"{prefix}-hybrid-0"
        keys = {kid: {"publicKey": _pub_ed25519(ed_sk), "publicKeyPq": _pub_mldsa(m_sk),
                     "alg": "hybrid-ed25519-mldsa65"}}
        pred = {
            "schemaVersion": "0.1.0", "trustPackId": "tp-agility", "version": version,
            "expires": "2099-01-01T00:00:00Z", "prevVersionDigest": {"sha256": _digest(prev_version)},
            "roles": {"root": {"keyIds": [kid], "threshold": 1}},
            "keys": keys, "nonClaims": _NON_CLAIMS,
        }
        return pred, kid, ed_sk, m_sk

    def test_old_ed25519_root_vouches_for_new_hybrid_root(self):
        old_pred, old_sks = self._old_pack("oldrot", 3)
        self.assertEqual(validate_trust_pack_predicate(old_pred), [])
        new_pred, new_kid, new_ed, new_m = self._new_hybrid_pack("newrot", 4, prev_version=3)
        self.assertEqual(validate_trust_pack_predicate(new_pred), [])

        # sign under the NEW pack's own (hybrid) root threshold...
        env = _manual_envelope(new_pred, {new_kid: (new_ed, new_m)})
        # ...then the OLD (ed25519) root vouches for the rotation.
        for kid, sk in old_sks.items():
            _external_sign(env, kid, sk)

        old_root_keys = {kid: kv["publicKey"] for kid, kv in old_pred["keys"].items()}
        r = verify_trust_pack(env, strict=True, now=_NOW, prev_version=3,
                              prev_version_digest=_digest(3),
                              prev_root_keys=old_root_keys, prev_root_threshold=2)
        self.assertTrue(r["root_threshold_met"], r)   # new hybrid root threshold met
        self.assertTrue(r["rotation_authorized"], r)  # old ed25519 root vouched
        self.assertEqual(r["old_root_signers"], ["oldrot-0", "oldrot-1"])
        self.assertTrue(r["ok"], r)

    def test_rotation_to_hybrid_without_old_vouch_still_rejected(self):
        # symmetry / no accidental loosening across the alg boundary: a self-owned hybrid v4 chained to a
        # real v3 digest, but with NO old-root vouch, is still rejected (mirrors the pre-existing
        # ed25519-only test_rotation_hijack_rejected in test_trust_pack.py).
        old_pred, _old_sks = self._old_pack("oldrej", 3)
        new_pred, new_kid, new_ed, new_m = self._new_hybrid_pack("newrej", 4, prev_version=3)
        env = _manual_envelope(new_pred, {new_kid: (new_ed, new_m)})
        old_root_keys = {kid: kv["publicKey"] for kid, kv in old_pred["keys"].items()}
        r = verify_trust_pack(env, strict=True, now=_NOW, prev_version=3,
                              prev_version_digest=_digest(3),
                              prev_root_keys=old_root_keys, prev_root_threshold=2)
        self.assertTrue(r["root_threshold_met"], r)  # the new root itself is fine
        self.assertFalse(r["rotation_authorized"])   # but nobody from the old root vouched
        self.assertFalse(r["ok"])


if __name__ == "__main__":
    unittest.main()
