"""3.2.0 O2 Trust Pack — fail-closed validate + THRESHOLD-of-root verify + expiry + rollback + revocation.

TUF-inspired: a threshold of root keys authenticates the pack (not any-single); a revoked key cannot count;
an expired or rolled-back pack fails. unittest-style.
"""
from __future__ import annotations

import base64
import unittest
from datetime import datetime, timezone

from proofbundle.emit import generate_signer
from proofbundle.trust_pack import (
    TrustPackError,
    build_trust_pack_statement,
    sign_trust_pack,
    validate_trust_pack_predicate,
    verify_trust_pack,
)

_NOW = datetime(2026, 7, 14, 12, 0, 0, tzinfo=timezone.utc)


def _pub(sk) -> str:
    return base64.b64encode(sk.public_key().public_bytes_raw()).decode("ascii")


def _fixture(threshold: int = 2, expires: str = "2027-01-01T00:00:00Z", version: int = 3,
             revoked: list | None = None):
    """Build a pack with 3 root keys + a matching signer map. Returns (predicate, signers)."""
    sks = {f"root-{i}": generate_signer() for i in range(3)}
    keys = {kid: {"publicKey": _pub(sk), "scheme": "ed25519"} for kid, sk in sks.items()}
    pred = {
        "schemaVersion": "0.1.0",
        "trustPackId": "tp-0001",
        "version": version,
        "expires": expires,
        "prevVersionDigest": None,
        "roles": {
            "root": {"keyIds": list(keys), "threshold": threshold},
            "outcomeExecutors": {"keyIds": ["root-0"], "threshold": 1},
        },
        "keys": keys,
        "nonClaims": ["names which keys hold which role, not that the holders are honest"],
    }
    if revoked is not None:
        pred["revoked"] = revoked
    return pred, sks


class TestTrustPackValidate(unittest.TestCase):
    def test_valid(self):
        pred, _ = _fixture()
        self.assertEqual(validate_trust_pack_predicate(pred), [])

    def test_root_role_required(self):
        pred, _ = _fixture()
        del pred["roles"]["root"]
        self.assertTrue(any("root" in e for e in validate_trust_pack_predicate(pred)))

    def test_threshold_exceeds_keyids_fails(self):
        pred, _ = _fixture(threshold=5)
        self.assertTrue(any("exceeds the number of keyIds" in e for e in validate_trust_pack_predicate(pred)))

    def test_role_keyid_not_in_keys_fails(self):
        pred, _ = _fixture()
        pred["roles"]["root"]["keyIds"].append("ghost")
        self.assertTrue(any("ghost" in e for e in validate_trust_pack_predicate(pred)))

    def test_revoked_makes_threshold_impossible_fails(self):
        # 3 keys, threshold 2, revoke 2 → only 1 live < 2 → dead on arrival.
        pred, _ = _fixture(threshold=2, revoked=["root-1", "root-2"])
        self.assertTrue(any("never be met" in e for e in validate_trust_pack_predicate(pred)))

    def test_revoked_unknown_key_fails(self):
        pred, _ = _fixture(revoked=["nope"])
        self.assertTrue(any("not present in keys" in e for e in validate_trust_pack_predicate(pred)))

    def test_nonclaims_mandatory(self):
        pred, _ = _fixture()
        del pred["nonClaims"]
        self.assertTrue(any("nonClaims" in e for e in validate_trust_pack_predicate(pred)))

    def test_bad_pubkey_length_fails(self):
        pred, _ = _fixture()
        pred["keys"]["root-0"]["publicKey"] = base64.b64encode(b"short").decode()
        self.assertTrue(any("32-byte" in e for e in validate_trust_pack_predicate(pred)))


class TestTrustPackVerify(unittest.TestCase):
    def test_threshold_met_green(self):
        pred, sks = _fixture(threshold=2)
        env = sign_trust_pack(pred, {"root-0": sks["root-0"], "root-1": sks["root-1"]})
        r = verify_trust_pack(env, strict=True, now=_NOW)
        self.assertTrue(r["ok"], r)
        self.assertTrue(r["root_threshold_met"])
        self.assertEqual(r["root_signers"], ["root-0", "root-1"])

    def test_below_threshold_fails(self):
        pred, sks = _fixture(threshold=2)
        env = sign_trust_pack(pred, {"root-0": sks["root-0"]})  # only 1, need 2
        r = verify_trust_pack(env, strict=True, now=_NOW)
        self.assertFalse(r["root_threshold_met"])
        self.assertFalse(r["ok"])

    def test_wrong_key_signature_does_not_count(self):
        pred, sks = _fixture(threshold=2)
        # one genuine root sig + one signature from a NON-root key smuggled under a root keyid → still 1 valid
        env = sign_trust_pack(pred, {"root-0": sks["root-0"]})
        env["signatures"].append({"keyid": "root-1", "sig": base64.b64encode(b"x" * 64).decode()})
        r = verify_trust_pack(env, strict=True, now=_NOW)
        self.assertEqual(r["root_signers"], ["root-0"])
        self.assertFalse(r["root_threshold_met"])

    def test_revoked_root_key_does_not_count(self):
        pred, sks = _fixture(threshold=1, revoked=["root-0"])
        # outcomeExecutors defaults to root-0; move it to a live key so revoking root-0 does not kill that
        # role (the validate dead-on-arrival guard is separate — proven in TestTrustPackValidate).
        pred["roles"]["outcomeExecutors"] = {"keyIds": ["root-1"], "threshold": 1}
        # sign with the revoked key AND a live one → only the live non-revoked signature counts.
        env = sign_trust_pack(pred, {"root-0": sks["root-0"], "root-1": sks["root-1"]})
        r = verify_trust_pack(env, strict=True, now=_NOW)
        self.assertNotIn("root-0", r["root_signers"])
        self.assertIn("root-1", r["root_signers"])
        self.assertTrue(r["ok"], r)

    def test_expired_fails(self):
        pred, sks = _fixture(threshold=1, expires="2025-01-01T00:00:00Z")
        env = sign_trust_pack(pred, {"root-0": sks["root-0"]})
        r = verify_trust_pack(env, strict=True, now=_NOW)
        self.assertFalse(r["not_expired"])
        self.assertFalse(r["ok"])

    def test_rollback_fails(self):
        pred, sks = _fixture(threshold=1, version=3)
        env = sign_trust_pack(pred, {"root-0": sks["root-0"]})
        r = verify_trust_pack(env, strict=True, now=_NOW, prev_version=3)  # not > 3
        self.assertFalse(r["version_monotone"])
        self.assertFalse(r["ok"])

    def test_monotone_version_ok(self):
        pred, sks = _fixture(threshold=1, version=4)
        env = sign_trust_pack(pred, {"root-0": sks["root-0"]})
        r = verify_trust_pack(env, strict=True, now=_NOW, prev_version=3)
        self.assertTrue(r["version_monotone"])
        self.assertTrue(r["ok"], r)

    def test_prev_version_digest_chain_mismatch_fails(self):
        pred, sks = _fixture(threshold=1)
        env = sign_trust_pack(pred, {"root-0": sks["root-0"]})  # prevVersionDigest is null
        r = verify_trust_pack(env, strict=True, now=_NOW, prev_version_digest="a" * 64)
        self.assertFalse(r["version_monotone"])
        self.assertFalse(r["ok"])

    def test_tamper_breaks_threshold(self):
        pred, sks = _fixture(threshold=2)
        env = sign_trust_pack(pred, {"root-0": sks["root-0"], "root-1": sks["root-1"]})
        # tamper the payload → the signatures no longer verify over the new bytes
        tampered = build_trust_pack_statement({**pred, "trustPackId": "EVIL"})
        import base64 as _b
        import json as _j
        env["payload"] = _b.b64encode(_j.dumps(tampered).encode()).decode()
        r = verify_trust_pack(env, now=_NOW)
        self.assertFalse(r["ok"])
        self.assertFalse(r["root_threshold_met"])

    def test_sign_rejects_unknown_signer_keyid(self):
        pred, sks = _fixture()
        with self.assertRaises(TrustPackError):
            sign_trust_pack(pred, {"stranger": generate_signer()})


def _pack(prefix: str, *, threshold: int = 2, n: int = 3, version: int = 3):
    """A pack whose keyIds carry ``prefix`` (so old/new packs don't collide in one envelope)."""
    sks = {f"{prefix}-{i}": generate_signer() for i in range(n)}
    keys = {kid: {"publicKey": _pub(sk), "scheme": "ed25519"} for kid, sk in sks.items()}
    pred = {
        "schemaVersion": "0.1.0", "trustPackId": "tp-0001", "version": version,
        "expires": "2027-01-01T00:00:00Z", "prevVersionDigest": None,
        "roles": {"root": {"keyIds": list(keys), "threshold": threshold},
                  "outcomeExecutors": {"keyIds": [f"{prefix}-0"], "threshold": 1}},
        "keys": keys,
        "nonClaims": ["names which keys hold which role, not that the holders are honest"],
    }
    return pred, sks


def _external_sign(env: dict, kid: str, sk) -> None:
    """Append a signature under ``kid`` over the envelope's exact PAE (a key NOT in the pack's own keys map,
    e.g. an OLD-root key vouching for a rotation)."""
    from proofbundle import dsse
    from proofbundle.trust_pack import INTOTO_STATEMENT_PAYLOAD_TYPE
    body = base64.b64decode(env["payload"])
    msg = dsse.pae(INTOTO_STATEMENT_PAYLOAD_TYPE, body)
    env["signatures"].append({"keyid": kid, "sig": base64.b64encode(sk.sign(msg)).decode("ascii")})


def _aliased_pred():
    """A pack where two keyIds (root-a, root-a-alias) map to the SAME key material (the Sybil vector)."""
    sk, other = generate_signer(), generate_signer()
    shared = _pub(sk)
    keys = {"root-a": {"publicKey": shared, "scheme": "ed25519"},
            "root-a-alias": {"publicKey": shared, "scheme": "ed25519"},
            "root-b": {"publicKey": _pub(other), "scheme": "ed25519"}}
    pred = {
        "schemaVersion": "0.1.0", "trustPackId": "tp-0001", "version": 3,
        "expires": "2027-01-01T00:00:00Z", "prevVersionDigest": None,
        "roles": {"root": {"keyIds": ["root-a", "root-a-alias", "root-b"], "threshold": 2},
                  "outcomeExecutors": {"keyIds": ["root-b"], "threshold": 1}},
        "keys": keys,
        "nonClaims": ["names which keys hold which role, not that the holders are honest"],
    }
    return pred, sk


class TestTrustPackKeyAliasing(unittest.TestCase):
    """#1 (release-review): a single key under N keyIds must not satisfy an N-of-M root threshold."""

    def test_key_aliasing_rejected_by_validate(self):
        pred, _ = _aliased_pred()
        self.assertTrue(any("aliasing" in e for e in validate_trust_pack_predicate(pred)),
                        validate_trust_pack_predicate(pred))

    def test_sign_rejects_aliased_pack(self):
        pred, sk = _aliased_pred()
        with self.assertRaises(TrustPackError):
            sign_trust_pack(pred, {"root-a": sk, "root-a-alias": sk})

    def test_distinct_keys_still_valid_green(self):
        # a NON-aliased pack (3 distinct keys) still validates — the check is not over-firing.
        pred, _ = _pack("root", threshold=2)
        self.assertEqual(validate_trust_pack_predicate(pred), [])


class TestTrustPackRotationAuthorization(unittest.TestCase):
    """#2 (release-review): a new version must be vouched for by a threshold of the OLD root keys."""

    def test_rotation_authorized_green(self):
        old_pred, old_sks = _pack("old", threshold=2, version=3)
        new_pred, new_sks = _pack("new", threshold=2, version=4)
        env = sign_trust_pack(new_pred, {"new-0": new_sks["new-0"], "new-1": new_sks["new-1"]})
        for kid in ("old-0", "old-1"):  # old root vouches
            _external_sign(env, kid, old_sks[kid])
        old_root_keys = {kid: kv["publicKey"] for kid, kv in old_pred["keys"].items()}
        r = verify_trust_pack(env, strict=True, now=_NOW,
                              prev_root_keys=old_root_keys, prev_root_threshold=2)
        self.assertTrue(r["rotation_authorized"], r)
        self.assertEqual(r["old_root_signers"], ["old-0", "old-1"])
        self.assertTrue(r["ok"], r)

    def test_rotation_hijack_rejected(self):
        # attacker mints v2 with self-owned keys, chained via the PUBLIC prevVersionDigest, but holds NONE of
        # the old root keys → no old-root vouch → rejected once the caller supplies the old root role.
        old_pred, _ = _pack("old", threshold=2, version=3)
        new_pred, new_sks = _pack("new", threshold=2, version=4)
        env = sign_trust_pack(new_pred, {"new-0": new_sks["new-0"], "new-1": new_sks["new-1"]})
        old_root_keys = {kid: kv["publicKey"] for kid, kv in old_pred["keys"].items()}
        r = verify_trust_pack(env, strict=True, now=_NOW,
                              prev_root_keys=old_root_keys, prev_root_threshold=2)
        self.assertFalse(r["rotation_authorized"])
        self.assertFalse(r["ok"])

    def test_rotation_below_old_threshold_rejected(self):
        # only ONE old-root vouch when the old threshold is 2 → not authorized.
        old_pred, old_sks = _pack("old", threshold=2, version=3)
        new_pred, new_sks = _pack("new", threshold=2, version=4)
        env = sign_trust_pack(new_pred, {"new-0": new_sks["new-0"], "new-1": new_sks["new-1"]})
        _external_sign(env, "old-0", old_sks["old-0"])
        old_root_keys = {kid: kv["publicKey"] for kid, kv in old_pred["keys"].items()}
        r = verify_trust_pack(env, strict=True, now=_NOW,
                              prev_root_keys=old_root_keys, prev_root_threshold=2)
        self.assertFalse(r["rotation_authorized"])
        self.assertFalse(r["ok"])

    def test_zero_prev_root_threshold_rejected(self):
        # a caller-supplied prev_root_threshold of 0 must not "authorize" a rotation with zero old-root vouches.
        old_pred, _ = _pack("old", threshold=2, version=3)
        new_pred, new_sks = _pack("new", threshold=2, version=4)
        env = sign_trust_pack(new_pred, {"new-0": new_sks["new-0"], "new-1": new_sks["new-1"]})
        old_root_keys = {kid: kv["publicKey"] for kid, kv in old_pred["keys"].items()}
        r = verify_trust_pack(env, strict=True, now=_NOW,
                              prev_root_keys=old_root_keys, prev_root_threshold=0)
        self.assertFalse(r["rotation_authorized"])
        self.assertFalse(r["ok"])

    def test_no_prev_root_is_backward_compatible(self):
        # a first pack / non-rotation verify does NOT require rotation authorization (field stays None).
        new_pred, new_sks = _pack("new", threshold=2, version=4)
        env = sign_trust_pack(new_pred, {"new-0": new_sks["new-0"], "new-1": new_sks["new-1"]})
        r = verify_trust_pack(env, strict=True, now=_NOW)
        self.assertIsNone(r["rotation_authorized"])
        self.assertTrue(r["ok"], r)

    def test_rotation_claim_without_prev_root_fails_closed(self):
        # audit fix (MEDIUM): a pack that DECLARES a prevVersionDigest but is verified WITHOUT prev_root_keys
        # must FAIL CLOSED by default — a v2 minting self-owned keys + the PUBLIC v1 digest would otherwise
        # pass on its own self-signature (the exact footgun this predicate defends against).
        new_pred, new_sks = _pack("new", threshold=1, version=4)
        new_pred["prevVersionDigest"] = {"sha256": "a" * 64}
        env = sign_trust_pack(new_pred, {"new-0": new_sks["new-0"]})
        r = verify_trust_pack(env, strict=True, now=_NOW)
        self.assertFalse(r["rotation_authorized"])
        self.assertFalse(r["ok"], r)   # the fail-open closes: was ok=True (warn only) before the fix
        self.assertTrue(any("rotation authorization was NOT verified" in e for e in r["errors"]), r["errors"])

    def test_rotation_claim_self_signature_only_opt_out(self):
        # explicit opt-out: a caller wanting only a standalone self-signature check (not a rotation
        # authorization) passes allow_unverified_rotation=True → warns, does not fail closed.
        new_pred, new_sks = _pack("new", threshold=1, version=4)
        new_pred["prevVersionDigest"] = {"sha256": "a" * 64}
        env = sign_trust_pack(new_pred, {"new-0": new_sks["new-0"]})
        r = verify_trust_pack(env, strict=True, now=_NOW, allow_unverified_rotation=True)
        self.assertIsNone(r["rotation_authorized"])
        self.assertTrue(r["ok"], r)
        self.assertTrue(any("rotation authorization was NOT verified" in w for w in r["warnings"]), r["warnings"])


if __name__ == "__main__":
    unittest.main()
