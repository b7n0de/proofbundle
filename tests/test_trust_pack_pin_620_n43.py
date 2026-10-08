"""N43 (security-fix 6.2.0): a Trust Pack confers TRUST only under a RELYING-PARTY ANCHOR.

Z309 / security-fix-620 class, trust-pack axis. A genesis Trust Pack self-authenticates from its OWN declared
root keys, so at the N38 head (f2443ed8) ``verify_trust_pack`` reported ``ok=True`` AND
``automation.safeForAutomation=True`` with NO relying-party input, and ``verify_outcome_receipt`` reported a
supplied-but-unpinned pack's executor as ``executor_role_trusted=True`` (and ``ok=True``,
``safeForAutomation=True``). Measured red at f2443ed8 in ``scratchpad/n43/belege/red_f2443ed8_both.txt``.

The contract (every test below is a FAIL-CLOSED test — a secure behaviour, never an attack rebuild):
  - ``ok`` is unchanged: it stays the self-authentication verdict (form, threshold, expiry, chain).
  - a NEW field ``pinned`` names whether the pack is bound to an anchor: True / False / None.
  - ``safeForAutomation`` and every DERIVED trust statement (outcome executor/receiver role) are positive ONLY
    when ``pinned`` is True — a genesis/content-root digest pin, a root-key set pin, or a rotation whose
    pinned predecessor's old root vouched.

Each surface has: the no-pin COUNTER-PROBE (must not be positive) + the correct-pin CONTROL (positive).
"""
from __future__ import annotations

import base64
import hashlib
import unittest
from datetime import datetime, timezone

from proofbundle.emit import generate_signer
from proofbundle.outcome import emit_outcome_receipt, verify_outcome_receipt
from proofbundle.trust_pack import (
    _rfc8785_bytes,
    build_trust_pack_statement,
    sign_trust_pack,
    trust_pack_is_pinned,
    verify_trust_pack,
)

_NOW = datetime(2026, 7, 14, 12, 0, 0, tzinfo=timezone.utc)


def _pub(sk) -> str:
    return base64.b64encode(sk.public_key().public_bytes_raw()).decode("ascii")


def _genesis(threshold: int = 2):
    """A real genesis pack (version 1, null prevVersionDigest) with 3 root keys + its signer map."""
    sks = {f"root-{i}": generate_signer() for i in range(3)}
    keys = {kid: {"publicKey": _pub(sk)} for kid, sk in sks.items()}
    pred = {
        "schemaVersion": "0.1.0", "trustPackId": "tp-n43", "version": 1,
        "expires": "2027-01-01T00:00:00Z", "prevVersionDigest": None,
        "roles": {"root": {"keyIds": list(keys), "threshold": threshold}},
        "keys": keys,
        "nonClaims": ["names which keys hold which role, not that the holders are honest"],
    }
    return pred, sks


def _content_root(pred: dict) -> str:
    return build_trust_pack_statement(pred)["subject"][0]["digest"]["sha256"]


def _root_keys_pin(pred: dict) -> dict:
    return {kid: {"publicKey": pred["keys"][kid]["publicKey"]} for kid in pred["roles"]["root"]["keyIds"]}


class TestVerifyTrustPackPin(unittest.TestCase):
    """K1: verify_trust_pack.automation.safeForAutomation is positive only under an RP anchor; ok unchanged."""

    def test_genesis_without_anchor_is_not_safe_for_automation(self):
        # COUNTER-PROBE (red at f2443ed8: safeForAutomation True, blockers []).
        pred, sks = _genesis()
        r = verify_trust_pack(sign_trust_pack(pred, sks), strict=True, now=_NOW)
        self.assertIs(r["ok"], True)                  # self-authentication is unchanged
        self.assertIsNone(r["pinned"])                # no anchor supplied -> unestablished
        self.assertIs(r["automation"]["safeForAutomation"], False)
        self.assertIn("POLICY_NOT_EVALUATED", r["automation"]["automationBlockers"])

    def test_genesis_digest_pin_correct_is_safe(self):
        # CONTROL.
        pred, sks = _genesis()
        r = verify_trust_pack(sign_trust_pack(pred, sks), strict=True, now=_NOW,
                              expected_genesis_digest=_content_root(pred))
        self.assertIs(r["ok"], True)
        self.assertIs(r["pinned"], True)
        self.assertIs(r["automation"]["safeForAutomation"], True)

    def test_genesis_digest_pin_wrong_fails_closed(self):
        pred, sks = _genesis()
        r = verify_trust_pack(sign_trust_pack(pred, sks), strict=True, now=_NOW,
                              expected_genesis_digest="a" * 64)
        self.assertIs(r["ok"], True)                  # ok still unchanged
        self.assertIs(r["pinned"], False)             # anchor supplied, no match -> refuted
        self.assertIs(r["automation"]["safeForAutomation"], False)
        self.assertIn("POLICY_FAILED", r["automation"]["automationBlockers"])

    def test_root_keys_pin_correct_is_safe(self):
        # CONTROL.
        pred, sks = _genesis()
        r = verify_trust_pack(sign_trust_pack(pred, sks), strict=True, now=_NOW,
                              expected_root_keys=_root_keys_pin(pred))
        self.assertIs(r["pinned"], True)
        self.assertIs(r["automation"]["safeForAutomation"], True)

    def test_root_keys_pin_partial_fails_closed(self):
        # the declared root is NOT a subset of the pinned set -> not bound (fail-closed).
        pred, sks = _genesis()
        full = _root_keys_pin(pred)
        partial = {next(iter(full)): full[next(iter(full))]}   # only one of three declared root keys
        r = verify_trust_pack(sign_trust_pack(pred, sks), strict=True, now=_NOW, expected_root_keys=partial)
        self.assertIs(r["pinned"], False)
        self.assertIs(r["automation"]["safeForAutomation"], False)

    def test_root_keys_pin_foreign_key_fails_closed(self):
        pred, sks = _genesis()
        other = base64.b64encode(generate_signer().public_key().public_bytes_raw()).decode("ascii")
        r = verify_trust_pack(sign_trust_pack(pred, sks), strict=True, now=_NOW,
                              expected_root_keys={"x": {"publicKey": other}})
        self.assertIs(r["pinned"], False)

    def test_rotation_vouched_is_pinned(self):
        # CONTROL: a v2 whose OLD (pinned) root vouched is anchored.
        pred1, sks1 = _genesis()
        gdigest = _content_root(pred1)
        pred2, _ = _genesis(threshold=2)
        pred2["version"] = 2
        pred2["prevVersionDigest"] = {"sha256": gdigest}
        pred2["keys"] = pred1["keys"]
        pred2["roles"]["root"]["keyIds"] = pred1["roles"]["root"]["keyIds"]
        env2 = sign_trust_pack(pred2, sks1)   # signed by the OLD (genesis) root keys
        prev_root = {kid: pred1["keys"][kid]["publicKey"] for kid in pred1["roles"]["root"]["keyIds"]}
        r = verify_trust_pack(env2, strict=True, now=_NOW, prev_version=1, prev_version_digest=gdigest,
                              prev_root_keys=prev_root, prev_root_threshold=2)
        self.assertIs(r["rotation_authorized"], True)
        self.assertIs(r["pinned"], True)
        self.assertIs(r["automation"]["safeForAutomation"], True)

    def test_ok_is_never_changed_by_the_pin(self):
        # The PROPERTY: ok is identical with and without the pin — pin governs only trust, never ok.
        pred, sks = _genesis()
        env = sign_trust_pack(pred, sks)
        ok_without = verify_trust_pack(env, strict=True, now=_NOW)["ok"]
        ok_with = verify_trust_pack(env, strict=True, now=_NOW,
                                    expected_genesis_digest=_content_root(pred))["ok"]
        ok_wrong = verify_trust_pack(env, strict=True, now=_NOW, expected_genesis_digest="a" * 64)["ok"]
        self.assertIs(ok_without, True)
        self.assertIs(ok_with, True)
        self.assertIs(ok_wrong, True)


class TestTrustPackIsPinnedDirect(unittest.TestCase):
    """trust_pack_is_pinned: three states, never two; fail-closed, never raises."""

    def test_three_states(self):
        pred, _ = _genesis()
        self.assertIsNone(trust_pack_is_pinned(pred))                               # no anchor -> None
        self.assertIs(trust_pack_is_pinned(pred, expected_genesis_digest="a" * 64), False)  # supplied, no match
        self.assertIs(trust_pack_is_pinned(pred, expected_genesis_digest=_content_root(pred)), True)
        self.assertIs(trust_pack_is_pinned(pred, expected_root_keys=_root_keys_pin(pred)), True)

    def test_rotation_anchor_supplied_but_not_authorized_is_false(self):
        # rotation_authorized is the tri-state verdict: False = a rotation anchor was supplied but the old root
        # did not vouch -> a supplied anchor that did not match -> False (not None).
        pred, _ = _genesis()
        self.assertIs(trust_pack_is_pinned(pred, rotation_authorized=False), False)
        self.assertIsNone(trust_pack_is_pinned(pred, rotation_authorized=None))  # no rotation anchor at all

    def test_malformed_predicate_never_raises(self):
        for bad in (None, 5, "x", {"keys": "nope"}, {"roles": 7}):
            self.assertIn(trust_pack_is_pinned(bad, expected_root_keys={"x": {"publicKey": "A" * 43 + "="}}),
                          (False,))   # anchor supplied, nothing matches -> False, never a raise
            self.assertIsNone(trust_pack_is_pinned(bad))   # no anchor -> None, never a raise


def _outcome_pred(**over):
    p = {"schemaVersion": "0.1.0", "outcomeId": "outcome-n43", "decisionRef": {"sha256": "a" * 64},
         "executor": {"id": "executor:runner-7", "keyId": "kid-exec"},
         "requestedActionDigest": {"sha256": "c" * 64}, "status": "executed",
         "performedAt": "2026-07-14T10:00:00Z", "effectDigest": {"sha256": "c" * 64}}
    p.update(over)
    return p


def _outcome_pack(executor_pub):
    # A genesis pack naming kid-exec in outcomeExecutors, carrying its real key material (L1-600-02).
    return {"schemaVersion": "0.1.0", "trustPackId": "tp-o-n43", "version": 1,
            "expires": "2099-01-01T00:00:00Z", "prevVersionDigest": None,
            "roles": {"root": {"keyIds": ["root-0"], "threshold": 1},
                      "outcomeExecutors": {"keyIds": ["kid-exec"], "threshold": 1}},
            "keys": {"root-0": {"publicKey": "A" * 43 + "="},
                     "kid-exec": {"publicKey": base64.b64encode(executor_pub).decode("ascii")}},
            "nonClaims": ["names which keys hold which role, not that the holders are honest"]}


class TestOutcomeExecutorRolePin(unittest.TestCase):
    """K2: the DERIVED executor-role trust statement is positive only under an RP anchor; ok/no-pack unchanged."""

    def _env_pub_pack(self):
        s = generate_signer()
        pub = s.public_key().public_bytes_raw()
        return emit_outcome_receipt(_outcome_pred(), s), pub, _outcome_pack(pub)

    def test_supplied_pack_without_anchor_is_not_trusted(self):
        # COUNTER-PROBE (red at f2443ed8: executor_role_trusted True, ok True, safeForAutomation True).
        env, pub, pack = self._env_pub_pack()
        r = verify_outcome_receipt(env, pub, trust_pack=pack)
        self.assertIs(r["executor_role_trusted"], False)
        self.assertIs(r["executor_key_bound"], True)        # the key IS bound; only the anchor is missing
        self.assertIs(r["ok"], False)
        self.assertIs(r["automation"]["safeForAutomation"], False)
        self.assertIn("TRUST_PACK_NOT_ANCHORED", r["automation"]["automationBlockers"])
        self.assertTrue(any("TRUST_PACK_NOT_ANCHORED" in e for e in r["errors"]), r["errors"])

    def test_genesis_digest_pin_makes_executor_trusted(self):
        # CONTROL.
        env, pub, pack = self._env_pub_pack()
        gdigest = hashlib.sha256(_rfc8785_bytes(pack)).hexdigest()
        r = verify_outcome_receipt(env, pub, trust_pack=pack, trust_pack_expected_genesis_digest=gdigest)
        self.assertIs(r["executor_role_trusted"], True)
        self.assertIs(r["ok"], True)
        self.assertIs(r["automation"]["safeForAutomation"], True)

    def test_root_keys_pin_makes_executor_trusted(self):
        # CONTROL (N45): the root-key anchor now counts ONLY with a verifying pack ENVELOPE whose threshold
        # signature verifies under the pinned root keys AND whose content is this predicate — a root-key
        # identity match alone no longer anchors (N45). So the pack carries a real root key and a real
        # envelope here, and the root-keys pin is forwarded together with that envelope.
        s = generate_signer()
        pub = s.public_key().public_bytes_raw()
        env = emit_outcome_receipt(_outcome_pred(), s)
        root_sk = generate_signer()
        pack = _outcome_pack(pub)
        pack["keys"]["root-0"] = {"publicKey": _pub(root_sk)}   # a real root key so an envelope can verify
        pack_env = sign_trust_pack(pack, {"root-0": root_sk})
        r = verify_outcome_receipt(env, pub, trust_pack=pack,
                                   trust_pack_envelope=pack_env,
                                   trust_pack_expected_root_keys=_root_keys_pin(pack))
        self.assertIs(r["executor_role_trusted"], True)
        self.assertIs(r["ok"], True)

    def test_forwarded_rotation_verdict_makes_executor_trusted(self):
        # CONTROL (N45): the caller forwards a rotation-authorized verify_trust_pack verdict this path cannot
        # recompute. Under N45 that forwarded verdict counts only when the caller also forwards the digest it
        # was computed over (trust_pack_pinned_digest == sha256(JCS(predicate))); a naked trust_pack_pinned=True
        # no longer anchors.
        env, pub, pack = self._env_pub_pack()
        r = verify_outcome_receipt(env, pub, trust_pack=pack, trust_pack_pinned=True,
                                   trust_pack_pinned_digest=hashlib.sha256(_rfc8785_bytes(pack)).hexdigest())
        self.assertIs(r["executor_role_trusted"], True)
        self.assertIs(r["ok"], True)

    def test_wrong_digest_pin_fails_closed(self):
        env, pub, pack = self._env_pub_pack()
        r = verify_outcome_receipt(env, pub, trust_pack=pack, trust_pack_expected_genesis_digest="a" * 64)
        self.assertIs(r["executor_role_trusted"], False)
        self.assertIs(r["ok"], False)

    def test_no_trust_pack_is_unchanged(self):
        # Backward compatible: the no-trust_pack path is untouched (executor_role_trusted None, ok True).
        env, pub, _ = self._env_pub_pack()
        r = verify_outcome_receipt(env, pub)
        self.assertIsNone(r["executor_role_trusted"])
        self.assertIs(r["ok"], True)

    def test_malformed_pack_with_anchor_never_crashes(self):
        env, pub, _ = self._env_pub_pack()
        for bad in ({}, {"roles": "x"}, {"roles": {"outcomeExecutors": "x"}}):
            r = verify_outcome_receipt(env, pub, trust_pack=bad,
                                       trust_pack_expected_root_keys={"root-0": {"publicKey": "A" * 43 + "="}})
            self.assertIsNot(r["executor_role_trusted"], True)   # never positive, never a raise


class TestOutcomeReceiverRolePin(unittest.TestCase):
    """K2 sibling: receiver_role_trusted is positive only under an RP anchor."""

    def _env_pub_pack(self, receiver_pub):
        s = generate_signer()
        pub = s.public_key().public_bytes_raw()
        pred = _outcome_pred(receiverRefs=[{"relation": "receiverAck", "digest": {"sha256": "d" * 64},
                                            "receiverId": "receiver:svc-1", "receiverKeyId": "kid-recv"}])
        env = emit_outcome_receipt(pred, s)
        pack = _outcome_pack(pub)
        pack["roles"]["outcomeReceivers"] = {"keyIds": ["kid-recv"], "threshold": 1}
        pack["keys"]["kid-recv"] = {"publicKey": base64.b64encode(receiver_pub).decode("ascii")}
        return env, pub, pack

    def test_receiver_role_without_anchor_is_not_trusted(self):
        # COUNTER-PROBE.
        rs = generate_signer()
        env, pub, pack = self._env_pub_pack(rs.public_key().public_bytes_raw())
        r = verify_outcome_receipt(env, pub, trust_pack=pack)
        self.assertIs(r["receiver_role_trusted"], False)
        self.assertTrue(any("TRUST_PACK_NOT_ANCHORED" in e for e in r["errors"]), r["errors"])

    def test_receiver_role_with_anchor_is_evaluated(self):
        # CONTROL (N45/N45B): under a content-bound anchor the receiver role is EVALUATED (membership answered),
        # not fail-closed by a missing anchor. Under N45B a member by LABEL only (no attestation resolver bound a
        # signer key) is no longer a positive verdict: receiver_role_trusted is None with a named reason, and
        # there is NO TRUST_PACK_NOT_ANCHORED error (the pack IS anchored). OLD: True by label.
        rs = generate_signer()
        env, pub, pack = self._env_pub_pack(rs.public_key().public_bytes_raw())
        r = verify_outcome_receipt(env, pub, trust_pack=pack,
                                   trust_pack_expected_genesis_digest=hashlib.sha256(_rfc8785_bytes(pack)).hexdigest())
        self.assertIsNone(r["receiver_role_trusted"])
        self.assertIsNone(r["receiver_key_bound"])
        self.assertTrue(any("RECEIVER_ROLE_NOT_BOUND" in e for e in r["errors"]), r["errors"])
        self.assertFalse(any("TRUST_PACK_NOT_ANCHORED" in e for e in r["errors"]), r["errors"])


if __name__ == "__main__":
    unittest.main()
