"""Addendum 45 (`KRAXO-CLOUD-N45-TRUSTPACK-ANKER-AN-DEN-INHALT-01`), follow-up to N43, Z309 / Release 6.2.0.

FINDING (read on the code at ae4a4c1d, branch claude/security-fix-620-trustpack): in ``verify_outcome_receipt``
the root-key anchor alone (``trust_pack_expected_root_keys``) and a bare forwarded ``trust_pack_pinned=True``
counted as an anchor. ``trust_pack_is_pinned``'s root-key anchor only checks that the root keys DECLARED in the
PREDICATE lie within the pinned set (declared <= pinned) -- no signature over the predicate. outcome checks no
signature there. A never-checked predicate that copies the public pinned root keys and names the outcome signer
as executor therefore counted as trustworthy, with ``ok`` and ``safeForAutomation`` positive. The same held for a
bare ``trust_pack_pinned=True``.

CONTRACT N45: at outcome only an anchor bound to the CONTENT of exactly the passed predicate counts: the digest
anchor (kept); a verified envelope under the pinned root keys whose content is the predicate
(``trust_pack_envelope`` + ``trust_pack_expected_root_keys``); or a forwarded verdict carrying the digest of the
verified predicate (``trust_pack_pinned=True`` + ``trust_pack_pinned_digest`` == sha256(JCS(predicate))). The
receiver path follows the same rule.

N47 (`KRAXO-CLOUD-N47-EMPFAENGER-NICHT-AUS-RESOLVER-ANTWORT-01`) adds, at the receiver path, that a caller
resolver answer no longer confers trust (the library does not verify the referenced receiver statement), so the
receiver controls below assert receiver_role_trusted None and receiver_key_bound None with an error containing
"RECEIVER_STATEMENT_NOT_VERIFIED", not True/True; the anchor rule and the executor controls are unchanged.

Per surface red at ae4a4c1d and green afterwards. Only fail-closed checked, no further attack probes: the attack
predicates are created only here, with test keys, to demonstrate the closed state.
"""
from __future__ import annotations

import base64
import hashlib
import unittest
from datetime import datetime, timezone

from proofbundle.emit import generate_signer
from proofbundle.outcome import emit_outcome_receipt, verify_outcome_receipt
from proofbundle.trust_pack import _rfc8785_bytes, sign_trust_pack

_NOW = datetime(2026, 7, 14, 12, 0, 0, tzinfo=timezone.utc)


def _pub_b64(sk) -> str:
    return base64.b64encode(sk.public_key().public_bytes_raw()).decode("ascii")


def _content_root(pred: dict) -> str:
    # sha256(JCS(predicate)): the trust-pack content root (= build_trust_pack_statement's subject digest).
    return hashlib.sha256(_rfc8785_bytes(pred)).hexdigest()


def _outcome_pred(with_receiver: bool = False) -> dict:
    p = {"schemaVersion": "0.1.0", "outcomeId": "outcome-n45", "decisionRef": {"sha256": "a" * 64},
         "executor": {"id": "executor:runner-7", "keyId": "kid-exec"},
         "requestedActionDigest": {"sha256": "c" * 64}, "status": "executed",
         "performedAt": "2026-07-14T10:00:00Z", "effectDigest": {"sha256": "c" * 64}}
    if with_receiver:
        p["receiverRefs"] = [{"relation": "observed", "digest": {"sha256": "d" * 64},
                              "receiverKeyId": "kid-recv"}]
    return p


def _genesis_pack(exec_pub: bytes, recv_pub: "bytes | None" = None):
    """A real genesis (version 1) trust-pack predicate: 2 root keys (threshold 2), outcomeExecutors[kid-exec]
    bound to the outcome signer's key (so key-binding holds), optionally outcomeReceivers[kid-recv]. Returns
    (predicate, {rootKeyId: signer}) so a test can ALSO sign it into an envelope for the verified-envelope path."""
    root_sks = {f"root-{i}": generate_signer() for i in range(2)}
    keys = {kid: {"publicKey": _pub_b64(sk)} for kid, sk in root_sks.items()}
    keys["kid-exec"] = {"publicKey": base64.b64encode(exec_pub).decode("ascii")}
    roles = {"root": {"keyIds": list(root_sks), "threshold": 2},
             "outcomeExecutors": {"keyIds": ["kid-exec"], "threshold": 1}}
    if recv_pub is not None:
        keys["kid-recv"] = {"publicKey": base64.b64encode(recv_pub).decode("ascii")}
        roles["outcomeReceivers"] = {"keyIds": ["kid-recv"], "threshold": 1}
    pred = {"schemaVersion": "0.1.0", "trustPackId": "tp-n45", "version": 1,
            "expires": "2099-01-01T00:00:00Z", "prevVersionDigest": None,
            "roles": roles, "keys": keys,
            "nonClaims": ["names which keys hold which role, not that the holders are honest"]}
    return pred, root_sks


def _pinned_root_keys(pred: dict) -> dict:
    # The relying party's pinned root identity == the pack's DECLARED root keys (the exact copy an attacker would
    # transcribe). At ae4a4c1d this alone made trust_pack_is_pinned return True; N45 rejects it without a
    # verified envelope.
    return {kid: {"publicKey": pred["keys"][kid]["publicKey"]} for kid in pred["roles"]["root"]["keyIds"]}


class _Base(unittest.TestCase):
    def _exec_fixtures(self, with_receiver=False, recv=False):
        out_sk = generate_signer()
        out_pub = out_sk.public_key().public_bytes_raw()
        env = emit_outcome_receipt(_outcome_pred(with_receiver=with_receiver), out_sk)
        recv_pub = generate_signer().public_key().public_bytes_raw() if recv else None
        pred, root_sks = _genesis_pack(out_pub, recv_pub)
        return env, out_pub, pred, root_sks


class TestExecutorAnchorBoundToContent(_Base):
    """Executor role trust is positive only under an anchor bound to THIS predicate's content."""

    def test_naked_root_key_copy_is_not_trusted(self):
        # COUNTER-PROBE (red@ae4a4c1d: executor_role_trusted True, ok True, safeForAutomation True — the FINDING):
        # a predicate copying the pinned public root keys + the outcome signer as executor, no verified envelope.
        env, out_pub, pred, _ = self._exec_fixtures()
        r = verify_outcome_receipt(env, out_pub, trust_pack=pred,
                                   trust_pack_expected_root_keys=_pinned_root_keys(pred))
        self.assertIs(r["executor_role_trusted"], False)
        self.assertIs(r["executor_key_bound"], True)   # the key IS bound; only a content-bound anchor is missing
        self.assertIs(r["ok"], False)
        self.assertIs(r["automation"]["safeForAutomation"], False)
        self.assertIn("TRUST_PACK_NOT_ANCHORED", r["automation"]["automationBlockers"])

    def test_bare_forwarded_pinned_true_is_not_trusted(self):
        # COUNTER-PROBE (red@ae4a4c1d: a bare forwarded True was accepted): not bound to any predicate.
        env, out_pub, pred, _ = self._exec_fixtures()
        r = verify_outcome_receipt(env, out_pub, trust_pack=pred, trust_pack_pinned=True)
        self.assertIs(r["executor_role_trusted"], False)
        self.assertIs(r["ok"], False)
        self.assertIn("TRUST_PACK_NOT_ANCHORED", r["automation"]["automationBlockers"])

    def test_forwarded_pinned_true_with_wrong_digest_is_not_trusted(self):
        # COUNTER-PROBE: a forwarded True carrying the digest of a DIFFERENT predicate does not bind this one.
        env, out_pub, pred, _ = self._exec_fixtures()
        other_pred, _ = _genesis_pack(generate_signer().public_key().public_bytes_raw())
        r = verify_outcome_receipt(env, out_pub, trust_pack=pred, trust_pack_pinned=True,
                                   trust_pack_pinned_digest=_content_root(other_pred))
        self.assertIs(r["executor_role_trusted"], False)
        self.assertIs(r["ok"], False)
        self.assertIn("TRUST_PACK_NOT_ANCHORED", r["automation"]["automationBlockers"])

    def test_genesis_digest_anchor_is_trusted(self):
        # CONTROL (positive): the content-bound digest anchor (unchanged by N45).
        env, out_pub, pred, _ = self._exec_fixtures()
        r = verify_outcome_receipt(env, out_pub, trust_pack=pred,
                                   trust_pack_expected_genesis_digest=_content_root(pred))
        self.assertIs(r["executor_role_trusted"], True)
        self.assertIs(r["executor_key_bound"], True)
        self.assertIs(r["ok"], True)
        self.assertIs(r["automation"]["safeForAutomation"], True)

    def test_verified_envelope_under_pinned_root_is_trusted(self):
        # CONTROL (positive): a pack envelope whose threshold signature verifies under the pinned root keys AND
        # whose content is exactly this predicate.
        env, out_pub, pred, root_sks = self._exec_fixtures()
        pack_env = sign_trust_pack(pred, root_sks)   # signed by the pack's own (= pinned) root keys
        r = verify_outcome_receipt(env, out_pub, trust_pack=pred,
                                   trust_pack_envelope=pack_env,
                                   trust_pack_expected_root_keys=_pinned_root_keys(pred))
        self.assertIs(r["executor_role_trusted"], True)
        self.assertIs(r["ok"], True)
        self.assertIs(r["automation"]["safeForAutomation"], True)

    def test_envelope_whose_content_differs_is_not_trusted(self):
        # COUNTER-PROBE: an envelope that verifies under the pinned root keys but carries a DIFFERENT predicate
        # than the one passed to outcome does not bind this predicate (content mismatch).
        env, out_pub, pred, root_sks = self._exec_fixtures()
        other_pred, _ = _genesis_pack(out_pub)        # different trustPackId content, same root signers
        other_pred["trustPackId"] = "tp-n45-other"
        pack_env = sign_trust_pack(other_pred, root_sks)
        r = verify_outcome_receipt(env, out_pub, trust_pack=pred,
                                   trust_pack_envelope=pack_env,
                                   trust_pack_expected_root_keys=_pinned_root_keys(pred))
        self.assertIs(r["executor_role_trusted"], False)
        self.assertIs(r["ok"], False)
        self.assertIn("TRUST_PACK_NOT_ANCHORED", r["automation"]["automationBlockers"])

    def test_forwarded_pinned_true_with_matching_digest_is_trusted(self):
        # CONTROL (positive): a forwarded rotation verdict carrying the digest of THIS predicate.
        env, out_pub, pred, _ = self._exec_fixtures()
        r = verify_outcome_receipt(env, out_pub, trust_pack=pred, trust_pack_pinned=True,
                                   trust_pack_pinned_digest=_content_root(pred))
        self.assertIs(r["executor_role_trusted"], True)
        self.assertIs(r["ok"], True)
        self.assertIs(r["automation"]["safeForAutomation"], True)


class TestReceiverAnchorBoundToContent(_Base):
    """Receiver role trust follows the same rule (receiverRefs never gates ok, but role trust must be anchored)."""

    def _recv_error_present(self, r):
        return any("TRUST_PACK_NOT_ANCHORED" in e and "receiverRefs" in e for e in r["errors"])

    def test_receiver_naked_root_key_copy_is_not_trusted(self):
        # COUNTER-PROBE at the receiver path (red@ae4a4c1d: receiver_role_trusted True).
        env, out_pub, pred, _ = self._exec_fixtures(with_receiver=True, recv=True)
        r = verify_outcome_receipt(env, out_pub, trust_pack=pred,
                                   trust_pack_expected_root_keys=_pinned_root_keys(pred))
        self.assertIs(r["receiver_role_trusted"], False)
        self.assertTrue(self._recv_error_present(r))

    def test_receiver_bare_forwarded_pinned_true_is_not_trusted(self):
        # COUNTER-PROBE at the receiver path with a bare forwarded True.
        env, out_pub, pred, _ = self._exec_fixtures(with_receiver=True, recv=True)
        r = verify_outcome_receipt(env, out_pub, trust_pack=pred, trust_pack_pinned=True)
        self.assertIs(r["receiver_role_trusted"], False)
        self.assertTrue(self._recv_error_present(r))

    def test_receiver_under_genesis_digest_anchor_is_not_positive_statement_not_verified(self):
        # CONTROL (was positive under N45B) at the receiver path: content-bound digest anchor AND a resolved key
        # that byte-matches the pack key. N47: a caller resolver answer can no longer confer receiver trust (the
        # library does not itself verify the referenced receiver statement), so this is receiver_role_trusted
        # None, receiver_key_bound None with RECEIVER_STATEMENT_NOT_VERIFIED, not True/True. The anchor still holds.
        out_sk = generate_signer()
        out_pub = out_sk.public_key().public_bytes_raw()
        env = emit_outcome_receipt(_outcome_pred(with_receiver=True), out_sk)
        recv_pub = generate_signer().public_key().public_bytes_raw()
        pred, _root_sks = _genesis_pack(out_pub, recv_pub)
        r = verify_outcome_receipt(env, out_pub, trust_pack=pred,
                                   trust_pack_expected_genesis_digest=_content_root(pred),
                                   evidence_resolver=lambda d: True,
                                   receiver_attestation_resolver=lambda d: recv_pub)
        self.assertIsNone(r["receiver_role_trusted"])
        self.assertIsNone(r["receiver_key_bound"])
        self.assertTrue(any("RECEIVER_STATEMENT_NOT_VERIFIED" in e for e in r["errors"]))

    def test_receiver_under_verified_envelope_is_not_positive_statement_not_verified(self):
        # CONTROL (was positive under N45B) at the receiver path: verified envelope under the pinned root keys AND
        # a resolved key that byte-matches the pack key. N47: a caller resolver answer can no longer confer
        # receiver trust (the library does not itself verify the referenced receiver statement), so this is
        # receiver_role_trusted None, receiver_key_bound None with RECEIVER_STATEMENT_NOT_VERIFIED, not True/True.
        out_sk = generate_signer()
        out_pub = out_sk.public_key().public_bytes_raw()
        env = emit_outcome_receipt(_outcome_pred(with_receiver=True), out_sk)
        recv_pub = generate_signer().public_key().public_bytes_raw()
        pred, root_sks = _genesis_pack(out_pub, recv_pub)
        pack_env = sign_trust_pack(pred, root_sks)
        r = verify_outcome_receipt(env, out_pub, trust_pack=pred,
                                   trust_pack_envelope=pack_env,
                                   trust_pack_expected_root_keys=_pinned_root_keys(pred),
                                   evidence_resolver=lambda d: True,
                                   receiver_attestation_resolver=lambda d: recv_pub)
        self.assertIsNone(r["receiver_role_trusted"])
        self.assertIsNone(r["receiver_key_bound"])
        self.assertTrue(any("RECEIVER_STATEMENT_NOT_VERIFIED" in e for e in r["errors"]))


if __name__ == "__main__":
    unittest.main()
