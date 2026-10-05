"""Nachtrag 45 (KRAXO-CLOUD-N45-TRUSTPACK-ANKER-AN-DEN-INHALT-01), Nachbesserung zu N43, Z309 / Release 6.2.0.

BEFUND (gelesen am Code an ae4a4c1d, Zweig claude/security-fix-620-trustpack): bei ``verify_outcome_receipt``
zaehlte der Root-Schluessel-Anker allein (``trust_pack_expected_root_keys``) und ein nacktes durchgereichtes
``trust_pack_pinned=True`` als Anker. ``trust_pack_is_pinned``'s Root-Schluessel-Anker prueft nur, dass die im
PRAEDIKAT erklaerten Root-Schluessel im gepinnten Satz liegen (declared <= pinned) -- keine Signatur ueber das
Praedikat. outcome prueft dort keine Signatur. Ein nie geprueftes Praedikat, das die oeffentlichen gepinnten
Root-Schluessel abschreibt und den Outcome-Signierer als Executor eintraegt, galt damit als vertrauenswuerdig,
``ok`` und ``safeForAutomation`` positiv. Dasselbe fuer ein nacktes ``trust_pack_pinned=True``.

VERTRAG N45: an outcome zaehlt nur ein Anker, der an den INHALT genau des uebergebenen Praedikats gebunden ist:
der Digest-Anker (bleibt); ein gepruefter Umschlag unter den gepinnten Root-Schluesseln, dessen Inhalt das
Praedikat ist (``trust_pack_envelope`` + ``trust_pack_expected_root_keys``); oder ein durchgereichtes Urteil mit
dem Digest des geprueften Praedikats (``trust_pack_pinned=True`` + ``trust_pack_pinned_digest`` ==
sha256(JCS(predicate))). Empfaengerweg folgt derselben Regel.

Je Flaeche rot an ae4a4c1d und gruen danach. Nur fail-closed geprueft, keine weiteren Angriffsproben: die
Angriffs-Praedikate werden nur hier mit Testschluesseln erzeugt, um den geschlossenen Zustand zu belegen.
"""
from __future__ import annotations

import base64
import hashlib
import unittest
from datetime import datetime, timezone

from proofbundle.emit import generate_signer
from proofbundle.outcome import emit_outcome_receipt, verify_outcome_receipt
from proofbundle.trust_pack import _rfc8785_bytes, build_trust_pack_statement, sign_trust_pack

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
        # COUNTER-PROBE (red@ae4a4c1d: executor_role_trusted True, ok True, safeForAutomation True — the BEFUND):
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

    def test_receiver_under_genesis_digest_anchor_is_trusted(self):
        # CONTROL (positive) at the receiver path: content-bound digest anchor AND a resolved+bound receiver key
        # (N45B: a label-only member is not positive, so the control resolves the member's signer key).
        out_sk = generate_signer()
        out_pub = out_sk.public_key().public_bytes_raw()
        env = emit_outcome_receipt(_outcome_pred(with_receiver=True), out_sk)
        recv_pub = generate_signer().public_key().public_bytes_raw()
        pred, _root_sks = _genesis_pack(out_pub, recv_pub)
        r = verify_outcome_receipt(env, out_pub, trust_pack=pred,
                                   trust_pack_expected_genesis_digest=_content_root(pred),
                                   evidence_resolver=lambda d: True,
                                   receiver_attestation_resolver=lambda d: recv_pub)
        self.assertIs(r["receiver_role_trusted"], True)
        self.assertIs(r["receiver_key_bound"], True)

    def test_receiver_under_verified_envelope_is_trusted(self):
        # CONTROL (positive) at the receiver path: verified envelope under the pinned root keys AND a
        # resolved+bound receiver key (N45B).
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
        self.assertIs(r["receiver_role_trusted"], True)
        self.assertIs(r["receiver_key_bound"], True)


if __name__ == "__main__":
    unittest.main()
