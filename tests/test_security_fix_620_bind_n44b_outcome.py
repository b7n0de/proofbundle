"""Order 44b (cloud order on the outcome surface with a verified trust pack), counter-probe from the Codex
class-search appendix (REPORT_codex_klassensuche_bindungswege_e37e872b_20261005.md, Fund 2).

Fund 2 at e37e872b: ``verify_outcome_receipt(..., trust_pack=<predicate>)`` took a bare trust-pack PREDICATE
that was never run through ``verify_trust_pack``; if the predicate named the role and exactly the outcome
signer's key, it reported ``executor_role_trusted=True``, ``executor_key_bound=True``, ``ok=True`` and
``safeForAutomation=True``.

N43 (claude/security-fix-620-trustpack) ALREADY closes this class: a trust-pack-derived role statement is
positive only when the pack is bound to a relying-party ANCHOR (``outcome.py`` gates
``executor_role_trusted`` on ``_tp_pinned is True`` via ``trust_pack.trust_pack_is_pinned``; without an anchor it
emits ``TRUST_PACK_NOT_ANCHORED`` and ``ok``/``safeForAutomation`` are not positive). The N43 fix and its
counter-probe/control live in ``tests/test_trust_pack_pin_620_n43.py::TestOutcomeExecutorRolePin``
(``test_supplied_pack_without_anchor_is_not_trusted`` and the anchor controls) and
``tests/test_outcome_verify.py::test_member_key_id_without_anchor_is_not_trusted``.

This file ADDS the appendix's exact construction as an extra counter-probe: a v2 (rotation-SHAPED) pack
predicate, never verified, passed bare -> not positive; and the appendix's legitimate positive control, a v2
pack actually verified through ``verify_trust_pack`` under a pinned predecessor (rotation_authorized), whose
verdict is then forwarded -> positive. Fail-closed only, no attack rebuild beyond the fail-closed case.
"""
from __future__ import annotations

import base64
import hashlib
import unittest
from datetime import datetime, timezone

from proofbundle.emit import generate_signer
from proofbundle.outcome import emit_outcome_receipt, verify_outcome_receipt
from proofbundle.trust_pack import _rfc8785_bytes, build_trust_pack_statement, sign_trust_pack, verify_trust_pack

_NOW = datetime(2026, 7, 14, 12, 0, 0, tzinfo=timezone.utc)


def _n45_digest(p: dict) -> str:
    # N45 content root sha256(JCS(predicate)) — the content-bound anchor digest at the outcome layer.
    return hashlib.sha256(_rfc8785_bytes(p)).hexdigest()


def _pub_b64(sk) -> str:
    return base64.b64encode(sk.public_key().public_bytes_raw()).decode("ascii")


def _content_root(pred: dict) -> str:
    return build_trust_pack_statement(pred)["subject"][0]["digest"]["sha256"]


def _outcome_pred():
    return {"schemaVersion": "0.1.0", "outcomeId": "outcome-n44b", "decisionRef": {"sha256": "a" * 64},
            "executor": {"id": "executor:runner-7", "keyId": "kid-exec"},
            "requestedActionDigest": {"sha256": "c" * 64}, "status": "executed",
            "performedAt": "2026-07-14T10:00:00Z", "effectDigest": {"sha256": "c" * 64}}


def _v1_genesis():
    """A real genesis (version 1) pack with 2 root keys + its signer map."""
    sks = {f"root-{i}": generate_signer() for i in range(2)}
    keys = {kid: {"publicKey": _pub_b64(sk)} for kid, sk in sks.items()}
    pred = {"schemaVersion": "0.1.0", "trustPackId": "tp-n44b", "version": 1,
            "expires": "2099-01-01T00:00:00Z", "prevVersionDigest": None,
            "roles": {"root": {"keyIds": list(keys), "threshold": 2}},
            "keys": keys,
            "nonClaims": ["names which keys hold which role, not that the holders are honest"]}
    return pred, sks


def _v2_predicate(executor_pub: bytes, v1_pred: dict) -> dict:
    """A v2 (rotation-shaped) pack naming kid-exec in outcomeExecutors with the outcome signer's key, linking
    the v1 genesis as its predecessor. A bare PREDICATE — nothing here proves it was ever verified."""
    keys = dict(v1_pred["keys"])
    keys["kid-exec"] = {"publicKey": base64.b64encode(executor_pub).decode("ascii")}
    return {"schemaVersion": "0.1.0", "trustPackId": "tp-n44b", "version": 2,
            "expires": "2099-01-01T00:00:00Z", "prevVersionDigest": {"sha256": _content_root(v1_pred)},
            "roles": {"root": {"keyIds": v1_pred["roles"]["root"]["keyIds"], "threshold": 2},
                      "outcomeExecutors": {"keyIds": ["kid-exec"], "threshold": 1}},
            "keys": keys,
            "nonClaims": ["names which keys hold which role, not that the holders are honest"]}


class TestOutcomeNakedV2PackIsNotTrusted(unittest.TestCase):
    """The appendix's Fund 2, exactly: a v2 pack PREDICATE never run through verify_trust_pack cannot confer
    executor-role trust just because it names the outcome signer's key."""

    def _fixtures(self):
        out_sk = generate_signer()
        out_pub = out_sk.public_key().public_bytes_raw()
        env = emit_outcome_receipt(_outcome_pred(), out_sk)
        v1_pred, v1_sks = _v1_genesis()
        v2_pred = _v2_predicate(out_pub, v1_pred)
        return env, out_pub, v1_pred, v1_sks, v2_pred

    def test_naked_v2_predicate_is_not_trusted(self):
        # COUNTER-PROBE (the appendix measured red at e37e872b: executor_role_trusted True, ok True,
        # safeForAutomation True). N43 closes it: no anchor -> not positive, with TRUST_PACK_NOT_ANCHORED.
        env, out_pub, _v1_pred, _v1_sks, v2_pred = self._fixtures()
        r = verify_outcome_receipt(env, out_pub, trust_pack=v2_pred)
        self.assertIs(r["executor_role_trusted"], False)
        self.assertIs(r["executor_key_bound"], True)        # the key IS bound; only the anchor is missing
        self.assertIs(r["ok"], False)
        self.assertIs(r["automation"]["safeForAutomation"], False)
        self.assertIn("TRUST_PACK_NOT_ANCHORED", r["automation"]["automationBlockers"])

    def test_v2_verified_via_rotation_then_forwarded_is_trusted(self):
        # CONTROL (the appendix's legitimate positive path): verify the v2 pack through verify_trust_pack under
        # the PINNED predecessor (the genesis old root vouches), then forward that verdict.
        env, out_pub, v1_pred, v1_sks, v2_pred = self._fixtures()
        env2 = sign_trust_pack(v2_pred, v1_sks)             # signed by the OLD (genesis) root keys
        gdigest = _content_root(v1_pred)
        prev_root = {kid: v1_pred["keys"][kid]["publicKey"] for kid in v1_pred["roles"]["root"]["keyIds"]}
        pack_verdict = verify_trust_pack(env2, strict=True, now=_NOW, prev_version=1,
                                         prev_version_digest=gdigest, prev_root_keys=prev_root,
                                         prev_root_threshold=2)
        self.assertIs(pack_verdict["rotation_authorized"], True)
        self.assertIs(pack_verdict["pinned"], True)
        self.assertIs(pack_verdict["ok"], True)
        # the relying party forwards the verified+pinned verdict to the outcome surface.
        # N45: OLD positive anchor was a bare trust_pack_pinned=True; NEW anchor adds trust_pack_pinned_digest
        # = sha256(JCS(v2_pred)). Reason: a bare pinned=True no longer binds the predicate's content at outcome.
        r = verify_outcome_receipt(env, out_pub, trust_pack=v2_pred, trust_pack_pinned=True,
                                   trust_pack_pinned_digest=_n45_digest(v2_pred))
        self.assertIs(r["executor_role_trusted"], True)
        self.assertIs(r["executor_key_bound"], True)
        self.assertIs(r["ok"], True)
        self.assertIs(r["automation"]["safeForAutomation"], True)


if __name__ == "__main__":
    unittest.main()
