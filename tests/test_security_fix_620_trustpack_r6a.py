"""Addendum R6a-3 (`KRAXO-CLOUD-R6A-SIEBEN-P1-VOR-CRIT-JSON-01`, Z309 / 6.2.0).

Reviewer round 6a, one P1 on the trust-pack head, reproduced by Cowork from the delivered probe
(probe_r6a_3.py):

R6a-3 — the relying-party ANCHOR ``expected_root_keys`` was matched against the pack's declared root by the
classical ``publicKey`` BYTES alone (``_pinned_root_material`` / ``_declared_root_material`` read only
``publicKey``). So a pin that DECLARES a hybrid key — ``{"publicKey": K, "alg": "hybrid-ed25519-mldsa65",
"publicKeyPq": <1952 bytes>}`` — was satisfied by a pack whose root key is Ed25519-only (no ``alg``, no
``publicKeyPq``, a signature carrying only the Ed25519 ``sig`` leg and no ``sigPq``): a downgrade that
docs/predicates/trust-pack.md forbids ("a signature carrying only the Ed25519 `sig` leg does not satisfy a
policy-declared hybrid key — no downgrade"). The fix compares the FULL normalized key identity (algorithm +
both legs); a hybrid pin is matched only by a declared hybrid key with the same classical AND post-quantum
leg, an unknown algorithm or an incomplete hybrid pin (no ``publicKeyPq``) is rejected closed, and the anchor
of ``verify_outcome_receipt`` (Anchor B) inherits the same binding because it goes through
``verify_trust_pack`` unchanged (no new anchor path).

RED at the trust-pack head ``dee2383292081df61066a696086a2b8089b73779`` (the hybrid pin, and an incomplete /
unknown-alg pin, keep ``pinned`` True and ``executor_role_trusted`` True); GREEN after. The matching-Ed25519
and matching-hybrid positive controls stay positive; the foreign-key counter-control stays refused.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
for _p in (str(REPO / "src"), str(REPO / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from proofbundle.emit import generate_signer  # noqa: E402
from proofbundle.outcome import emit_outcome_receipt, verify_outcome_receipt  # noqa: E402
from proofbundle.trust_pack import sign_trust_pack, trust_pack_is_pinned, verify_trust_pack  # noqa: E402
from test_security_fix_620_trustpack_n45_anchor import _outcome_pred  # noqa: E402

_NOW = datetime(2026, 7, 14, 12, 0, 0, tzinfo=timezone.utc)
_HYB = "hybrid-ed25519-mldsa65"
# 1952 bytes (the FIPS-204 ML-DSA-65 public-key length), deterministic, NOT a real ML-DSA key — only its bytes
# matter to an identity pin, which never verifies a PQ signature.
_PQ = hashlib.shake_256(b"r6a3/pq-leg").digest(1952)


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _pub(sk) -> bytes:
    return sk.public_key().public_bytes_raw()


def _ed25519_pack(root_sk, exec_sk):
    """A valid Ed25519-only genesis pack: keys[root-K] has NO alg (defaults ed25519) and NO publicKeyPq; it is
    signed with the Ed25519 leg only (no sigPq). Returns (predicate, signed_envelope)."""
    pred = {"schemaVersion": "0.1.0", "trustPackId": "tp-r6a3", "version": 1,
            "expires": "2099-01-01T00:00:00Z", "prevVersionDigest": None,
            "roles": {"root": {"keyIds": ["root-K"], "threshold": 1},
                      "outcomeExecutors": {"keyIds": ["kid-exec"], "threshold": 1}},
            "keys": {"root-K": {"publicKey": _b64(_pub(root_sk))},
                     "kid-exec": {"publicKey": _b64(_pub(exec_sk))}},
            "nonClaims": ["names which keys hold which role, not that the holders are honest"]}
    return pred, sign_trust_pack(pred, {"root-K": root_sk})


def _tp_pinned(env, pin):
    return verify_trust_pack(env, now=_NOW, expected_root_keys=pin)


class R6a3HybridPinNeverAuthorizesEd25519Only(unittest.TestCase):
    """A relying party that pins a HYBRID root key must not have that pin satisfied by an Ed25519-only pack."""

    def setUp(self):
        self.root = generate_signer()
        self.out_sk = generate_signer()
        self.pred, self.env = _ed25519_pack(self.root, self.out_sk)
        self.out_env = emit_outcome_receipt(_outcome_pred(), self.out_sk)
        self.pin_hybrid = {"root-K": {"publicKey": _b64(_pub(self.root)), "alg": _HYB, "publicKeyPq": _b64(_PQ)}}
        self.pin_ed25519 = {"root-K": {"publicKey": _b64(_pub(self.root))}}
        self.pin_ed25519_alg = {"root-K": {"publicKey": _b64(_pub(self.root)), "alg": "ed25519"}}

    def _sanity_pack_is_ed25519_only(self):
        signed = json.loads(base64.b64decode(self.env["payload"]))["predicate"]
        self.assertNotIn("alg", signed["keys"]["root-K"])
        self.assertNotIn("publicKeyPq", signed["keys"]["root-K"])
        self.assertFalse(any("sigPq" in s for s in self.env["signatures"]),
                         "the pack is signed with the Ed25519 leg only (no sigPq)")

    # ── the finding: hybrid pin against an Ed25519-only pack ──────────────────────────────────────────────
    def test_hybrid_pin_is_refused_by_trust_pack_is_pinned(self):
        self._sanity_pack_is_ed25519_only()
        self.assertIsNot(trust_pack_is_pinned(self.pred, expected_root_keys=self.pin_hybrid), True,
                         "a hybrid pin must NOT be satisfied by an Ed25519-only declared root (no downgrade)")

    def test_hybrid_pin_is_refused_by_verify_trust_pack(self):
        r = _tp_pinned(self.env, self.pin_hybrid)
        self.assertIsNot(r["pinned"], True)
        self.assertIsNot(r["automation"]["safeForAutomation"], True)

    def test_hybrid_pin_is_refused_at_the_outcome_anchor_b(self):
        # Anchor B: verify_outcome_receipt forwards the pin through verify_trust_pack, so it inherits the fix.
        r = verify_outcome_receipt(self.out_env, _pub(self.out_sk), trust_pack=self.pred,
                                   trust_pack_envelope=self.env, trust_pack_expected_root_keys=self.pin_hybrid)
        self.assertIsNot(r["executor_role_trusted"], True)
        self.assertIsNot(r["ok"], True)
        self.assertIn("TRUST_PACK_NOT_ANCHORED", r["automation"]["automationBlockers"])

    # ── positive controls: a matching Ed25519 pin still authorizes ───────────────────────────────────────
    def test_matching_ed25519_pin_authorizes(self):
        for name, pin in (("no alg", self.pin_ed25519), ("alg ed25519", self.pin_ed25519_alg)):
            with self.subTest(pin=name):
                self.assertIs(trust_pack_is_pinned(self.pred, expected_root_keys=pin), True)
                r = _tp_pinned(self.env, pin)
                self.assertIs(r["pinned"], True)
                self.assertIs(r["automation"]["safeForAutomation"], True)

    def test_matching_ed25519_pin_authorizes_at_the_outcome_anchor_b(self):
        r = verify_outcome_receipt(self.out_env, _pub(self.out_sk), trust_pack=self.pred,
                                   trust_pack_envelope=self.env, trust_pack_expected_root_keys=self.pin_ed25519)
        self.assertIs(r["executor_role_trusted"], True)
        self.assertIs(r["ok"], True)

    # ── counter-control: a foreign classical key stays refused (anchor is not trivially positive) ────────
    def test_foreign_classical_key_is_refused(self):
        pin_foreign = {"root-K": {"publicKey": _b64(_pub(generate_signer()))}}
        self.assertIsNot(trust_pack_is_pinned(self.pred, expected_root_keys=pin_foreign), True)
        r = verify_outcome_receipt(self.out_env, _pub(self.out_sk), trust_pack=self.pred,
                                   trust_pack_envelope=self.env, trust_pack_expected_root_keys=pin_foreign)
        self.assertIsNot(r["executor_role_trusted"], True)
        self.assertIsNot(r["ok"], True)


class R6a3FullIdentityControlsAndClosedRejections(unittest.TestCase):
    """The match is on the full normalized identity: a matching hybrid pin DOES authorize a declared hybrid
    root (the fix is a narrowing, not a blanket hybrid refusal), while an unknown algorithm or an incomplete
    hybrid pin is rejected closed."""

    def setUp(self):
        self.root = generate_signer()
        # A predicate that DECLARES a hybrid root key (classical K + the same 1952-byte PQ leg). It need not be
        # signed: trust_pack_is_pinned matches the pin against the declared root identity, not the signature.
        self.pred_hybrid = {"schemaVersion": "0.1.0", "trustPackId": "tp-r6a3-h", "version": 1,
                            "expires": "2099-01-01T00:00:00Z", "prevVersionDigest": None,
                            "roles": {"root": {"keyIds": ["root-K"], "threshold": 1}},
                            "keys": {"root-K": {"publicKey": _b64(_pub(self.root)), "alg": _HYB,
                                                "publicKeyPq": _b64(_PQ)}},
                            "nonClaims": ["declares a hybrid root key"]}

    def test_matching_hybrid_pin_authorizes_a_declared_hybrid_root(self):
        pin = {"root-K": {"publicKey": _b64(_pub(self.root)), "alg": _HYB, "publicKeyPq": _b64(_PQ)}}
        self.assertIs(trust_pack_is_pinned(self.pred_hybrid, expected_root_keys=pin), True,
                      "a hybrid pin matching the declared hybrid identity (both legs) still authorizes")

    def test_ed25519_pin_does_not_authorize_a_declared_hybrid_root(self):
        # The reverse downgrade: pinning only the classical leg must NOT anchor a hybrid-declared root.
        pin = {"root-K": {"publicKey": _b64(_pub(self.root))}}
        self.assertIsNot(trust_pack_is_pinned(self.pred_hybrid, expected_root_keys=pin), True)

    def test_hybrid_pin_with_a_different_pq_leg_does_not_authorize(self):
        other_pq = hashlib.shake_256(b"r6a3/pq-leg-OTHER").digest(1952)
        pin = {"root-K": {"publicKey": _b64(_pub(self.root)), "alg": _HYB, "publicKeyPq": _b64(other_pq)}}
        self.assertIsNot(trust_pack_is_pinned(self.pred_hybrid, expected_root_keys=pin), True)

    def test_incomplete_hybrid_pin_without_pq_leg_is_rejected_closed(self):
        # An Ed25519-only pack declared normally; a pin that claims hybrid but omits publicKeyPq is incomplete
        # and must match nothing (at the old head it reduced to the classical leg and matched).
        exec_sk = generate_signer()
        pred, _env = _ed25519_pack(self.root, exec_sk)
        pin = {"root-K": {"publicKey": _b64(_pub(self.root)), "alg": _HYB}}   # no publicKeyPq
        self.assertIsNot(trust_pack_is_pinned(pred, expected_root_keys=pin), True)

    def test_unknown_alg_pin_is_rejected_closed(self):
        exec_sk = generate_signer()
        pred, _env = _ed25519_pack(self.root, exec_sk)
        pin = {"root-K": {"publicKey": _b64(_pub(self.root)), "alg": "rot13-not-an-alg"}}
        self.assertIsNot(trust_pack_is_pinned(pred, expected_root_keys=pin), True)


if __name__ == "__main__":
    unittest.main()
