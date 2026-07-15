"""VerificationBudget — Finding 15b (2026-07 verify-layer hardening).

Unit tests of the pure budget primitive, plus integration tests proving the two concretely-identified
unguarded DoS paths (trust_pack keys/keyIds counts, renewal ATS chain length) are now capped, and that the
cheap input_bytes cap is wired into every DSSE verify_* entry point without affecting a legitimate payload."""
from __future__ import annotations

import base64
import dataclasses
import unittest

from proofbundle.budget import DEFAULT_BUDGET, BudgetExceeded, VerificationBudget
from proofbundle.emit import generate_signer
from proofbundle.errors import ProofBundleError


class TestVerificationBudgetUnit(unittest.TestCase):
    def test_within_true_at_and_under_limit(self):
        b = VerificationBudget(witnesses=10)
        self.assertTrue(b.within("witnesses", 10))
        self.assertTrue(b.within("witnesses", 0))
        self.assertFalse(b.within("witnesses", 11))

    def test_check_raises_over_limit_not_at_limit(self):
        b = VerificationBudget(witnesses=10)
        b.check("witnesses", 10)          # must not raise (at the limit is fine)
        with self.assertRaises(BudgetExceeded):
            b.check("witnesses", 11)

    def test_budget_exceeded_is_a_proofbundle_error(self):
        # every existing `except (ProofBundleError, ...)` call site (CLI commands, fuzz sweeps) must
        # already catch this — no new uncaught exception type introduced.
        self.assertTrue(issubclass(BudgetExceeded, ProofBundleError))
        try:
            VerificationBudget(witnesses=1).check("witnesses", 2)
        except ProofBundleError as exc:
            self.assertIsInstance(exc, BudgetExceeded)
            self.assertEqual(exc.dimension, "witnesses")
            self.assertEqual(exc.got, 2)
            self.assertEqual(exc.limit, 1)
        else:
            self.fail("check() did not raise")

    def test_default_budget_is_generous(self):
        # sanity: the shipped defaults comfortably exceed any receipt/pack this repo's own examples use.
        self.assertGreater(DEFAULT_BUDGET.input_bytes, 1_000_000)
        self.assertGreaterEqual(DEFAULT_BUDGET.merkle_path, 256)   # matches anchors_chia._MAX_LAYERS
        self.assertGreaterEqual(DEFAULT_BUDGET.disclosures, 256)   # matches sdjwt._MAX_DISCLOSURES

    def test_frozen_dataclass_immutable(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            DEFAULT_BUDGET.witnesses = 1  # type: ignore[misc]


def _pub(sk) -> str:
    return base64.b64encode(sk.public_key().public_bytes_raw()).decode("ascii")


class TestBudgetLimitsUntrustedCollections(unittest.TestCase):
    """`budget_limits_untrusted_collections` (prompt-mandated test name): the two concretely-named
    "gefährdete Pfade" (renewal ATS chain length, trust_pack keys count) are capped, bidirectionally (a
    legitimate small collection is unaffected; an over-budget one is refused)."""

    def test_trust_pack_keys_count_capped(self):
        from proofbundle.trust_pack import validate_trust_pack_predicate
        over = DEFAULT_BUDGET.witnesses + 1
        keys = {f"k-{i}": {"publicKey": _pub(generate_signer())} for i in range(over)}
        pred = {
            "schemaVersion": "0.1.0", "trustPackId": "t", "version": 1,
            "expires": "2099-01-01T00:00:00Z", "prevVersionDigest": None,
            "roles": {"root": {"keyIds": [f"k-{i}" for i in range(2)], "threshold": 1}},
            "keys": keys, "nonClaims": ["x"],
        }
        errs = validate_trust_pack_predicate(pred)
        self.assertTrue(any("budget.witnesses" in e for e in errs), errs)

    def test_trust_pack_keys_count_within_budget_unaffected(self):
        from proofbundle.trust_pack import validate_trust_pack_predicate
        keys = {f"k-{i}": {"publicKey": _pub(generate_signer())} for i in range(3)}
        pred = {
            "schemaVersion": "0.1.0", "trustPackId": "t", "version": 1,
            "expires": "2099-01-01T00:00:00Z", "prevVersionDigest": None,
            "roles": {"root": {"keyIds": list(keys), "threshold": 1}},
            "keys": keys, "nonClaims": ["x"],
        }
        errs = validate_trust_pack_predicate(pred)
        self.assertFalse(any("budget.witnesses" in e for e in errs), errs)

    def test_trust_pack_role_keyids_count_capped(self):
        from proofbundle.trust_pack import validate_trust_pack_predicate
        over = DEFAULT_BUDGET.witnesses + 1
        # keys map itself stays small (isolates the ROLE keyIds cap from the top-level keys-map cap); the
        # role references key ids that need not all exist in `keys` for THIS specific check to fire first.
        keys = {"k-0": {"publicKey": _pub(generate_signer())}}
        pred = {
            "schemaVersion": "0.1.0", "trustPackId": "t", "version": 1,
            "expires": "2099-01-01T00:00:00Z", "prevVersionDigest": None,
            "roles": {"root": {"keyIds": [f"k-{i}" for i in range(over)], "threshold": 1}},
            "keys": keys, "nonClaims": ["x"],
        }
        errs = validate_trust_pack_predicate(pred)
        self.assertTrue(any("budget.witnesses" in e for e in errs), errs)

    def test_renewal_ats_chain_length_capped(self):
        from proofbundle.renewal import ArchiveTimeStamp
        from proofbundle.renewal import verify_sequence as _verify_sequence
        over = DEFAULT_BUDGET.renewal_ats_chain + 1
        # a synthetic (not necessarily chain-consistent) sequence — the budget check runs BEFORE the
        # covering-consistency walk, so this fires purely on count.
        chain = [ArchiveTimeStamp("sha256", "a" * 64, i) for i in range(over)]
        res = _verify_sequence([chain], ["a" * 64], allow_unauthenticated_anchor=True)
        self.assertFalse(res.ok)
        self.assertTrue(any("renewal:budget" in c.name and "budget.renewal_ats_chain" in c.detail
                            for c in res.checks), [str(c) for c in res.checks])

    def test_renewal_ats_chain_length_within_budget_unaffected(self):
        from proofbundle.renewal import build_initial_sequence
        from proofbundle.renewal import verify_sequence as _verify_sequence
        seq = build_initial_sequence(["a" * 64], hash_alg="sha256", time=1000)
        res = _verify_sequence(seq, ["a" * 64], allow_unauthenticated_anchor=True)
        self.assertTrue(res.ok, [str(c) for c in res.checks if not c.ok])
        self.assertFalse(any(c.name == "renewal:budget" for c in res.checks))


class TestInputBytesBudgetEnforced(unittest.TestCase):
    """The cheap, universally-safe input_bytes cap wired into every DSSE verify_* entry point
    (decision/outcome/trust_pack/verification_summary/run_ledger): a normal payload is completely
    unaffected; an absurdly oversized one is refused before parsing, as a typed ProofBundleError."""

    def test_decision_verify_raises_budget_exceeded_over_cap(self):
        import json
        from pathlib import Path

        from proofbundle.decision import emit_decision_receipt, verify_decision_receipt
        pred = json.loads((Path(__file__).resolve().parent.parent / "examples" /
                           "decision_receipt_deny.json").read_text())
        s = generate_signer()
        pub = s.public_key().public_bytes_raw()
        env = emit_decision_receipt(pred, s, strict=True)
        tiny = VerificationBudget(input_bytes=8)
        import unittest.mock as mock
        with mock.patch("proofbundle.budget.DEFAULT_BUDGET", tiny):
            with self.assertRaises(BudgetExceeded):
                verify_decision_receipt(env, pub, strict=True)
        # sanity: the SAME envelope verifies fine under the real (generous) default budget.
        r = verify_decision_receipt(env, pub, strict=True)
        self.assertTrue(r["ok"])

    def test_legitimate_receipts_never_hit_the_default_input_bytes_cap(self):
        import json
        from pathlib import Path

        from proofbundle.decision import emit_decision_receipt, verify_decision_receipt
        pred = json.loads((Path(__file__).resolve().parent.parent / "examples" /
                           "decision_receipt_deny.json").read_text())
        s = generate_signer()
        pub = s.public_key().public_bytes_raw()
        env = emit_decision_receipt(pred, s, strict=True)
        r = verify_decision_receipt(env, pub, strict=True)   # must not raise
        self.assertTrue(r["ok"])


class TestDsseSignaturesCapDoS(unittest.TestCase):
    """Crypto-review 2026-07-15 (C1/X1): the DSSE signatures list is the real DoS vector on decision/
    outcome/verification_summary/run_ledger verify (they funnel through dsse.verify_envelope). The cap must
    reject an attacker-scaled list BEFORE the O(n) verify loop, yet leave two-stage-rotation headroom."""

    def _env(self):
        from proofbundle import dsse
        s = generate_signer()
        pub = s.public_key().public_bytes_raw()
        env = dsse.sign_envelope(b'{"x":1}', s, payload_type="application/x.proofbundle-test")
        return dsse, env, pub

    def test_verify_envelope_rejects_oversized_signatures_list(self):
        dsse, env, pub = self._env()
        # one real sig + enough junk entries to exceed the cap: without the guard this drives O(n) ed25519
        # verifies (none match, no early exit) = seconds of CPU; the input_bytes cap bounds only the payload.
        env["signatures"] = env["signatures"] + [{"sig": "AA=="} for _ in range(DEFAULT_BUDGET.signatures)]
        with self.assertRaises(BudgetExceeded):
            dsse.verify_envelope(env, pub)

    def test_verify_envelope_accepts_at_signatures_limit(self):
        dsse, env, pub = self._env()
        env["signatures"] = env["signatures"] + [{"sig": "AA=="} for _ in range(DEFAULT_BUDGET.signatures - 1)]
        self.assertEqual(len(env["signatures"]), DEFAULT_BUDGET.signatures)
        self.assertTrue(dsse.verify_envelope(env, pub))   # at the limit is fine; real sig still verifies

    def test_signatures_cap_has_two_stage_rotation_headroom(self):
        # X1: trust_pack's rotation reuses ONE signatures list for BOTH new-root threshold AND old-root
        # vouch, so a consortium at the per-role witnesses ceiling needs up to 2x that many in one envelope.
        self.assertGreaterEqual(DEFAULT_BUDGET.signatures, 2 * DEFAULT_BUDGET.witnesses)


if __name__ == "__main__":
    unittest.main()
