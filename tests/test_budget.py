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
from proofbundle.errors import BundleFormatError, ProofBundleError


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

    def test_decision_verify_over_cap_is_failclosed_verdict_not_raise(self):
        # PB-2026-0718-11 RE-GATE never-raise: an over-budget payload yields a fail-closed VERDICT
        # (structure_ok=False, ok!=True), NEVER a raw uncaught BudgetExceeded — that would be an
        # uncaught-exception DoS on a verify surface whose contract is never-raise. The budget guard still
        # fires (the payload is refused), it just surfaces as a verdict + errors[] entry, not an exception.
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
            r = verify_decision_receipt(env, pub, strict=True)   # must RETURN a verdict, never raise
        self.assertIs(r["structure_ok"], False)
        self.assertIsNot(r["ok"], True)
        self.assertTrue(any("budget" in e.lower() for e in r["errors"]), r["errors"])
        # sanity: the SAME envelope verifies fine under the real (generous) default budget.
        r2 = verify_decision_receipt(env, pub, strict=True)
        self.assertTrue(r2["ok"])

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
        # Berkeley re-gate round 6: verify_envelope is a public verify surface whose docstring signals only
        # BundleFormatError; the over-cap list now maps the internal BudgetExceeded to it (still a
        # ProofBundleError, so in-repo `except ProofBundleError` callers are unaffected — see the note at
        # dsse.py:108) rather than leaking the raw sibling to a direct third-party caller.
        with self.assertRaises(BundleFormatError):
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

    def test_verify_envelope_rejects_oversized_base64_payload_before_decode(self):
        # Refuter residual (crypto-review, 2026-07-15): _payload_bytes base64-decodes envelope.payload as its
        # first op — unbounded before the entry-point's decoded-bytes cap. Cap the raw base64 string first.
        import unittest.mock as mock

        from proofbundle import dsse
        s = generate_signer()
        pub = s.public_key().public_bytes_raw()
        env = dsse.sign_envelope(b'{"x": 1}', s, payload_type="application/x.proofbundle-test")
        tiny = VerificationBudget(input_bytes=4)   # the base64 payload is longer than 4 chars
        with mock.patch("proofbundle.budget.DEFAULT_BUDGET", tiny):
            # Berkeley re-gate round 6: mapped to the documented BundleFormatError (a ProofBundleError) instead
            # of leaking the raw BudgetExceeded sibling from this public verify/load surface.
            with self.assertRaises(BundleFormatError):
                dsse.verify_envelope(env, pub)


class TestLoadsStrictResourceCaps(unittest.TestCase):
    """Crypto-review 2026-07-15 (C1.1 + json_nodes): loads_strict is the ONE parse chokepoint, so the raw
    input_bytes cap (bounds parse-time DoS the downstream sig cap cannot reach) and the previously-dead
    json_nodes cap live here. Both fail closed with BudgetExceeded."""

    def test_rejects_oversized_raw_input_before_parse(self):
        from proofbundle._strict_json import loads_strict
        tiny = VerificationBudget(input_bytes=16)
        with self.assertRaises(BudgetExceeded):
            loads_strict('{"x": "' + "a" * 200 + '"}', budget=tiny)

    def test_rejects_excessive_node_count(self):
        from proofbundle._strict_json import loads_strict
        tiny = VerificationBudget(json_nodes=10)   # input_bytes stays generous; only node count is tight
        big = "[" + ",".join("1" for _ in range(50)) + "]"   # 50 list items > 10 nodes
        with self.assertRaises(BudgetExceeded):
            loads_strict(big, budget=tiny)

    def test_accepts_normal_input_under_caps(self):
        from proofbundle._strict_json import loads_strict
        self.assertEqual(loads_strict('{"a": 1, "b": [1, 2, 3]}'), {"a": 1, "b": [1, 2, 3]})

    def test_json_nodes_default_is_wired_not_dead(self):
        # regression: json_nodes was a documented budget field never referenced by any code.
        import proofbundle._strict_json as sj
        big = "[" + ",".join("0" for _ in range(DEFAULT_BUDGET.json_nodes + 5)) + "]"
        with self.assertRaises(BudgetExceeded):
            sj.loads_strict(big)


if __name__ == "__main__":
    unittest.main()
