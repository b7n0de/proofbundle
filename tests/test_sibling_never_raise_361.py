"""3.6.1 RE-GATE round 2 — the never-raise contract holds on the SIBLING DSSE verify_* surfaces too.

Round 1 closed the raw-BudgetExceeded / type-confusion hole on decision.verify_decision_receipt +
outcome.verify_outcome_receipt. The Berkeley RE-GATE then found the SAME class STILL LIVE on the sibling
dict-returning verify surfaces (run_ledger / relation_statement / verification_summary / trust_pack), plus
a crypto-boundary regression (a bytearray public key crashed ALL five DSSE entrypoints from the shared
signature primitive) and a status-snapshot type-confusion. This guard pins every one of those fixes:

* REGATE-BUDGET-01 / RE-TCE-01 verify_relation_statement, REGATE-BUDGET-02 verify_run_ledger, the
  verification_summary sibling, MJSON-TP-01 verify_trust_pack: a WIDE (json_nodes over cap) / OVERSIZED
  (input_bytes over the 8 MiB cap) / over-signatures untrusted envelope yields a fail-closed verdict, never
  a raw BudgetExceeded (a ProofBundleError sibling of BundleFormatError the old narrow except let escape).
* CB-01: a bytearray public key VERIFIES correctly (not a raw TypeError, not a wrong False) through the
  shared signature.verify_ed25519 primitive, so decision/outcome never-raise is not defeated by key type.
* RE-TCE-06: verify_status_snapshot returns a fail-closed verdict for a non-str token, not AttributeError.
* PB06-RELSTMT-CANON-FAILOPEN: with the RFC-8785 canonicalizer unavailable, relation-statement verify fails
  CLOSED regardless of strict (rfc8785 is a declared core dependency), never a silent fail-open ok=True.
"""
import json
import unittest

from proofbundle import dsse
from proofbundle.emit import generate_signer
from proofbundle.relation_statement import verify_relation_statement
from proofbundle.run_ledger import verify_run_ledger
from proofbundle.trust_pack import verify_trust_pack
from proofbundle.verification_summary import verify_verification_summary

_INTOTO = "application/vnd.in-toto+json"


def _keys():
    s = generate_signer()
    return s, s.public_key().public_bytes_raw()


def _signed(signer, payload: bytes) -> dict:
    return dsse.sign_envelope(payload, signer, payload_type=_INTOTO)


_WIDE = json.dumps([0] * 200_005).encode("utf-8")        # json_nodes over the 200k cap
_OVERSIZED = json.dumps([0] * 3_000_000).encode("utf-8")  # ~12 MB, over the 8 MiB byte cap


class SiblingBudgetNeverRaise(unittest.TestCase):
    def test_public_key_dsse_siblings_never_raise_on_budget_overrun(self):
        s, pub = _keys()
        for verify in (verify_relation_statement, verify_run_ledger, verify_verification_summary):
            for payload in (_WIDE, _OVERSIZED):
                r = verify(_signed(s, payload), pub)   # must NOT raise
                self.assertIsInstance(r, dict)
                self.assertIsNot(r["ok"], True)
                self.assertIs(r["structure_ok"], False)

    def test_trust_pack_never_raises_on_budget_or_bad_signatures(self):
        s, _ = _keys()
        for payload in (_WIDE, _OVERSIZED):
            r = verify_trust_pack(_signed(s, payload))
            self.assertIsNot(r["ok"], True)
        # oversized signatures array (> 512 cap)
        env = _signed(s, json.dumps({"x": 1}).encode("utf-8"))
        env_big = dict(env)
        env_big["signatures"] = [{"sig": "AA=="} for _ in range(600)]
        self.assertIsNot(verify_trust_pack(env_big)["ok"], True)
        # non-list signatures — a fail-closed verdict, not a raw BundleFormatError
        for bogus in (True, 5, {"a": 1}, "x"):
            env_b = dict(env)
            env_b["signatures"] = bogus
            r = verify_trust_pack(env_b)
            self.assertIs(r["ok"], False)
            self.assertIs(r["structure_ok"], False)


class CryptoBoundaryBytearrayKey(unittest.TestCase):
    def test_verify_ed25519_accepts_bytearray_key_and_sig(self):
        # CB-01: a bytearray key/sig must VERIFY (bytes coercion), never a raw TypeError, never a wrong False.
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from proofbundle.signature import verify_ed25519
        sk = Ed25519PrivateKey.generate()
        vk = sk.public_key().public_bytes_raw()
        msg = b"proofbundle CB-01"
        sig = sk.sign(msg)
        self.assertTrue(verify_ed25519(bytearray(vk), bytearray(sig), msg))
        self.assertFalse(verify_ed25519(bytearray(b"\x00" * 32), bytearray(sig), msg))

    def test_decision_verify_bytearray_key_verifies_not_crashes(self):
        from pathlib import Path

        from proofbundle.decision import emit_decision_receipt, verify_decision_receipt
        s, pub = _keys()
        pred = json.loads((Path(__file__).resolve().parent.parent / "examples" /
                           "decision_receipt_deny.json").read_text())
        env = emit_decision_receipt(pred, s, strict=True)
        r = verify_decision_receipt(env, bytearray(pub))   # must not raise; a valid key verifies
        self.assertIs(r["ok"], True)
        self.assertIs(r["crypto_ok"], True)


class StatusSnapshotTypeConfusion(unittest.TestCase):
    def test_non_str_token_is_failclosed_verdict(self):
        from proofbundle.statuslist import verify_status_snapshot
        s, pub = _keys()
        for token in (123, None, [1, 2], {"a": 1}, b"bytes"):
            r = verify_status_snapshot(token, expected_uri="x", index=0, issuer_pubkey=pub)
            self.assertIs(r["ok"], False)


class BreadthSweepTypeConfusion(unittest.TestCase):
    """RE-GATE breadth sweep: the remaining dict-returning verify surfaces return a verdict, not a raw
    exception, for a type-confused primary argument (same class as RE-TCE-06)."""

    def test_verify_tlog_proof_non_str_text_is_verdict(self):
        from proofbundle import verify_tlog_proof
        for bad in (123, None, [1], {}):
            r = verify_tlog_proof(bad, b"leaf", "vkey")   # must NOT raise
            self.assertIs(r["ok"], False)
        # a bad threshold is also a verdict, not a raise
        self.assertIs(verify_tlog_proof("x\n\nsig", b"leaf", "vkey", threshold=-1)["ok"], False)

    def test_verify_key_binding_non_str_compact_is_verdict(self):
        from proofbundle import verify_key_binding
        for bad in (123, None, [1], {}):
            r = verify_key_binding(bad)   # must NOT raise
            self.assertIs(r["ok"], False)
            self.assertIs(r["present"], False)

    def test_verify_sd_jwt_non_str_compact_is_verdict(self):
        from proofbundle.sdjwt import verify_sd_jwt
        for bad in (123, None, [1], {}):
            r = verify_sd_jwt(bad)   # must NOT raise
            self.assertIsInstance(r, dict)
            self.assertIs(r["sig_ok"], False)
            self.assertIs(r["structure_ok"], False)

    def test_verify_commitment_non_str_identifier_is_false(self):
        from proofbundle.evalclaim import verify_commitment
        for bad in (123, None, [1], {}):
            self.assertIs(verify_commitment(bad, b"salt", "commit"), False)   # must NOT raise


class MerklePathBudgetDirectDict(unittest.TestCase):
    """PB-2026-0718-16 (RT-09): the merkle_path step budget is enforced in the verification core, effective
    on the direct dict path where the input_bytes byte-proxy never runs — an over-budget or non-list proof
    is fail-closed, never an unbounded per-step hash loop or a raw comparison crash."""

    def test_over_budget_proof_is_failclosed(self):
        from proofbundle.budget import DEFAULT_BUDGET
        from proofbundle.merkle import verify_consistency, verify_inclusion
        cap = DEFAULT_BUDGET.merkle_path
        big = [b"\x00" * 32] * (cap + 1)
        self.assertFalse(verify_inclusion(b"leaf", 0, 1, big, b"\x00" * 32))
        self.assertFalse(verify_inclusion(b"leaf", 0, 1, [b"\x00" * 32] * 65536, b"\x00" * 32))
        self.assertFalse(verify_consistency(1, 2, big, b"\x00" * 32, b"\x00" * 32))

    def test_type_confused_proof_or_sizes_are_failclosed(self):
        from proofbundle.merkle import verify_consistency, verify_inclusion
        self.assertFalse(verify_inclusion(b"leaf", 0, 1, "notlist", b"\x00" * 32))
        self.assertFalse(verify_consistency("x", None, [], b"\x00" * 32, b"\x00" * 32))

    def test_legit_small_proof_still_verifies(self):
        import hashlib

        from proofbundle.merkle import leaf_hash, verify_inclusion
        h1 = leaf_hash(b"b")
        root = hashlib.sha256(b"\x01" + leaf_hash(b"a") + h1).digest()
        self.assertTrue(verify_inclusion(b"a", 0, 2, [h1], root))


class RelationCanonicalityFailClosed(unittest.TestCase):
    def test_rfc8785_unavailable_fails_closed_regardless_of_strict(self):
        # PB06-RELSTMT-CANON-FAILOPEN: without the canonicalizer, verify must NOT pass (ok=True) in default
        # mode — a broken install is fail-closed, never a lenient pass over unverifiable canonicality.
        import proofbundle.relation_statement as rsm
        s, pub = _keys()
        env = _signed(s, json.dumps({"predicateType": "x"}).encode("utf-8"))
        orig = rsm._rfc8785_available
        rsm._rfc8785_available = lambda: False
        try:
            for strict in (False, True):
                r = verify_relation_statement(env, pub, strict=strict)
                self.assertIsNot(r["ok"], True)
                self.assertIs(r["structure_ok"], False)
        finally:
            rsm._rfc8785_available = orig


if __name__ == "__main__":
    unittest.main()
