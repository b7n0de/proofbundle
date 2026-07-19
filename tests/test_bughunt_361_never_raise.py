"""Regression tests for the 3.6.2 bug-hunt never-raise / DoS follow-ups.

The 3.6.1 never-raise hardening wrapped some public entrypoints but left siblings unwrapped. Each of
these surfaces must map malformed / hostile untrusted input to a typed fail-closed result (a dict
verdict, or a typed BundleFormatError), never a RAW exception (crash / DoS for a direct integrator).
"""
import io
import unittest

from proofbundle.errors import BundleFormatError


class TlogProofNeverRaisesOnMalformedCheckpoint(unittest.TestCase):
    def test_malformed_embedded_checkpoint_is_fail_closed_dict(self):
        from proofbundle import checkpoint as cp
        from proofbundle.tlogproof import verify_tlog_proof
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        sk = Ed25519PrivateKey.generate()
        vk = cp.vkey("log", sk.public_key().public_bytes_raw())
        good_root = "A" * 43 + "="  # decodes to 32 bytes -> passes parse, non-base64 root inside note
        text = ("c2sp.org/tlog-proof@v1\nindex 0\n" + good_root
                + "\n\norigin\n5\n!!!not-base64!!!\n\n— log AAAA\n")
        r = verify_tlog_proof(text, b"payload", vk)   # must NOT raise
        self.assertIsInstance(r, dict)
        self.assertFalse(r["ok"])


class AuditChallengeRaisesTypedOnHostileInput(unittest.TestCase):
    def _root(self):
        import hashlib
        return hashlib.sha256(b"x").digest()

    def test_non_base64_root_is_typed(self):
        from proofbundle.persample import audit_challenge
        with self.assertRaises(BundleFormatError):
            audit_challenge("!!!not-base64!!!", 1000, 5)

    def test_oversized_n_is_typed_not_overflow(self):
        from proofbundle.persample import audit_challenge
        with self.assertRaises(BundleFormatError):
            audit_challenge(self._root(), 10 ** 30, 5)   # n >= 2**64 would overflow n.to_bytes(8)

    def test_non_bytes_nonce_is_typed(self):
        from proofbundle.persample import audit_challenge
        with self.assertRaises(BundleFormatError):
            audit_challenge(self._root(), 1000, 5, nonce="not-bytes")

    def test_valid_inputs_still_work(self):
        import base64
        from proofbundle.persample import audit_challenge
        idx = audit_challenge(base64.b64encode(self._root()).decode(), n=1000, k=5, nonce=b"audit")
        self.assertEqual(len(idx), 5)
        self.assertEqual(len(set(idx)), 5)


class CliBoundedReadCapsHugeInput(unittest.TestCase):
    def test_over_cap_read_is_typed(self):
        from proofbundle.budget import DEFAULT_BUDGET
        from proofbundle.cli import _read_capped
        cap = DEFAULT_BUDGET.input_bytes

        class Huge:
            def read(self, n=-1):
                return "x" * (n if n and n > 0 else cap * 4)

        with self.assertRaises(BundleFormatError):
            _read_capped(Huge())

    def test_small_input_passes_through(self):
        from proofbundle.cli import _read_capped
        self.assertEqual(_read_capped(io.StringIO("{}")), "{}")

    def test_bytes_mode_cap(self):
        # Berkeley re-gate: the rb verify handles (verify-proof --payload-file, anchor inspect/upgrade)
        # use the bytes-mode cap
        from proofbundle.budget import DEFAULT_BUDGET
        from proofbundle.cli import _read_capped_bytes
        cap = DEFAULT_BUDGET.input_bytes

        class HugeB:
            def read(self, n=-1):
                return b"\x00" * (n if n and n > 0 else cap * 4)

        with self.assertRaises(BundleFormatError):
            _read_capped_bytes(HugeB())
        self.assertEqual(_read_capped_bytes(io.BytesIO(b"abc")), b"abc")


class PolicyLoadBoundedRead(unittest.TestCase):
    def test_oversized_policy_file_is_policy_error_not_oom(self):
        # Berkeley re-gate P1: load_policy bounded the read at input_bytes (policy lint --policy /dev/zero
        # would otherwise OOM before loads_strict's cap)
        import os
        import tempfile
        from proofbundle.budget import DEFAULT_BUDGET
        from proofbundle.policy import PolicyError, load_policy
        cap = DEFAULT_BUDGET.input_bytes
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write("{" + '"pad":' + "9" * (cap + 16) + "}")
            tmp = f.name
        try:
            with self.assertRaises(PolicyError):
                load_policy(tmp)
        finally:
            os.unlink(tmp)

    def test_wide_policy_under_byte_cap_is_policy_error_not_raw_budget_exceeded(self):
        # Berkeley re-gate round 2: a small (< byte cap) but node-heavy policy trips loads_strict's SIBLING
        # BudgetExceeded (a ProofBundleError that is NOT BundleFormatError) — the except must catch the BASE.
        import json
        import os
        import tempfile
        from proofbundle.policy import PolicyError, load_policy
        wide = {"schema": "proofbundle/trust-policy/v0.2", "policy_id": "x",
                "allowed_schema_versions": list(range(200_001))}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(wide, f)
            tmp = f.name
        try:
            with self.assertRaises(PolicyError):
                load_policy(tmp)
        finally:
            os.unlink(tmp)


class LibrarySurfaceBudgetSiblingIsFailClosed(unittest.TestCase):
    """Berkeley re-gate round 3 (repro-confirmed): several PUBLIC library verify surfaces funnel an embedded
    SD-JWT/claim payload through loads_strict, which raises a SIBLING BudgetExceeded (a ProofBundleError that
    is NOT BundleFormatError) on a node-heavy payload. An `except (BundleFormatError, ...)` that omits the
    BASE let a raw DoS exception escape. Each surface must now map it to its own fail-closed verdict."""

    def _node_heavy_compact(self, extra_top=None):
        import base64
        import json

        from proofbundle.budget import DEFAULT_BUDGET
        over = DEFAULT_BUDGET.json_nodes + 50
        payload = {"pad": list(range(over))}
        if extra_top:
            payload.update(extra_top)
        raw = json.dumps(payload).encode()
        assert len(raw) < DEFAULT_BUDGET.input_bytes, "byte-cap would fire first"
        b64 = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        return "hdr." + b64 + ".sig"

    def test_sd_jwt_hidden_count_is_none_not_raw_budget(self):
        from proofbundle.evalclaim import sd_jwt_hidden_count
        compact = self._node_heavy_compact({"_sd": []})
        self.assertIsNone(sd_jwt_hidden_count({"sd_jwt_vc": {"compact": compact}}))

    def test_check_binds_bundle_is_false_not_raw_budget(self):
        from proofbundle.sdjwt_issue import check_binds_bundle
        compact = self._node_heavy_compact()
        self.assertFalse(check_binds_bundle(compact, {"passed": True}, "root"))

    def test_present_with_key_binding_maps_oversized_to_valueerror(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from proofbundle.sdjwt_issue import present_with_key_binding
        compact = self._node_heavy_compact({"_sd_alg": "sha-256"}) + "~"
        with self.assertRaises(ValueError):
            present_with_key_binding(compact, Ed25519PrivateKey.generate(),
                                     aud="a", nonce="n", iat=1)

    def test_load_claim_text_maps_budget_to_evalclaim_error(self):
        # evalclaim.load_claim_text: a node-heavy claim must raise the documented EvalClaimError
        # (a ValueError), never a raw BudgetExceeded.
        import json

        from proofbundle.budget import DEFAULT_BUDGET
        from proofbundle.evalclaim import EvalClaimError, load_claim_text
        over = DEFAULT_BUDGET.json_nodes + 50
        text = json.dumps({"pad": list(range(over))})
        with self.assertRaises(EvalClaimError):
            load_claim_text(text)


class CliMainCatchAllBackstop(unittest.TestCase):
    def test_escaping_proofbundle_error_maps_to_exit_2(self):
        # Berkeley re-gate round 2: anchor inspect's own except does not catch BundleFormatError; the
        # main() backstop must map any escaping ProofBundleError sibling to a clean exit 2, not a traceback.
        from proofbundle.cli import main
        self.assertEqual(main(["anchor", "inspect", "/dev/zero"]), 2)


if __name__ == "__main__":
    unittest.main()
