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


class Round4TopLevelSurfacesFailClosed(unittest.TestCase):
    """Berkeley DEEP re-gate round 3 (11 confirmed escapes): the round-3 library widening fixed the inner
    loads_strict except sites but MISSED the flagship top-level surfaces, the rfc8785 ValueError family, and
    two file-read DoS classes. Each must now map hostile input to a typed fail-closed result."""

    def _node_heavy_dict(self):
        from proofbundle.budget import DEFAULT_BUDGET
        return {"schema": "proofbundle/v0.1", "big": list(range(DEFAULT_BUDGET.json_nodes + 50))}

    def _node_heavy_file(self):
        import os
        import tempfile
        from proofbundle.budget import DEFAULT_BUDGET
        # mkstemp (not the deprecated/insecure mktemp — CodeQL py/insecure-temporary-file): creates the file
        # atomically and returns an open fd, no name-then-open race.
        fd, p = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "wb") as fh:
            fh.write(b"[" + b"1," * (DEFAULT_BUDGET.json_nodes + 50) + b"1]")
        return p

    def test_verify_bundle_node_heavy_dict_and_file_are_bundleformat(self):
        from proofbundle.bundle import verify_bundle
        with self.assertRaises(BundleFormatError):
            verify_bundle(self._node_heavy_dict())
        with self.assertRaises(BundleFormatError):
            verify_bundle(self._node_heavy_file())

    def test_load_bundle_node_heavy_file_is_bundleformat(self):
        from proofbundle.bundle import load_bundle
        with self.assertRaises(BundleFormatError):
            load_bundle(self._node_heavy_file())

    def test_recompute_merkle_node_heavy_dict_and_file_are_bundleformat(self):
        from proofbundle.bundle import recompute_merkle_root_b64
        with self.assertRaises(BundleFormatError):
            recompute_merkle_root_b64(self._node_heavy_dict())
        with self.assertRaises(BundleFormatError):
            recompute_merkle_root_b64(self._node_heavy_file())

    def test_verify_enclave_node_heavy_eat_is_dict_not_raw(self):
        import base64
        import warnings
        warnings.filterwarnings("ignore")
        from proofbundle.budget import DEFAULT_BUDGET
        from proofbundle.experimental.enclave import verify_enclave_attestation
        b = lambda x: base64.urlsafe_b64encode(x).rstrip(b"=").decode()  # noqa: E731
        over = DEFAULT_BUDGET.json_nodes + 50
        eat = b(b"{}") + "." + b(b"[" + b"1," * over + b"1]") + ".AAAA"
        res = verify_enclave_attestation(eat, verifier_pubkey=b"\x00" * 32, expected_binding="x")
        self.assertIsInstance(res, dict)
        self.assertFalse(res["ok"])

    def test_intoto_verify_nan_inf_hugeint_are_dict_not_raw(self):
        import base64
        import json
        from proofbundle import intoto

        def envelope(pred):
            s = {"_type": "https://in-toto.io/Statement/v1",
                 "subject": [{"name": "x", "digest": {"sha256": "a" * 64}}],
                 "predicateType": "https://in-toto.io/attestation/test-result/v0.1",
                 "predicate": pred, "contentRootAlg": "jcs-sha256-v1"}
            body = json.dumps(s).encode()
            return {"payload": base64.b64encode(body).decode(),
                    "payloadType": "application/vnd.in-toto+json",
                    "signatures": [{"sig": base64.b64encode(b"x" * 64).decode()}]}

        for pred in ({"x": float("nan")}, {"x": float("inf")}, {"x": int("1" + "0" * 400)}):
            res = intoto.verify_intoto_dsse(envelope(pred), b"\x00" * 32)
            self.assertIsInstance(res, dict)
            self.assertFalse(res["ok"])

    def test_evalcard_and_prereg_devzero_and_fifo_fail_closed(self):
        import os
        import tempfile
        from proofbundle import verify_evaluation_card, verify_prereg
        # /dev/zero (character device) must fail-closed, not hang
        r = verify_evaluation_card("/dev/zero", {"evaluation_card_sha256": "bb"})
        self.assertFalse(r["ok"])
        # a FIFO with no writer must be refused by the stat-guard before open() blocks
        d = tempfile.mkdtemp()
        fifo = os.path.join(d, "fifo")
        os.mkfifo(fifo)
        try:
            self.assertFalse(verify_evaluation_card(fifo, {"evaluation_card_sha256": "bb"})["ok"])
            self.assertFalse(verify_prereg(fifo, {"prereg_sha256": "aa"})["ok"])
        finally:
            os.unlink(fifo)
            os.rmdir(d)

    def test_cli_verify_on_fifo_does_not_hang(self):
        # Berkeley re-gate round 4 completeness critic: a CLI verify command given a FIFO path blocked at
        # open() forever. The _open_input stat-guard maps it to a clean exit 2 via main()'s backstop.
        import base64
        import os
        import tempfile
        from proofbundle.cli import main
        d = tempfile.mkdtemp()
        fifo = os.path.join(d, "fifo")
        os.mkfifo(fifo)
        pub = base64.b64encode(b"\x00" * 32).decode()
        try:
            self.assertEqual(main(["intoto", fifo, "--verify", "--pub", pub]), 2)
        finally:
            os.unlink(fifo)
            os.rmdir(d)


class Round5PolicyCanonicalRenewalCheckpoint(unittest.TestCase):
    """Berkeley DEEP re-gate round 4 (3 confirmed + completeness escapes): the same direct-object budget-bypass,
    FIFO DoS and PQ-sibling classes at the surfaces round-4 did not reach — load_policy, canonical primitives,
    renewal.verify_sequence, and the witness quorum. Each must fail closed / return a verdict, never a raw
    RecursionError / PQ sibling / hang. The PQ cases assert 'returns a verdict, never raises' so they hold on
    both a PQ-capable and a stock (non-FIPS-204) build."""

    def test_load_policy_deep_dict_is_policyerror_not_recursion(self):
        from proofbundle.policy import PolicyError, load_policy
        d = {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "p"}
        c = d
        for _ in range(3000):
            c["allowed_issuers"] = {}
            c = c["allowed_issuers"]
        with self.assertRaises(PolicyError):
            load_policy(d)

    def test_load_policy_fifo_fails_closed(self):
        import os
        import tempfile
        from proofbundle.policy import PolicyError, load_policy
        dd = tempfile.mkdtemp()
        fifo = os.path.join(dd, "pfifo")
        os.mkfifo(fifo)
        try:
            with self.assertRaises(PolicyError):
                load_policy(fifo)
        finally:
            os.unlink(fifo)
            os.rmdir(dd)

    def test_statement_content_root_deep_is_typed_not_recursion(self):
        from proofbundle import statement_content_root
        from proofbundle.errors import ProofBundleError
        d = {}
        c = d
        for _ in range(5000):
            c["a"] = {}
            c = c["a"]
        with self.assertRaises(ProofBundleError):
            statement_content_root(d)

    def test_verify_sequence_mldsa_label_returns_verdict_never_raises(self):
        from proofbundle import ArchiveTimeStamp, verify_sequence
        ats = ArchiveTimeStamp(hash_alg="sha256", covered_digest="ab" * 32, time=1,
                               anchor_status="confirmed", sig_alg="mldsa65",
                               signatures=(("mldsa65", "AAAA"),))
        res = verify_sequence([[ats]], ["cd" * 32], authority_keys={"mldsa65": b"\x00" * 32})
        self.assertTrue(hasattr(res, "ok"))  # a VerificationResult, never a raw PQUnavailable

    def test_witness_quorum_mldsa_witness_returns_verdict_never_raises(self):
        import base64
        from proofbundle import checkpoint as cp
        keymat = bytes([0x06]) + b"\x00" * 1312
        vkey = "w+00000000+" + base64.b64encode(keymat).decode()
        note = ("o\n1\n" + base64.b64encode(b"\x00" * 32).decode() + "\nx\n\n— w "
                + base64.b64encode(b"\x00" * 2432).decode())
        ok, witnesses = cp.witness_quorum(note, [vkey], 1)  # must not raise UnsupportedError out of the batch
        self.assertIsInstance(witnesses, dict)

    def test_cli_verify_trusted_tsa_root_fifo_does_not_hang(self):
        import os
        import tempfile
        from proofbundle.cli import main
        dd = tempfile.mkdtemp()
        fifo = os.path.join(dd, "tsafifo")
        bundle = os.path.join(dd, "b.json")
        os.mkfifo(fifo)
        with open(bundle, "w") as fh:
            fh.write("{}")
        try:
            self.assertEqual(main(["verify", bundle, "--trusted-tsa-root", fifo]), 2)
        finally:
            os.unlink(fifo)
            os.unlink(bundle)
            os.rmdir(dd)


class Round6DsseAnchorPqsig(unittest.TestCase):
    """Berkeley DEEP re-gate round 5 (2 confirmed + completeness): the last public verify/load surfaces that
    leaked a raw BudgetExceeded / rfc8785 ValueError sibling, plus a documented-contract fix in pqsig."""

    def test_dsse_verify_envelope_oversized_signatures_is_bundleformat(self):
        from proofbundle.dsse import verify_envelope
        env = {"payload": "eyJhIjoxfQ==", "payloadType": "application/vnd.in-toto+json",
               "signatures": [{"sig": "AA=="} for _ in range(600)]}
        with self.assertRaises(BundleFormatError):
            verify_envelope(env, b"\x00" * 32, payload_type="application/vnd.in-toto+json")

    def test_dsse_load_payload_oversized_payload_is_bundleformat(self):
        from proofbundle.dsse import load_payload
        big = {"payload": "A" * (8 * 1024 * 1024 + 10), "payloadType": "x",
               "signatures": [{"sig": "AA=="}]}
        with self.assertRaises(BundleFormatError):
            load_payload(big)

    def test_receipt_canonical_root_non_jcs_number_is_bundleformat(self):
        # a crypto-valid attacker bundle can carry a 2**53 int / NaN (loads_strict admits them) that rfc8785
        # rejects — the `verify --require-anchor` path reached this; now typed, not a raw IntegerDomainError.
        from proofbundle.anchors import receipt_canonical_root
        for bundle in ({"schema": "x", "merkle": {"tree_size": 2 ** 53}}, {"x": float("nan")}):
            with self.assertRaises(BundleFormatError):
                receipt_canonical_root(bundle)

    def test_verify_mldsa_unknown_level_returns_false_not_raise(self):
        # docstring: "Malformed input returns False (never raises)". An unknown level is malformed input, so
        # it must fail closed to False (not PQUnavailable) — while a MISSING FIPS-204 build still raises.
        from proofbundle.pqsig import verify_mldsa
        self.assertFalse(verify_mldsa(b"\x00" * 32, b"\x00" * 64, b"msg", level="bogus-level"))


class Round7CanonicalRootJwtDecodeParse(unittest.TestCase):
    """Berkeley DEEP re-gate round 6 (1 confirmed + completeness): the last direct-primitive RecursionError,
    the JWT/token pre-decode memory amplification, and a public parse_ contract fix."""

    def test_receipt_canonical_root_deeply_nested_is_bundleformat_not_recursion(self):
        from proofbundle.anchors import receipt_canonical_root
        o = {}
        cur = o
        for _ in range(2000):
            nxt = {}
            cur["a"] = nxt
            cur = nxt
        cur["a"] = 1
        with self.assertRaises(BundleFormatError):
            receipt_canonical_root(o)

    def test_jwt_b64url_decode_oversized_segment_is_fail_closed(self):
        # kbjwt/statuslist/sdjwt/persample cap the raw segment before base64-decode — a huge segment fails
        # closed (a dict verdict or a typed error), never an unbounded pre-cap allocation.
        import base64
        from proofbundle import verify_key_binding
        big = base64.urlsafe_b64encode(b"A" * (18 * 1024 * 1024)).rstrip(b"=").decode()
        res = verify_key_binding("e30." + big + ".AA~kbh.kbp.kbs")
        self.assertIsInstance(res, dict)
        self.assertFalse(res["ok"])

    def test_b64url_decode_direct_oversized_is_typed(self):
        from proofbundle.kbjwt import _b64url_decode
        with self.assertRaises(BundleFormatError):
            _b64url_decode("A" * (9 * 1024 * 1024))

    def test_parse_tlog_proof_non_str_is_bundleformat_not_crash(self):
        from proofbundle.tlogproof import parse_tlog_proof
        for bad in (None, 123, b"bytes"):
            with self.assertRaises(BundleFormatError):
                parse_tlog_proof(bad)


if __name__ == "__main__":
    unittest.main()
