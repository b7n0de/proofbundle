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


class SdJwtFamilyBudgetNeverRaise(unittest.TestCase):
    """RE-GATE round-final: the SD-JWT / status-list / KB-JWT / sample-opening verify surfaces parse their
    JWT parts with loads_strict, but their except caught only BundleFormatError + ValueError/TypeError — not
    BudgetExceeded (a ProofBundleError sibling). A wide/oversized JWT part must be a fail-closed verdict."""

    def _b64u(self, obj):
        import base64
        import json
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    def test_budget_overrun_is_failclosed_not_raise(self):
        wide = self._b64u([0] * 200_005) + "." + self._b64u({"x": 1}) + ".AA"
        over = self._b64u({"x": 1}) + "." + self._b64u({"p": "A" * (9 * 1024 * 1024)}) + ".AA"
        pub = generate_signer().public_key().public_bytes_raw()
        from proofbundle.kbjwt import verify_key_binding
        from proofbundle.sdjwt import verify_sd_jwt
        from proofbundle.sdjwt_vc import verify_sdjwt_vc
        from proofbundle.statuslist import verify_status_snapshot
        for tok in (wide, over):
            self.assertIs(verify_status_snapshot(tok, expected_uri="x", index=0, issuer_pubkey=pub)["ok"], False)
            self.assertIsNot(verify_sd_jwt(tok)["sig_ok"], True)   # verify_sd_jwt reports sig_ok/structure_ok
        self.assertIsNot(verify_key_binding(wide + "~" + wide)["ok"], True)
        self.assertIsNot(verify_sdjwt_vc(wide, {"vctAllowlist": ["x"], "requireKeyBinding": False},
                                         issuer_pubkey=b"\x00" * 32)["ok"], True)
        # persample.verify_sample_opening's BudgetExceeded fix (same except-ProofBundleError change) is
        # covered by the Berkeley-gate reproducer (its opening/root_b64 shape validation runs before the
        # disclosure parse, so a self-contained budget-only probe here is brittle).


class RelationStatementPolicyGuard(unittest.TestCase):
    def test_non_dict_policy_is_failclosed(self):
        # REGATE-CRYPTO-RELSTMT-POLICY: verify_relation_statement was missing the non-dict policy guard its
        # decision/outcome siblings carry — policy.get('relations') raised a raw AttributeError.
        from proofbundle.relation_statement import emit_relation_statement, verify_relation_statement
        s = generate_signer()
        edge = {"relation": "supersedes",
                "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": "b" * 64}}
        env = emit_relation_statement({"schemaVersion": "0.1.0", "statementId": "s1",
                                       "relationships": [edge]}, s)
        pub = s.public_key().public_bytes_raw()
        for pol in (123, "str", [1, 2]):
            r = verify_relation_statement(env, pub, policy=pol)   # must NOT raise AttributeError
            self.assertIs(r["ok"], False)
            self.assertIs(r["policy_ok"], False)
        self.assertIs(verify_relation_statement(env, pub)["ok"], True)  # no-policy regression


class CliInspectLoneSurrogate(unittest.TestCase):
    def test_inspect_lone_surrogate_is_clean_exit_2(self):
        # TCE-01/02/03: `<verb> inspect` dumped a raw UnicodeEncodeError on a lone-surrogate payload under
        # strict utf-8 stdout — now a clean exit 2 (ascii-escaped fallback), never a traceback.
        import contextlib
        import io
        import json
        import pathlib
        import tempfile

        from proofbundle import cli, dsse
        s = generate_signer()
        body = json.dumps({"predicateType": "x", "predicate": {"s": "\ud800"}},
                          ensure_ascii=False).encode("utf-8", "surrogatepass")
        env = dsse.sign_envelope(body, s, payload_type=_INTOTO)
        fd, p = tempfile.mkstemp(suffix=".json")
        pathlib.Path(p).write_text(json.dumps(env))
        try:
            for verb in ("decision", "outcome", "relation-statement"):
                # a STRICT utf-8 stdout (like a real terminal) is where the lone surrogate would crash — pytest's
                # own capture is lenient, so force strict to exercise the fix. Clean exit 2, never a traceback.
                strict = io.TextIOWrapper(io.BytesIO(), encoding="utf-8", errors="strict")
                with contextlib.redirect_stdout(strict):
                    rc = cli.main([verb, "inspect", p])
                self.assertEqual(rc, 2)
        finally:
            pathlib.Path(p).unlink()


class CallerPathTypedErrors(unittest.TestCase):
    """Final sweep: the last two raw-exception CALLER paths are now typed BundleFormatError, so the whole
    public verify surface is uniformly typed (no raw OSError / AttributeError on any probed input)."""

    def test_verify_bundle_bad_path_is_bundleformaterror(self):
        from proofbundle.bundle import verify_bundle
        from proofbundle.errors import BundleFormatError
        # a `str` bundle is a PATH; a huge / unreadable path is the documented BundleFormatError, not OSError.
        with self.assertRaises(BundleFormatError):
            verify_bundle("W" * 5000)          # File name too long -> OSError, now typed
        with self.assertRaises(BundleFormatError):
            verify_bundle("/no/such/proofbundle/path/deadbeef.json")

    def test_checkpoint_non_str_vkey_is_bundleformaterror(self):
        from proofbundle.checkpoint import (verify_checkpoint, verify_cosignature,
                                            verify_witnessed_checkpoint)
        from proofbundle.errors import BundleFormatError
        for bad in (None, 123, [1], {}):
            with self.assertRaises(BundleFormatError):
                verify_checkpoint("origin\n\nsig", bad)         # was raw AttributeError on .split
            with self.assertRaises(BundleFormatError):
                verify_cosignature("origin\n\nsig", bad)
            with self.assertRaises(BundleFormatError):
                verify_witnessed_checkpoint("origin\n\nsig", bad, ())

    def test_rt09_direct_dict_structural_budget(self):
        # RT-09 / PB-2026-0718-16: the structural budget (node count + nesting depth) must be enforced on the
        # DIRECT-DICT verify_bundle path, not only via loads_strict on the STR path. An over-limit hostile
        # dict is a fail-closed ProofBundleError verdict, never accepted and never a raw RecursionError.
        import base64
        from proofbundle import verify_bundle
        from proofbundle.budget import BudgetExceeded
        from proofbundle.errors import ProofBundleError
        # nesting depth past json_depth (64) — Teil-5 called out 257/4096/65536
        for depth in (257, 4096):
            inner = {"x": 1}
            for _ in range(depth):
                inner = {"a": inner}
            with self.assertRaises(ProofBundleError):
                verify_bundle({"schema": "proofbundle/v0.1", "deep": inner})
        # node count past json_nodes (200000)
        wide = {"schema": "proofbundle/v0.1", "big": {f"k{i}": i for i in range(250000)}}
        with self.assertRaises(BudgetExceeded):
            verify_bundle(wide)
        # RT-BDOS-01 / RT09-STRINGLEN-INERT: a single oversized string VALUE (or key) is capped on the
        # direct-dict path too (input_bytes is inert there), with rejection parity to the str/file path.
        from proofbundle._strict_json import enforce_structural_budget
        with self.assertRaises(BudgetExceeded):
            enforce_structural_budget({"k": "A" * 2_000_000})
        with self.assertRaises(BudgetExceeded):
            enforce_structural_budget({"K" * 2_000_000: 1})
        with self.assertRaises(ProofBundleError):
            verify_bundle({"schema": "proofbundle/v0.1", "payload_b64": "Z" * 2_000_000})
        # a legitimately shallow bundle is NOT rejected by the budget (it fails later on schema/content, but
        # never on the structural budget) — proves the guard is not over-tight.
        shallow = {"schema": "proofbundle/v0.1", "payload_b64": base64.b64encode(b"{}").decode()}
        try:
            verify_bundle(shallow)
        except BudgetExceeded:  # pragma: no cover - must NOT be a budget rejection
            self.fail("a shallow bundle must not trip the structural budget")
        except ProofBundleError:
            pass  # a downstream schema/content rejection is fine; only a budget false-positive is a bug

    def test_verify_inclusion_non_int_index_is_false_not_raise(self):
        # 6-lens gate: a non-int / float / None leaf_index or tree_size reached the `<=` / bit-ops in
        # root_from_inclusion as a raw TypeError on this PUBLIC never-raise surface. Now fail-closed False.
        from proofbundle import verify_inclusion
        root = b"\x00" * 32
        for li, ts in (("x", 1), (None, 1), (1.5, 2), (0, "x"), (0, None)):
            self.assertIs(verify_inclusion(b"leaf", li, ts, [], root), False)

    def test_merkle_non_bytes_root_proof_is_false_not_raise(self):
        # 6-lens gate L3-02: a non-bytes expected_root/root/proof-element reached hmac.compare_digest /
        # _node_hash (outside the guards) as a raw TypeError. Now fail-closed False on both public surfaces.
        from proofbundle import verify_consistency, verify_inclusion
        for bad_root in ("x", None, 123):
            self.assertIs(verify_inclusion(b"leaf", 0, 1, [], bad_root), False)
        self.assertIs(verify_consistency(1, 2, [b"\x00" * 32], None, None), False)
        self.assertIs(verify_consistency(1, 2, [123], b"\x00" * 32, b"\x00" * 32), False)
        self.assertIs(verify_consistency(2, 2, [], None, None), False)  # first==second branch

    def test_verify_evaluation_card_bad_path_is_verdict(self):
        # 6-lens gate L1-01: verify_evaluation_card read the card file unguarded, so a missing / directory /
        # None / NUL / surrogate card_path raised a raw FileNotFoundError/IsADirectoryError/TypeError/ValueError
        # on this public surface. Now a fail-closed verdict dict (present, no match).
        import base64
        from proofbundle import verify_evaluation_card
        claim = {"evaluation_card_sha256": "a" * 64}
        for bad in ("/no/such/file", "/tmp", None, "/no\x00nul", "/no\ud800sur"):
            r = verify_evaluation_card(bad, claim)
            self.assertIsInstance(r, dict)
            self.assertFalse(r["ok"])
        # unchanged: a claim with no card reference returns present=False before any read
        self.assertFalse(verify_evaluation_card("/no/such", {})["present"])
        _ = base64  # keep import symmetry with the sibling tests

    def test_verify_sample_opening_non_ascii_disclosure_is_verdict(self):
        # 6-lens gate L3-01: a non-ASCII / surrogate / emoji disclosure passed the isinstance(str) guard but
        # disclosure.encode("ascii") raised a raw UnicodeEncodeError. Now a fail-closed verdict (ok=False).
        import base64
        from proofbundle import verify_sample_opening
        root = base64.b64encode(b"\x00" * 32).decode()
        for disc in ("café☕", "\ud800sur", "emoji🎯"):
            r = verify_sample_opening({"index": 0, "disclosure": disc, "proof_b64": []}, root, 1)
            self.assertIsInstance(r, dict)
            self.assertFalse(r["ok"])

    def test_verify_dual_hash_non_bytes_data_is_result_not_raise(self):
        # 6-lens gate L3-02: verify_dual_hash's compute_digest(data, ...) call sat outside the guards, so a
        # non-bytes primary `data` (str/int/None/list) raised a raw TypeError from h.update(data). Now a
        # fail-closed VerificationResult on this public relying-party surface.
        from proofbundle import verify_dual_hash
        from proofbundle.errors import VerificationResult
        for bad in ("str", 123, None, [1], {"a": 1}):
            r = verify_dual_hash(bad, {"sha256": "abc"})
            self.assertIsInstance(r, VerificationResult)
            self.assertFalse(r.ok)

    def test_verify_bundle_nul_or_surrogate_path_is_typed(self):
        # 6-lens gate L3-01: a str bundle is a PATH; an embedded-NUL ('embedded null byte' -> ValueError) or
        # lone-surrogate (UnicodeEncodeError -> ValueError) path escaped the OSError-only guard as a raw
        # exception. Now a typed BundleFormatError, like every other bad path.
        from proofbundle import verify_bundle
        from proofbundle.bundle import BundleFormatError
        for bad in ('{"a":"\x00b"}', '{"a":"\ud800"}', "/no/such/file.json"):
            with self.assertRaises(BundleFormatError):
                verify_bundle(bad)

    def test_evaluate_public_transparency_non_str_note_is_verdict(self):
        # a non-str signed_note is a fail-closed verdict (all statuses FAIL), never a raw AttributeError —
        # this evaluate surface returns a named-status dict.
        from proofbundle.public_transparency import evaluate_public_transparency
        for bad in (123, None, [1]):
            r = evaluate_public_transparency(bad, {})   # must NOT raise
            self.assertIsInstance(r, dict)


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
