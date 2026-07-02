"""Per-sample Merkle receipts (v2.0) — pins, roundtrips, adversarial red matrix."""
import base64
import copy
import hashlib
import hmac
import json
import unittest

from proofbundle import merkle
from proofbundle.errors import BundleFormatError
from proofbundle.persample import (LEAF_ALG, audit_challenge, build_sample_tree,
                                   catch_probability, derive_leaf_salt, make_disclosure,
                                   sample_opening, verify_sample_opening)

SECRET = bytes(range(32))
RECORDS = [{"id": i, "epoch": 1, "success": i % 3 != 0, "score": str(i % 3 != 0 and 1 or 0)}
           for i in range(10)]


def _tree(records=None, secret=SECRET):
    return build_sample_tree(records if records is not None else copy.deepcopy(RECORDS), secret)


class TestPins(unittest.TestCase):
    """Byte-level pins independent of roundtrips — mutation killers, not tautologies."""

    def test_salt_derivation_pin(self):
        # salt = HMAC-SHA256(secret, domain || id || 0x00 || epoch)[:16], pinned byte-exact.
        expected = hmac.new(SECRET, b"proofbundle/v2/leaf-salt" + b"42" + b"\x00" + b"7",
                            hashlib.sha256).digest()[:16]
        self.assertEqual(derive_leaf_salt(SECRET, 42, 7), expected)
        # id/epoch ambiguity guard: (id="1", epoch=12) != (id="11", epoch=2)
        self.assertNotEqual(derive_leaf_salt(SECRET, "1", 12), derive_leaf_salt(SECRET, "11", 2))

    def test_leaf_is_rfc6962_domain_separated(self):
        # Leaf = SHA-256(0x00 || disclosure_ascii) — the RFC 6962 leaf prefix, pinned.
        d = make_disclosure({"idx": 0, "id": 0}, b"\x01" * 16)
        self.assertEqual(merkle.leaf_hash(d.encode("ascii")),
                         hashlib.sha256(b"\x00" + d.encode("ascii")).digest())

    def test_challenge_derivation_pin(self):
        # seed = SHA-256(domain || root || u64(n) || u64(k) || nonce); expansion + rejection
        # sampling reproduced independently here — the implementation cannot drift silently.
        root = hashlib.sha256(b"pin").digest()
        n, k, nonce = 10, 3, b"\xaa" * 16
        seed = hashlib.sha256(b"proofbundle/v2/audit-challenge" + root
                              + n.to_bytes(8, "big") + k.to_bytes(8, "big") + nonce).digest()
        limit = (2**64 // n) * n
        expected, seen, counter = [], set(), 0
        while len(expected) < k:
            block = hmac.new(seed, counter.to_bytes(8, "big"), hashlib.sha256).digest()
            counter += 1
            for off in range(0, 32, 8):
                v = int.from_bytes(block[off:off + 8], "big")
                if v >= limit or (v % n) in seen:
                    continue
                seen.add(v % n)
                expected.append(v % n)
                if len(expected) == k:
                    break
        self.assertEqual(audit_challenge(root, n, k, nonce), expected)

    def test_catch_probability_por_bound(self):
        self.assertAlmostEqual(catch_probability(0.01, 300), 0.951, places=2)
        self.assertGreater(catch_probability(0.01, 459), 0.99)


class TestTreeAndOpenings(unittest.TestCase):
    def test_green_full_roundtrip(self):
        tree = _tree()
        self.assertEqual(tree["n"], 10)
        self.assertEqual(tree["leaf_alg"], LEAF_ALG)
        for idx in (0, 3, 9):
            opening = sample_opening(tree["disclosures"], idx)
            res = verify_sample_opening(opening, tree["root_b64"], tree["n"])
            self.assertTrue(res["ok"], res["detail"])
            self.assertEqual(res["record"]["id"], idx)
            self.assertEqual(res["record"]["idx"], idx)

    def test_deterministic_root_same_secret(self):
        self.assertEqual(_tree()["root_b64"], _tree()["root_b64"])

    def test_different_secret_different_root(self):
        self.assertNotEqual(_tree()["root_b64"], _tree(secret=bytes(range(1, 33)))["root_b64"])

    def test_builder_owns_indices(self):
        # Caller-supplied idx that disagrees with canonical position is refused (no reorder games).
        bad = copy.deepcopy(RECORDS)
        bad[2]["idx"] = 5
        with self.assertRaises(BundleFormatError):
            _tree(bad)

    def test_red_empty_and_bad_inputs(self):
        with self.assertRaises(BundleFormatError):
            build_sample_tree([], SECRET)
        with self.assertRaises(BundleFormatError):
            build_sample_tree(RECORDS, b"short")
        with self.assertRaises(BundleFormatError):
            make_disclosure({"id": 1}, b"\x00" * 16)     # missing idx → no replay guard, refused


class TestOpeningAdversarial(unittest.TestCase):
    def setUp(self):
        self.tree = _tree()
        self.opening = sample_opening(self.tree["disclosures"], 4)

    def test_red_record_tamper(self):
        # Flip the score inside the disclosure: leaf hash changes, inclusion fails.
        parsed = json.loads(base64.urlsafe_b64decode(self.opening["disclosure"] + "=="))
        parsed[1]["success"] = not parsed[1]["success"]
        forged = base64.urlsafe_b64encode(
            json.dumps(parsed, sort_keys=True, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()
        opening = dict(self.opening, disclosure=forged)
        res = verify_sample_opening(opening, self.tree["root_b64"], self.tree["n"])
        self.assertFalse(res["ok"])
        self.assertIsNone(res["record"], "tampered plaintext must never be returned")

    def test_red_replay_at_other_index(self):
        # A valid opening for index 4 presented at index 5 (with index 5's proof) fails BOTH
        # ways: wrong proof → inclusion fails; right-proof-wrong-position is impossible because
        # idx is inside the committed leaf.
        other = sample_opening(self.tree["disclosures"], 5)
        grafted = dict(other, disclosure=self.opening["disclosure"])
        res = verify_sample_opening(grafted, self.tree["root_b64"], self.tree["n"])
        self.assertFalse(res["ok"])

    def test_red_index_lied_in_opening(self):
        lied = dict(self.opening, index=5)
        res = verify_sample_opening(lied, self.tree["root_b64"], self.tree["n"])
        self.assertFalse(res["ok"])

    def test_red_proof_tamper(self):
        proof = list(self.opening["proof_b64"])
        raw = bytearray(base64.b64decode(proof[0]))
        raw[0] ^= 1
        proof[0] = base64.b64encode(bytes(raw)).decode()
        res = verify_sample_opening(dict(self.opening, proof_b64=proof),
                                    self.tree["root_b64"], self.tree["n"])
        self.assertFalse(res["ok"])

    def test_red_wrong_root_or_n(self):
        other_root = base64.b64encode(hashlib.sha256(b"other").digest()).decode()
        self.assertFalse(verify_sample_opening(self.opening, other_root, self.tree["n"])["ok"])
        self.assertFalse(verify_sample_opening(self.opening, self.tree["root_b64"], 5)["ok"])

    def test_tree_size_truth_comes_from_the_signature(self):
        # HONEST FINDING (documented in SPEC §7g/THREAT_MODEL): an RFC 6962 inclusion proof only
        # constrains n up to PATH-SHAPE EQUIVALENCE — measured here: for index 4 of a 10-leaf
        # tree, EVERY claimed n' in [9..16] verifies (same 4-node path, same left/right walk);
        # n'=17 changes the shape and fails. The size truth anchor is therefore the SIGNATURE:
        # build_eval_claim enforces samples.n == claim n, both signed. The proof binds position
        # and content under the signed (root, n) — never n itself.
        self.assertFalse(verify_sample_opening(self.opening, self.tree["root_b64"], 17)["ok"],
                         "a shape-changing n must fail")
        self.assertFalse(verify_sample_opening(self.opening, self.tree["root_b64"], 8)["ok"],
                         "n <= index is rejected outright")
        # the pinned coincidence window, so this stays measured fact, not folklore:
        for n_prime in (9, 12, 16):
            self.assertTrue(verify_sample_opening(self.opening, self.tree["root_b64"],
                                                  n_prime)["ok"],
                            f"shape-identical n'={n_prime} verifies — signature binds n")

    def test_red_lying_producer_embedded_idx(self):
        # THE case the replay guard exists for: a malicious PRODUCER commits a record whose
        # embedded idx lies about its position (bypassing build_sample_tree). The inclusion
        # proof is then VALID (the lie is inside the committed leaf), and only the
        # record.idx == proven-position check catches it.
        import base64 as b64
        from proofbundle.persample import make_disclosure, derive_leaf_salt
        records = [{"id": i} for i in range(8)]
        disclosures = []
        for i, rec in enumerate(records):
            r = dict(rec)
            r["idx"] = 7 - i                                     # every position lies
            disclosures.append(make_disclosure(r, derive_leaf_salt(SECRET, r["id"], 1)))
        leaves = [d.encode("ascii") for d in disclosures]
        root_b64 = b64.b64encode(merkle.merkle_tree_hash(leaves)).decode()
        opening = {"index": 2, "n": 8, "disclosure": disclosures[2],
                   "proof_b64": [b64.b64encode(p).decode()
                                  for p in merkle.inclusion_proof(leaves, 2)]}
        res = verify_sample_opening(opening, root_b64, 8)
        self.assertFalse(res["ok"], "a lying embedded idx must be rejected")
        self.assertIn("replay guard", res["detail"])

    def test_red_malformed_opening_raises(self):
        with self.assertRaises(BundleFormatError):
            verify_sample_opening({"index": "x", "disclosure": 1, "proof_b64": {}},
                                  self.tree["root_b64"], self.tree["n"])


class TestChallenge(unittest.TestCase):
    def test_distinct_in_range_deterministic(self):
        root = _tree()["root"]
        idx = audit_challenge(root, 10, 10, b"n" * 16)
        self.assertEqual(sorted(idx), list(range(10)))   # k=n → full coverage, all distinct
        self.assertEqual(idx, audit_challenge(root, 10, 10, b"n" * 16))

    def test_nonce_changes_challenge(self):
        root = _tree()["root"]
        self.assertNotEqual(audit_challenge(root, 10, 5, b"a" * 16),
                            audit_challenge(root, 10, 5, b"b" * 16))

    def test_root_binds_challenge(self):
        self.assertNotEqual(audit_challenge(hashlib.sha256(b"r1").digest(), 100, 5, b"n"),
                            audit_challenge(hashlib.sha256(b"r2").digest(), 100, 5, b"n"))

    def test_grinding_semantics_documented_and_real(self):
        # Self-challenge mode (empty nonce) IS grindable by re-salting: different secrets give
        # different roots give different indices. This test pins the THREAT — it must stay true,
        # and the docs must keep saying it (the honest bound, not a hidden weakness).
        t1, t2 = _tree(), _tree(secret=bytes(range(1, 33)))
        self.assertNotEqual(audit_challenge(t1["root"], 10, 3),
                            audit_challenge(t2["root"], 10, 3))

    def test_red_bad_params(self):
        root = hashlib.sha256(b"x").digest()
        for n, k in ((0, 1), (10, 0), (10, 11), (-1, 1)):
            with self.assertRaises(BundleFormatError):
                audit_challenge(root, n, k)
        with self.assertRaises(BundleFormatError):
            audit_challenge(b"short", 10, 1)

    def test_rejection_sampling_in_isolation(self):
        # The rejection branch fires with p = (2^64 mod n)/2^64 (~1e-19 for small n) — it can
        # NEVER be observed through the full challenge path, so it is pinned here directly on
        # the pure mapping function (this is what kills the "remove rejection" mutant).
        from proofbundle.persample import _map_draw
        n = 10
        limit = (2**64 // n) * n
        self.assertIsNone(_map_draw(2**64 - 1, n), "draw above the limit must be rejected")
        self.assertIsNone(_map_draw(limit, n), "the limit itself is rejected (half-open)")
        self.assertEqual(_map_draw(limit - 1, n), (limit - 1) % n)
        self.assertEqual(_map_draw(0, n), 0)
        # power-of-two n has zero rejection region: everything accepted
        self.assertEqual(_map_draw(2**64 - 1, 16), (2**64 - 1) % 16)


class TestClaimIntegration(unittest.TestCase):
    def test_claim_carries_signed_samples_root(self):
        from proofbundle import generate_signer, verify_bundle
        from proofbundle.evalclaim import build_eval_claim, decode_eval_claim, emit_eval_receipt
        tree = _tree()
        claim, _ = build_eval_claim(
            suite="s", suite_version="1", metric="pass_rate", comparator=">=",
            threshold="0.50", score="0.70", n=tree["n"], model_id="m", dataset_id="d",
            issuer="", timestamp="2026-07-02T16:00:00Z",
            samples={"root_b64": tree["root_b64"], "n": tree["n"], "leaf_alg": tree["leaf_alg"]})
        bundle = emit_eval_receipt(claim, generate_signer())
        self.assertTrue(verify_bundle(bundle).ok)
        decoded = decode_eval_claim(bundle)
        self.assertEqual(decoded["samples"]["root_b64"], tree["root_b64"])
        # an opening verifies against the SIGNED root from the decoded claim
        opening = sample_opening(tree["disclosures"], 2)
        res = verify_sample_opening(opening, decoded["samples"]["root_b64"],
                                    decoded["samples"]["n"])
        self.assertTrue(res["ok"])

    def test_red_samples_n_must_match_claim_n(self):
        from proofbundle.evalclaim import EvalClaimError, build_eval_claim
        tree = _tree()
        with self.assertRaises(EvalClaimError):
            build_eval_claim(
                suite="s", suite_version="1", metric="pass_rate", comparator=">=",
                threshold="0.50", score="0.70", n=tree["n"] + 5, model_id="m", dataset_id="d",
                issuer="", timestamp="2026-07-02T16:00:00Z",
                samples={"root_b64": tree["root_b64"], "n": tree["n"],
                         "leaf_alg": tree["leaf_alg"]})

    def test_red_bad_samples_objects(self):
        from proofbundle.evalclaim import EvalClaimError, build_eval_claim
        base = dict(suite="s", suite_version="1", metric="m", comparator=">=",
                    threshold="0.5", score="0.7", n=10, model_id="m", dataset_id="d",
                    issuer="", timestamp="2026-07-02T16:00:00Z")
        for bad in ({"root_b64": "!!", "n": 10, "leaf_alg": LEAF_ALG},
                    {"root_b64": base64.b64encode(b"short").decode(), "n": 10, "leaf_alg": LEAF_ALG},
                    {"root_b64": base64.b64encode(bytes(32)).decode(), "n": 10, "leaf_alg": "md5"},
                    {"root_b64": base64.b64encode(bytes(32)).decode(), "n": 10,
                     "leaf_alg": LEAF_ALG, "extra": 1}):
            with self.assertRaises(EvalClaimError, msg=bad):
                build_eval_claim(samples=bad, **base)


class TestSampleExtractors(unittest.TestCase):
    def test_promptfoo_samples_to_tree(self):
        from pathlib import Path
        from proofbundle.adapters import samples_from_promptfoo_results
        fixture = Path(__file__).parent / "fixtures" / "promptfoo_results_v3.json"
        records = samples_from_promptfoo_results(fixture)
        self.assertEqual(len(records), 3)
        self.assertEqual([r["id"] for r in records], [0, 1, 2])         # canonical order
        tree = build_sample_tree(records, SECRET)
        res = verify_sample_opening(sample_opening(tree["disclosures"], 1),
                                    tree["root_b64"], tree["n"])
        self.assertTrue(res["ok"])
        self.assertFalse(res["record"]["success"])                      # the failing test row

    def test_lm_eval_jsonl_roundtrip(self):
        import tempfile
        from proofbundle.adapters import samples_from_lm_eval_jsonl
        rows = [{"doc_id": i, "filter": "strict-match", "doc_hash": f"d{i}",
                 "prompt_hash": f"p{i}", "target_hash": f"t{i}",
                 "filtered_resps": [str(i)], "metrics": ["exact_match"], "exact_match": 1.0}
                for i in (2, 0, 1)]                                     # unsorted on purpose
        handle = tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False)
        handle.write("\n".join(json.dumps(r) for r in rows))
        handle.close()
        records = samples_from_lm_eval_jsonl(handle.name)
        self.assertEqual([r["id"] for r in records], [0, 1, 2])         # sorted canonically
        self.assertEqual(records[0]["metrics"], {"exact_match": "1.0"})
        tree = build_sample_tree(records, SECRET)
        self.assertTrue(verify_sample_opening(sample_opening(tree["disclosures"], 0),
                                              tree["root_b64"], tree["n"])["ok"])

    def test_red_lm_eval_bad_rows(self):
        import tempfile
        from proofbundle.adapters import samples_from_lm_eval_jsonl
        for content in ("", "not json", json.dumps({"no_doc_id": 1})):
            handle = tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False)
            handle.write(content)
            handle.close()
            with self.assertRaises(ValueError, msg=repr(content)):
                samples_from_lm_eval_jsonl(handle.name)


if __name__ == "__main__":
    unittest.main()


class TestVerifySideInvariants(unittest.TestCase):
    """v1.6 external review: the samples.n==n / leaf_alg / root invariants and context_binding
    MUST hold on the VERIFY path (decode_eval_claim), not only in the blessed emitter."""

    def _signed_claim_with(self, claim_dict):
        # Directly sign a hand-built claim, bypassing build_eval_claim's emit-side checks.
        from proofbundle import generate_signer
        from proofbundle.emit import emit_bundle
        from proofbundle.evalclaim import canonicalize
        import base64 as b64
        signer = generate_signer()
        raw = signer.public_key().public_bytes(
            __import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.Raw,
            __import__("cryptography.hazmat.primitives.serialization", fromlist=["PublicFormat"]).PublicFormat.Raw)
        claim_dict = dict(claim_dict)
        claim_dict["issuer"] = "ed25519:" + b64.b64encode(raw).decode()
        return emit_bundle(canonicalize(claim_dict), signer)

    def _base_claim(self, **over):
        c = {"schema": "proofbundle/eval-claim/v0.1", "suite": "s", "suite_version": "1",
             "metric": "pass_rate", "comparator": ">=", "threshold": "0.5", "passed": True,
             "n": 100, "model_id_commit": "sha256:x", "dataset_id_commit": "sha256:y",
             "commit_alg": "sha256-salted-v1", "issuer": "ed25519:z",
             "timestamp": "2026-07-02T00:00:00Z", "assurance_level": "self_attested"}
        c.update(over)
        return c

    def test_decode_rejects_samples_n_mismatch(self):
        from proofbundle.evalclaim import decode_eval_claim
        import base64 as b64
        root = b64.b64encode(bytes(32)).decode()
        bundle = self._signed_claim_with(self._base_claim(
            n=100, samples={"root_b64": root, "n": 7, "leaf_alg": "sha256-rfc6962-sdjwt-v1"}))
        self.assertIsNone(decode_eval_claim(bundle), "samples.n (7) != claim n (100) must reject")

    def test_decode_rejects_bad_leaf_alg(self):
        from proofbundle.evalclaim import decode_eval_claim
        import base64 as b64
        root = b64.b64encode(bytes(32)).decode()
        bundle = self._signed_claim_with(self._base_claim(
            n=5, samples={"root_b64": root, "n": 5, "leaf_alg": "md5"}))
        self.assertIsNone(decode_eval_claim(bundle))

    def test_decode_rejects_short_root(self):
        from proofbundle.evalclaim import decode_eval_claim
        import base64 as b64
        bundle = self._signed_claim_with(self._base_claim(
            n=5, samples={"root_b64": b64.b64encode(b"short").decode(),
                          "n": 5, "leaf_alg": "sha256-rfc6962-sdjwt-v1"}))
        self.assertIsNone(decode_eval_claim(bundle))

    def test_decode_accepts_valid_samples(self):
        from proofbundle.evalclaim import decode_eval_claim
        import base64 as b64
        root = b64.b64encode(bytes(range(32))).decode()
        bundle = self._signed_claim_with(self._base_claim(
            n=5, samples={"root_b64": root, "n": 5, "leaf_alg": "sha256-rfc6962-sdjwt-v1"}))
        self.assertIsNotNone(decode_eval_claim(bundle))

    def test_context_binding_enforced_on_verify(self):
        from proofbundle.evalclaim import decode_eval_claim
        bundle = self._signed_claim_with(self._base_claim(context_binding="run-A"))
        self.assertIsNotNone(decode_eval_claim(bundle))                       # no expectation → ok
        self.assertIsNotNone(decode_eval_claim(bundle, expected_context="run-A"))
        self.assertIsNone(decode_eval_claim(bundle, expected_context="run-B"))  # mismatch → reject
        # absent binding but a context expected → reject (no false assurance)
        bundle2 = self._signed_claim_with(self._base_claim())
        self.assertIsNone(decode_eval_claim(bundle2, expected_context="run-A"))
