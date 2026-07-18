"""C2SP tlog-proof — green roundtrips + adversarial red matrix (v1.3)."""
import base64
import unittest

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import checkpoint as cp
from proofbundle import emit_bundle, generate_signer
from proofbundle.errors import BundleFormatError
from proofbundle.tlogproof import (MAGIC, format_tlog_proof, parse_tlog_proof,
                                   tlog_proof_for_bundle, verify_tlog_proof)

TS = 1_780_000_000
ORIGIN = "log.example/l1"


def _raw(key):
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _setup(n_witnesses=1, prior=(b"a", b"b", b"c")):
    """Emit a bundle anchored after prior leaves, checkpoint its root, cosign, build the proof."""
    log_key = generate_signer()
    payload = b'{"result": 42}'
    bundle = emit_bundle(payload, log_key, prior_leaves=list(prior))
    root = base64.b64decode(bundle["merkle"]["root_b64"])
    note = cp.sign_checkpoint(ORIGIN, bundle["merkle"]["tree_size"], root, log_key, ORIGIN)
    witnesses = []
    for i in range(n_witnesses):
        wk = generate_signer()
        wname = f"w{i}.example/w"
        note = cp.cosign_checkpoint(note, wk, wname, TS + i)
        witnesses.append(cp.cosign_vkey(wname, _raw(wk)))
    proof = tlog_proof_for_bundle(bundle, note)
    return proof, payload, cp.vkey(ORIGIN, _raw(log_key)), witnesses, bundle


class TestFormatParse(unittest.TestCase):
    def test_roundtrip_with_extra(self):
        proof, payload, log_vkey, _, bundle = _setup(0)
        p2 = format_tlog_proof(bundle["merkle"]["leaf_index"],
                               [base64.b64decode(x) for x in bundle["merkle"]["inclusion_proof_b64"]],
                               proof.split("\n\n", 1)[1], extra=b"context")
        parsed = parse_tlog_proof(p2)
        self.assertEqual(parsed["extra"], b"context")
        self.assertEqual(parsed["index"], bundle["merkle"]["leaf_index"])

    def test_parse_rejects(self):
        proof, *_ = _setup(0)
        for mutate in (
            lambda t: t.replace(MAGIC, "c2sp.org/tlog-proof@v2"),          # wrong magic
            lambda t: t.replace("index 3", "index 03"),                     # leading zero
            lambda t: t.replace("index 3", "index -3"),                     # negative
            lambda t: t.replace("index 3", "idx 3"),                        # missing index line
            lambda t: t.replace("\n\n", "\n", 1),                           # no separator
        ):
            with self.assertRaises(BundleFormatError, msg=mutate):
                parse_tlog_proof(mutate(proof))

    def test_no_fake_guard_checkpoint_mismatch(self):
        # tlog_proof_for_bundle refuses a checkpoint over a DIFFERENT root/size.
        _, _, _, _, bundle = _setup(0)
        other_key = generate_signer()
        other_note = cp.sign_checkpoint(ORIGIN, 99, b"\x00" * 32, other_key, ORIGIN)
        with self.assertRaises(BundleFormatError):
            tlog_proof_for_bundle(bundle, other_note)


class TestVerify(unittest.TestCase):
    def test_green_log_only(self):
        proof, payload, log_vkey, _, _ = _setup(0)
        res = verify_tlog_proof(proof, payload, log_vkey)
        self.assertTrue(res["ok"], res)
        self.assertTrue(res["log_ok"] and res["inclusion_ok"] and res["witnesses_ok"])
        self.assertEqual(res["origin"], ORIGIN)

    def test_green_witnessed(self):
        proof, payload, log_vkey, wvkeys, _ = _setup(3)
        res = verify_tlog_proof(proof, payload, log_vkey, wvkeys, threshold=2)
        self.assertTrue(res["ok"], res)

    def test_red_one_key_under_many_names_not_a_quorum(self):
        # CRITICAL (release review): verify_tlog_proof must dedup the witness quorum by KEY MATERIAL, not name —
        # one physical key under N names must NOT satisfy threshold>1 (mirrors verify_witnessed_checkpoint).
        log_key = generate_signer()
        payload = b'{"result": 42}'
        bundle = emit_bundle(payload, log_key, prior_leaves=[b"a", b"b", b"c"])
        root = base64.b64decode(bundle["merkle"]["root_b64"])
        note = cp.sign_checkpoint(ORIGIN, bundle["merkle"]["tree_size"], root, log_key, ORIGIN)
        sole = generate_signer()
        names = ("wa.example/w", "wb.example/w", "wc.example/w")
        for i, name in enumerate(names):
            note = cp.cosign_checkpoint(note, sole, name, TS + i)
        vkeys = [cp.cosign_vkey(n, _raw(sole)) for n in names]
        proof = tlog_proof_for_bundle(bundle, note)
        res = verify_tlog_proof(proof, payload, cp.vkey(ORIGIN, _raw(log_key)), vkeys, threshold=3)
        self.assertFalse(res["witnesses_ok"], "one key under three names must not satisfy threshold=3")
        self.assertFalse(res["ok"])

    def test_red_wrong_leaf(self):
        proof, _, log_vkey, _, _ = _setup(0)
        res = verify_tlog_proof(proof, b"other bytes", log_vkey)
        self.assertFalse(res["ok"])
        self.assertFalse(res["inclusion_ok"])
        self.assertTrue(res["log_ok"])          # checkpoint itself is fine — precise verdicts

    def test_red_wrong_log_key(self):
        proof, payload, _, _, _ = _setup(0)
        stranger = generate_signer()
        res = verify_tlog_proof(proof, payload, cp.vkey(ORIGIN, _raw(stranger)))
        self.assertFalse(res["ok"])
        self.assertFalse(res["log_ok"])
        self.assertTrue(res["inclusion_ok"])    # inclusion binds to the (unsigned-for-us) root

    def test_red_index_tamper(self):
        proof, payload, log_vkey, _, _ = _setup(0)
        tampered = proof.replace("index 3", "index 2")
        res = verify_tlog_proof(tampered, payload, log_vkey)
        self.assertFalse(res["ok"])
        self.assertFalse(res["inclusion_ok"])

    def test_red_proof_hash_tamper(self):
        proof, payload, log_vkey, _, _ = _setup(0)
        lines = proof.split("\n")
        for i, ln in enumerate(lines):
            if ln.startswith("index "):
                h = base64.b64decode(lines[i + 1])
                lines[i + 1] = base64.b64encode(bytes([h[0] ^ 1]) + h[1:]).decode()
                break
        res = verify_tlog_proof("\n".join(lines), payload, log_vkey)
        self.assertFalse(res["ok"])

    def test_red_quorum_not_met(self):
        proof, payload, log_vkey, wvkeys, _ = _setup(1)
        res = verify_tlog_proof(proof, payload, log_vkey, wvkeys, threshold=2)
        self.assertFalse(res["ok"])
        self.assertFalse(res["witnesses_ok"])
        self.assertTrue(res["log_ok"] and res["inclusion_ok"])

    def test_red_extra_is_not_trusted(self):
        # Mutating the (unauthenticated) extra line must not turn a bad proof good — and a good
        # proof stays good: extra is carried, never verified.
        proof, payload, log_vkey, _, _ = _setup(0)
        with_extra = proof.replace(MAGIC + "\n", MAGIC + "\nextra " +
                                   base64.b64encode(b"attacker data").decode() + "\n")
        res = verify_tlog_proof(with_extra, payload, log_vkey)
        self.assertTrue(res["ok"])              # good proof unaffected by extra
        res2 = verify_tlog_proof(with_extra, b"forged", log_vkey)
        self.assertFalse(res2["ok"])            # extra cannot rescue a wrong leaf

    def test_red_index_out_of_range(self):
        proof, payload, log_vkey, _, _ = _setup(0)
        tampered = proof.replace("index 3", "index 4")   # == tree_size → out of range
        self.assertFalse(verify_tlog_proof(tampered, payload, log_vkey)["ok"])

    def test_red_bad_threshold(self):
        # RE-GATE never-raise (breadth sweep): a bad threshold is a fail-closed VERDICT (ok=False), not a
        # raw BundleFormatError — this dict-returning verify surface must always return a verdict.
        proof, payload, log_vkey, _, _ = _setup(0)
        r = verify_tlog_proof(proof, payload, log_vkey, (), threshold=-1)
        self.assertIs(r["ok"], False)
        self.assertIn("threshold", r["detail"])

    def test_failclosed_witnesses_is_a_dict_like_the_happy_path(self):
        # 6-lens gate L3-01: the fail-closed verdict returned "witnesses": [] (a LIST) while the happy path
        # returns a name->verdict DICT (checkpoint.witness_quorum). A consumer formatting the verdict with
        # res["witnesses"].items()/.values()/len() crashed with a raw AttributeError on malformed input.
        # Every malformed/type-confused input must now yield witnesses as a DICT so the shape is stable.
        for bad in ("", "garbage", b"\x00", 12345, None,
                    "c2sp.org/tlog-proof@v1\n\nx\n\ny\n"):
            r = verify_tlog_proof(bad, b"leaf", "log+deadbeef+abc")
            self.assertIs(r["ok"], False)
            self.assertIsInstance(r["witnesses"], dict,
                                  "witnesses must be a dict on the fail-closed path (matches happy path)")
            # the exact consumer access that used to crash must now work
            self.assertEqual(dict(r["witnesses"].items()), {})
            self.assertEqual(sum(1 for w in r["witnesses"].values() if w.get("ok")), 0)


if __name__ == "__main__":
    unittest.main()
