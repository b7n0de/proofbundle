"""The vectors of draft-gruszka-signed-evaluation-receipts-00 as conformance tests (EXPERIMENTAL format).

Every vector of the draft's Appendix A is judged as the draft judges it: the same verdict and the same
first failing step of Section 6. Where proofbundle produces a receipt (P1 to P3, P6 to P9) it
produces the draft's bytes. eval-claim v0.1 stays verifiable next to the new format, and the new format
is written only on the explicit ``--format eval-receipt-v1`` switch. A divergence is red; the fixture
is never adjusted to the code (tests/fixtures/signed_eval_receipt/README.md).
"""
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle import signed_eval_receipt as ser

REPO = Path(__file__).resolve().parents[1]
FIXTURE = REPO / "tests" / "fixtures" / "signed_eval_receipt" / "draft1_vectors.json"
SPECCHECK = REPO / "tests" / "fixtures" / "ed25519_speccheck_cases.json"


def _load():
    doc = json.loads(FIXTURE.read_text(encoding="utf-8"))
    payloads = {name: (p["text"].encode("utf-8") if "text" in p else base64.b64decode(p["b64"]))
                for name, p in doc["payloads"].items()}
    vectors = []
    for v in doc["vectors"]:
        raw = v["receipt_text"].encode("utf-8") if "receipt_text" in v else base64.b64decode(v["receipt_b64"])
        for name, b in payloads.items():
            raw = raw.replace(b"@" + name.encode("ascii") + b"@", base64.b64encode(b))
        vectors.append(dict(v, receipt=raw, key=base64.b64decode(v["key_b64"])))
    return doc, vectors


DOC, VECTORS = _load()


def _run(*args):
    return subprocess.run([sys.executable, "-m", "proofbundle.cli", *args], capture_output=True, text=True,
                          cwd=REPO, env={**os.environ, "PYTHONPATH": str(REPO / "src")})


class TheFixtureIsTheDraftsVectors(unittest.TestCase):
    def test_every_rebuilt_receipt_has_the_published_sha256(self):
        self.assertEqual(len(VECTORS), 64)
        for v in VECTORS:
            with self.subTest(vector=v["id"]):
                self.assertEqual(hashlib.sha256(v["receipt"]).hexdigest(), v["receipt_sha256"])


class EveryVectorIsJudgedAsTheDraftJudgesIt(unittest.TestCase):
    def test_verdict_and_first_failing_step(self):
        for v in VECTORS:
            with self.subTest(vector=v["id"]):
                got = ser.verify_signed_eval_receipt(v["receipt"], v["key"])
                self.assertEqual(("PASS" if got.ok else "FAIL", got.step_label), (v["expected"], v["step"]),
                                 got.reason)

    def test_each_of_the_twelve_steps_decides_some_vector(self):
        steps = {int(v["step"].split()[0]) for v in VECTORS if v["expected"] == "FAIL"}
        self.assertEqual(steps, set(range(1, 13)))

    def test_a_pass_returns_b_and_a_fail_returns_none(self):
        p1 = next(v for v in VECTORS if v["id"] == "P1")
        got = ser.verify_signed_eval_receipt(p1["receipt"], p1["key"])
        self.assertEqual(base64.b64encode(got.payload).decode("ascii"),
                         json.loads(p1["receipt"])["payload_b64"])
        n7 = next(v for v in VECTORS if v["id"] == "N7")
        self.assertIsNone(ser.verify_signed_eval_receipt(n7["receipt"], n7["key"]).payload)


class TheEmitterWritesTheDraftsBytes(unittest.TestCase):
    def test_positive_vectors_byte_for_byte(self):
        signer = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(DOC["issuer_seed_hex"]))
        other = [bytes.fromhex(x) for x in DOC["other_leaves_hex"]]
        by_id = {v["id"]: v for v in VECTORS}
        for vid, (leaf_index, key_hint) in DOC["emit"].items():
            with self.subTest(vector=vid):
                v = by_id[vid]
                b = base64.b64decode(json.loads(v["receipt"])["payload_b64"])
                out = ser.emit_signed_eval_receipt(json.loads(b), signer, other_leaves=other,
                                                   leaf_index=leaf_index, key_hint=key_hint)
                self.assertEqual(out, v["receipt"])

    def test_a_payload_the_verifier_refuses_is_not_emitted(self):
        signer = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(DOC["issuer_seed_hex"]))
        p1 = next(v for v in VECTORS if v["id"] == "P1")
        payload = json.loads(base64.b64decode(json.loads(p1["receipt"])["payload_b64"]))
        for change, step in (({"score": "0.700"}, "8"), ({"score": ".834"}, "6"), ({"n": 0}, "6"),
                             ({"model_id_commit": "acme/model-x"}, "7"), ({"extra": "x"}, "6")):
            with self.subTest(change=change):
                with self.assertRaisesRegex(ValueError, f"step {step}"):
                    ser.emit_signed_eval_receipt(dict(payload, **change), signer)


class TheProfileIsTheDraftsProfile(unittest.TestCase):
    def test_taming_the_many_eddsas_cases_get_the_strict_row(self):
        """The 12 cases of "Taming the Many EdDSAs" (vendored, tests/fixtures). The draft's profile
        refuses non-canonical encodings and small-order points and uses the cofactorless equation;
        measured, it accepts case 3 only, the row of Dalek strict and LibSodium in that fixture's
        README, where SPEC section 4a's backing verifier accepts 0, 1, 2, 3 and 11."""
        row = []
        for case in json.loads(SPECCHECK.read_text(encoding="utf-8")):
            try:
                ser._profile(bytes.fromhex(case["pub_key"]), bytes.fromhex(case["signature"]),
                             bytes.fromhex(case["message"]))
                row.append("V")
            except ser._Fail:
                row.append("X")
        self.assertEqual("".join(row), "XXXVXXXXXXXX")


class NoReceiptBytesRaise(unittest.TestCase):
    def test_every_prefix_of_p1_is_judged_not_raised(self):
        p1 = next(v for v in VECTORS if v["id"] == "P1")
        for cut in range(0, len(p1["receipt"]), 7):
            got = ser.verify_signed_eval_receipt(p1["receipt"][:cut], p1["key"])
            self.assertFalse(got.ok)
            self.assertEqual(got.step, 1)

    def test_deep_nesting_is_a_step_1_failure(self):
        key = VECTORS[0]["key"]
        self.assertEqual(ser.verify_signed_eval_receipt(b"[" * 100000 + b"]" * 100000, key).step, 1)

    def test_a_key_that_is_not_32_bytes_is_a_caller_error(self):
        with self.assertRaises(TypeError):
            ser.verify_signed_eval_receipt(VECTORS[0]["receipt"], b"\x00" * 31)


class TheCliKeepsV01AndSwitchesExplicitly(unittest.TestCase):
    def test_emit_eval_writes_v01_by_default_and_the_receipt_only_on_the_switch(self):
        p1 = next(v for v in VECTORS if v["id"] == "P1")
        b = base64.b64decode(json.loads(p1["receipt"])["payload_b64"])
        with tempfile.TemporaryDirectory() as d:
            seed = os.path.join(d, "seed.bin")
            Path(seed).write_bytes(bytes.fromhex(DOC["issuer_seed_hex"]))
            payload, leaves = os.path.join(d, "payload.json"), os.path.join(d, "leaves.json")
            Path(payload).write_bytes(b)
            Path(leaves).write_text(json.dumps(DOC["other_leaves_hex"]), encoding="utf-8")
            out = os.path.join(d, "receipt.json")
            r = _run("emit-eval", "--format", "eval-receipt-v1", "--claim", payload, "--key", seed,
                     "--other-leaves", leaves, "--out", out)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(Path(out).read_bytes(), p1["receipt"])
            # Without the switch the same payload is read as an eval-claim v0.1 claim, which it is not:
            # the v0.1 path refuses it, and no receipt of the new format is written.
            out01 = os.path.join(d, "v01.json")
            r = _run("emit-eval", "--claim", payload, "--key", seed, "--out", out01)
            self.assertEqual(r.returncode, 2)
            self.assertFalse(os.path.exists(out01))

    def test_show_eval_tells_the_formats_apart_by_schema(self):
        from proofbundle import evalclaim as ec
        from proofbundle.emit import generate_signer
        signer = generate_signer()
        claim, _ = ec.build_eval_claim(
            suite="s", suite_version="v1", metric="acc", comparator=">=", threshold="0.80", score="0.90",
            n=100, model_id="m", dataset_id="d", issuer="x", timestamp="2026-07-01T12:00:00Z",
            model_salt=b"0" * 16, dataset_salt=b"1" * 16)
        pin = "ed25519:" + DOC["issuer_public_b64"]
        by_id = {v["id"]: v for v in VECTORS}
        with tempfile.TemporaryDirectory() as d:
            v01 = os.path.join(d, "v01.json")
            Path(v01).write_text(json.dumps(ec.emit_eval_receipt(claim, signer)), encoding="utf-8")
            r = _run("show-eval", v01)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertNotIn("eval-receipt-v1", r.stdout)
            for vid, code, text in (("P1", 0, "=> OK"), ("P5", 0, "=> OK"),
                                    ("N7", 1, "=> FAILED at step 11 (profile 4)"),
                                    ("N23", 1, "=> FAILED at step 1"), ("N44", 1, "=> FAILED at step 1")):
                with self.subTest(vector=vid):
                    path = os.path.join(d, vid + ".json")
                    Path(path).write_bytes(by_id[vid]["receipt"])
                    r = _run("show-eval", path, "--expect-issuer", pin)
                    self.assertEqual(r.returncode, code, r.stderr)
                    self.assertIn(text, r.stdout + r.stderr)
            # Measured and kept as it is: N2's schema is not the receipt type, so the dispatch sends it
            # to the eval-claim v0.1 path, which refuses it (exit 1); N12's key is a point of small
            # order, and a pin naming one is refused before any receipt is read (exit 2, SPEC 4b).
            # Both stay FAIL; neither reaches the step the draft names.
            for vid, code, text in (("N2", 1, "not a valid, issuer-bound eval receipt"),
                                    ("N12", 2, "low-order Ed25519 key")):
                with self.subTest(vector=vid):
                    path = os.path.join(d, vid + ".json")
                    Path(path).write_bytes(by_id[vid]["receipt"])
                    r = _run("show-eval", path, "--expect-issuer", "ed25519:" + by_id[vid]["key_b64"])
                    self.assertEqual(r.returncode, code, r.stderr)
                    self.assertIn(text, r.stderr)
            # The receipt format needs the key the Receiver fixed: no pin is a malformed invocation.
            r = _run("show-eval", os.path.join(d, "P1.json"))
            self.assertEqual(r.returncode, 2)
            self.assertIn("exactly one --expect-issuer", r.stderr)


if __name__ == "__main__":
    unittest.main()
