"""The 66 vectors of draft-gruszka-signed-evaluation-receipts-04 from the draft's own vector file, and a round trip of
the producer and the verifier under keys made in the run (EXPERIMENTAL format, in no release scope).

THE FILE. ``drafts/ser-04/test-vectors.json`` is the file Section 3.2 and Appendix A.3 of -04 fix by URL, size and
SHA-256 (232309 bytes, 710cb8ab...). It is read byte for byte as it stands, never rebuilt, and its size and SHA-256 are
checked before anything is read from it.

THE TEXT DECIDES. ``TABLE_2`` below is Table 2 of -04 written out (identifier, expected result, first failing step,
what it shows), in the draft's order; ``TheTableIsTheDraftsTable`` reads the same table from the text of -04 in
``drafts/ser-04`` and holds the literal to it. Each vector is judged against the TABLE, not against the file's own
``expected`` and ``step``; a vector whose file entry differs from the text is listed by name in ``_DIVERGES_FROM_TEXT``
with the reason, and that list is empty because none differs.

THE KEYS. Each vector names its verification key in words (an item "verification key: ..."); the four phrases map
to the bytes of Appendix A.1 and Section 5 of -04 in ``_KEYS``. A phrase that is not in that map is a red test.

THE ROUND TRIP. The producer writes receipts under Ed25519 keys generated in the run, with commitments made by
``salted_commitment`` from fresh salts, with and without the key hint and the optional criteria_digest; the verifier
reads each one under the signer's key (PASS) and under another generated key (FAIL at step 10 with the hint, at step
11 rule 4 without it).
"""
import base64
import hashlib
import json
import re
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle import signed_eval_receipt as ser

REPO = Path(__file__).resolve().parents[1]
VECTOR_FILE = REPO / "drafts" / "ser-04" / "test-vectors.json"
VECTOR_FILE_SIZE = 232309
VECTOR_FILE_SHA256 = "710cb8abab7ca51cf61b85c5610018f9a153add4c3db4f71b2d597e57b1671d1"
DRAFT_TEXT = REPO / "drafts" / "ser-04" / "draft-gruszka-signed-evaluation-receipts-04.txt"

#: Table 2 of -04: (identifier, expected, first failing step, what it shows).
TABLE_2 = (
    ("P1", "PASS", "all", "pass"),
    ("P2", "PASS", "all", "recorded-failure"),
    ("P4", "PASS", "all", "escaped-receipt-string"),
    ("P6", "PASS", "all", "no-key-hint"),
    ("P7", "PASS", "all", "comparator-le"),
    ("P8", "PASS", "all", "exact-decimal"),
    ("P9", "PASS", "all", "year-0000"),
    ("P10", "PASS", "all", "criteria-digest"),
    ("P12", "PASS", "all", "receipt-trailing-whitespace"),
    ("P13", "PASS", "all", "receipt-leading-whitespace"),
    ("N1", "FAIL", "4", "no-duplicate-names"),
    ("N2", "FAIL", "2", "receipt-schema"),
    ("N3", "FAIL", "4", "no-trailing-data"),
    ("N4", "FAIL", "7", "commitment-pattern"),
    ("N5", "FAIL", "5", "jcs-form"),
    ("N6", "FAIL", "11 (profile 3)", "s-less-than-L"),
    ("N7", "FAIL", "11 (profile 4)", "pae-type"),
    ("N9", "FAIL", "10", "key-hint"),
    ("N10", "FAIL", "6", "payload-schema"),
    ("N11", "FAIL", "8", "result-consistency"),
    ("N12", "FAIL", "11 (profile 2, key)", "small-order-key"),
    ("N13", "FAIL", "3", "canonical-base64"),
    ("N14", "FAIL", "1", "receipt-duplicate-names"),
    ("N15", "FAIL", "9", "signature-alg"),
    ("N16", "FAIL", "11 (profile 2, R)", "small-order-R"),
    ("N17", "FAIL", "11 (profile 1, R)", "noncanonical-R"),
    ("N18", "FAIL", "11 (profile 1, key)", "noncanonical-key"),
    ("N19", "FAIL", "1", "receipt-trailing-data"),
    ("N20", "FAIL", "1", "receipt-member-set"),
    ("N21", "FAIL", "1", "signature-member-set"),
    ("N22", "FAIL", "1", "receipt-duplicate-after-unescaping"),
    ("N23", "FAIL", "1", "receipt-bom"),
    ("N24", "FAIL", "3", "payload-not-base64"),
    ("N25", "FAIL", "9", "signature-length"),
    ("N26", "FAIL", "9", "signature-canonical-base64"),
    ("N30", "FAIL", "6", "commit-alg"),
    ("N31", "FAIL", "6", "payload-member-missing"),
    ("N32", "FAIL", "6", "payload-member-extra"),
    ("N33", "FAIL", "6", "payload-member-type"),
    ("N34", "FAIL", "6", "decimal-grammar"),
    ("N35", "FAIL", "6", "n-at-least-1"),
    ("N36", "FAIL", "6", "timestamp-calendar"),
    ("N37", "FAIL", "6", "timestamp-leap-second"),
    ("N38", "FAIL", "6", "comparator-set"),
    ("N39", "FAIL", "6", "non-empty-string"),
    ("N40", "FAIL", "4", "payload-utf8"),
    ("N41", "FAIL", "4", "payload-lone-surrogate"),
    ("N42", "FAIL", "4", "payload-noncharacter"),
    ("N43", "FAIL", "4", "payload-bom"),
    ("N44", "FAIL", "1", "receipt-utf8"),
    ("N45", "FAIL", "1", "receipt-lone-surrogate"),
    ("N46", "FAIL", "1", "receipt-noncharacter"),
    ("N48", "FAIL", "8", "comparator-gt"),
    ("N49", "FAIL", "8", "comparator-lt"),
    ("N50", "FAIL", "6", "n-below-2-53"),
    ("N51", "FAIL", "6", "ascii-digits"),
    ("N52", "FAIL", "5", "number-without-double"),
    ("N53", "FAIL", "11 (profile 1, key)", "key-before-R-rule-1"),
    ("N54", "FAIL", "11 (profile 2, key)", "key-before-R-rule-2"),
    ("N55", "FAIL", "2", "receipt-number-at-step-2"),
    ("N56", "FAIL", "5", "number-serialization"),
    ("N57", "FAIL", "7", "criteria-digest-pattern"),
    ("N58", "FAIL", "6", "criteria-digest-type"),
    ("N59", "FAIL", "11 (profile 2, R)", "mixed-order-R"),
    ("N60", "FAIL", "5", "payload-trailing-whitespace"),
    ("N61", "FAIL", "11 (profile 2, key)", "mixed-order-key"),
)


#: Vectors whose entry in the file differs from Table 2 of the text, with the reason. The text decides.
_DIVERGES_FROM_TEXT: dict = {}

#: The verification keys the vectors name in words, as bytes: Appendix A.1 (issuer test key, mixed-order test key)
#: and Section 5 (the neutral element: 01 followed by 31 zero bytes; non-canonical y = p + 1: EE, 30 bytes FF, 7F).
_KEYS = {
    "the issuer test key": base64.b64decode("x7ppA99DtumHO/Au0M/gumSK8IwCzNwPiID92BSFbak="),
    "the neutral element, canonical encoding (01 followed by 31 zero bytes)": b"\x01" + bytes(31),
    "the neutral element, non-canonical encoding y = p + 1 (EE, 30 bytes FF, 7F)": b"\xee" + b"\xff" * 30 + b"\x7f",
    "the mixed-order test key": base64.b64decode("JBz17qgxoLE067Bf5k3hKZ6Pfmfx/iD8IEaped1NGoM="),
}
#: The issuer test seed of Appendix A.1 (PURE TEST KEY), and the salts and identifiers of its two commitments.
_ISSUER_SEED = bytes.fromhex("2365520410748de8778b544410b15792fcf174e0fba4806a8c1afbdbb0946b07")
_A1_COMMITMENTS = (
    ("2d1845bc523b3c2635ab90af343f33eb", "acme/model-x@2026-09",
     "sha256:904de42562f9a19651e19eb7ab165e4ffe114ce5a2f98e57da5838959684fb0f"),
    ("6233feb59b670c391abeed0a61973c40", "acme/suite-data@v3",
     "sha256:a21ba4d96c803d4263dd3d2161bc039a30f4462bd59470e31ba5a9ab0a9b3b63"),
)


def _file_bytes() -> bytes:
    return VECTOR_FILE.read_bytes()


def _vectors() -> list:
    return json.loads(_file_bytes().decode("utf-8"))["vectors"]


def _key_of(vector: dict) -> bytes:
    phrases = [i[len("verification key: "):] for i in vector["items"] if i.startswith("verification key: ")]
    assert len(phrases) == 1, (vector["id"], phrases)
    return _KEYS[phrases[0]]


def _receipt_of(vector: dict) -> bytes:
    found = [bytes.fromhex(b["hex"]) for b in vector["bytes"] if b["label"] == "Receipt"]
    assert len(found) == 1, vector["id"]
    return found[0]


class TheFileIsTheOneTheDraftFixes(unittest.TestCase):
    def test_size_and_sha256(self):
        raw = _file_bytes()
        self.assertEqual(len(raw), VECTOR_FILE_SIZE)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), VECTOR_FILE_SHA256)

    def test_it_holds_66_vectors_with_the_counts_of_the_text(self):
        doc = json.loads(_file_bytes().decode("utf-8"))
        self.assertEqual(doc["document"], "draft-gruszka-signed-evaluation-receipts-04")
        self.assertEqual((doc["count"], len(doc["vectors"])), (66, 66))
        self.assertEqual(sum(1 for r in TABLE_2 if r[1] == "PASS"), 10)
        self.assertEqual(sum(1 for r in TABLE_2 if r[1] == "FAIL"), 56)

    def test_every_byte_string_has_the_length_and_sha256_the_file_states(self):
        for v in _vectors():
            for b in v["bytes"]:
                with self.subTest(vector=v["id"], label=b["label"]):
                    raw = bytes.fromhex(b["hex"])
                    self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (b["length"], b["sha256"]))


class TheTableIsTheDraftsTable(unittest.TestCase):
    def test_the_literal_is_table_2_of_the_text(self):
        text = DRAFT_TEXT.read_text(encoding="utf-8")
        self.assertEqual(hashlib.sha256(DRAFT_TEXT.read_bytes()).hexdigest(),
                         "d60c3dd95aefb8019a5f1c0ce041d8c4eb1d4571302766944bfbc92b91c1e358")
        start, end = text.index("   | ID  | Step"), text.index("Table 2", text.index("   | ID  | Step"))
        rows, cur = [], None
        for line in text[start:end].splitlines():
            m = re.match(r"   \| (\S*)\s*\| (.*?)\s*\| (\S*)\s*\| (.*?)\s*\|$", line)
            if not m or m.group(1) == "ID":
                continue
            if m.group(1):
                cur = [m.group(1), m.group(3), m.group(2), m.group(4)]
                rows.append(cur)
            else:
                cur[2] = (cur[2] + " " + m.group(2)).strip()
        self.assertEqual([tuple(r) for r in rows], list(TABLE_2))

    def test_the_file_agrees_with_the_text_except_where_listed(self):
        by_id = {v["id"]: v for v in _vectors()}
        self.assertEqual([v["id"] for v in _vectors()], [r[0] for r in TABLE_2])
        for vid, expected, step, label in TABLE_2:
            with self.subTest(vector=vid):
                v = by_id[vid]
                if vid in _DIVERGES_FROM_TEXT:
                    continue
                self.assertEqual((v["expected"], v["step"], v["label"]), (expected, step, label))


class EachVectorGetsTheTextsResult(unittest.TestCase):
    def test_verdict_and_first_failing_step_of_all_66(self):
        by_id = {v["id"]: v for v in _vectors()}
        for vid, expected, step, _label in TABLE_2:
            with self.subTest(vector=vid):
                v = by_id[vid]
                verdict = ser.verify_signed_eval_receipt(_receipt_of(v), _key_of(v))
                self.assertFalse(verdict.input_error or verdict.resource_limit, verdict)
                self.assertEqual(("PASS" if verdict.ok else "FAIL", verdict.step_label), (expected, step),
                                 verdict.reason)

    def test_a_pass_returns_the_b_the_vector_carries(self):
        for v in _vectors():
            if v["expected"] != "PASS":
                continue
            with self.subTest(vector=v["id"]):
                b = [bytes.fromhex(x["hex"]) for x in v["bytes"] if x["label"] == "B"]
                verdict = ser.verify_signed_eval_receipt(_receipt_of(v), _key_of(v))
                self.assertEqual([verdict.payload], b)


class TheCommitmentIsSection33(unittest.TestCase):
    def test_the_two_commitments_of_appendix_a1(self):
        for salt, ident, commitment in _A1_COMMITMENTS:
            with self.subTest(identifier=ident):
                self.assertEqual(ser.salted_commitment(ident, bytes.fromhex(salt)), (commitment, bytes.fromhex(salt)))

    def test_a_fresh_salt_is_16_bytes_and_differs_per_call(self):
        (c1, s1), (c2, s2) = ser.salted_commitment("m"), ser.salted_commitment("m")
        self.assertEqual((len(s1), len(s2)), (16, 16))
        self.assertNotEqual(s1, s2)
        self.assertNotEqual(c1, c2)
        self.assertEqual(c1, "sha256:" + hashlib.sha256(s1 + b"m").hexdigest())

    def test_a_salt_of_another_length_or_a_non_string_identifier_is_refused(self):
        for args in (("m", b"x" * 15), ("m", b"x" * 17), ("m", "x" * 16), (b"m", b"x" * 16), ("\ud800", b"x" * 16)):
            with self.subTest(args=repr(args)[:40]):
                with self.assertRaises(ValueError):
                    ser.salted_commitment(*args)


def _payload(model: str, dataset: str, **extra) -> dict:
    return {"schema": ser.PAYLOAD_SCHEMA, "suite": "acme-safety-suite", "suite_version": "3.1.0",
            "metric": "accuracy", "comparator": ">=", "threshold": "0.800", "score": "0.834", "passed": True,
            "n": 1800, "model_id_commit": ser.salted_commitment(model)[0],
            "dataset_id_commit": ser.salted_commitment(dataset)[0], "commit_alg": ser.COMMIT_ALG,
            "timestamp": "2026-11-19T20:00:00Z", **extra}


class TheRoundTrip(unittest.TestCase):
    def test_the_producer_writes_and_the_verifier_reads_under_keys_of_this_run(self):
        signer, other = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        pub, other_pub = (k.public_key().public_bytes_raw() for k in (signer, other))
        criteria = "sha256:" + hashlib.sha256(b'{"metric":"accuracy"}').hexdigest()
        for extra in ({}, {"criteria_digest": criteria}, {"score": "0.700", "passed": False},
                      {"comparator": "<", "threshold": "1", "score": "0.5"}):
            for hint in (True, False):
                with self.subTest(extra=extra, hint=hint):
                    payload = _payload("acme/model-x@2026-09", "acme/suite-data@v3", **extra)
                    receipt = ser.emit_signed_eval_receipt(payload, signer, key_hint=hint)
                    verdict = ser.verify_signed_eval_receipt(receipt, pub)
                    self.assertTrue(verdict.ok, verdict)
                    self.assertEqual(verdict.payload, ser.payload_bytes(payload))
                    obj = json.loads(receipt)
                    self.assertEqual("key" in obj["signature"], hint)
                    wrong = ser.verify_signed_eval_receipt(receipt, other_pub)
                    self.assertEqual(wrong.step_label, "10" if hint else "11 (profile 4)", wrong)

    def test_what_is_signed_is_pae_of_type_and_b_and_nothing_else(self):
        signer = Ed25519PrivateKey.generate()
        pub = signer.public_key().public_bytes_raw()
        receipt = ser.emit_signed_eval_receipt(_payload("m", "d"), signer, key_hint=False)
        obj = json.loads(receipt)
        b = base64.b64decode(obj["payload_b64"])
        sig = base64.b64decode(obj["signature"]["sig"])
        signer.public_key().verify(sig, ser.pae(ser.RECEIPT_TYPE, b))
        # The receipt object around B is not signed: reordered members and an added hint still verify.
        reordered = json.dumps({"signature": {"key": base64.b64encode(pub).decode(), "sig": obj["signature"]["sig"],
                                              "alg": "ed25519"},
                                "payload_b64": obj["payload_b64"], "schema": obj["schema"]}).encode()
        self.assertTrue(ser.verify_signed_eval_receipt(reordered, pub).ok)

    def test_a_signer_whose_signature_fails_the_profile_gets_no_receipt(self):
        """The producer verifies its own bytes by Section 5 before it returns them: a signer whose signature does not
        hold under its own public key (here 64 zero bytes, S = 0 and R not a point of order L) gets ValueError naming
        the failing step, and no receipt."""
        real = Ed25519PrivateKey.generate()

        class _Broken(Ed25519PrivateKey):
            def public_key(self):
                return real.public_key()

            def sign(self, data):
                return bytes(64)

            def private_bytes(self, *a, **k):
                return real.private_bytes(*a, **k)

            def private_bytes_raw(self):
                return real.private_bytes_raw()

            def __copy__(self):
                return self

            def __deepcopy__(self, memo):
                return self

        with self.assertRaisesRegex(ValueError, "fails its own verification at step 11"):
            ser.emit_signed_eval_receipt(_payload("m", "d"), _Broken())

    def test_the_issuer_test_key_reproduces_p1_of_the_file(self):
        p1 = next(v for v in _vectors() if v["id"] == "P1")
        b = next(bytes.fromhex(x["hex"]) for x in p1["bytes"] if x["label"] == "B")
        out = ser.emit_signed_eval_receipt(json.loads(b), Ed25519PrivateKey.from_private_bytes(_ISSUER_SEED))
        self.assertEqual(out, _receipt_of(p1))


if __name__ == "__main__":
    unittest.main()
