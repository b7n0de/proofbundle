"""The vectors of draft-gruszka-signed-evaluation-receipts-04 as conformance tests (EXPERIMENTAL format).

Every vector of the draft's Appendix A is judged as the draft judges it: the same verdict and the same first
failing step of Section 5. The ten vectors that Appendix A.2 gives in full are written out below from the text
of -04, with the size and SHA-256 of each receipt, so the fixture is held against the draft and not only
against itself. The other 56 come from the fixture, byte-identical to the one the draft's Section 11 measured
at a339424e07fd58fa261d8ca3f41af5de4dcbf751; the change log of -04 says the vector set is unchanged since -00.

Only the verifier is here. proofbundle writes no receipt of this format, and ``show-eval`` reads one only on
the explicit ``--format eval-receipt-v1`` switch; without it the command is what it was. A divergence is red;
the fixture is never adjusted to the code (tests/fixtures/signed_eval_receipt/README.md).
"""
import base64
import hashlib
import importlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
FIXTURE = REPO / "tests" / "fixtures" / "signed_eval_receipt" / "draft1_vectors.json"
SPECCHECK = REPO / "tests" / "fixtures" / "ed25519_speccheck_cases.json"
#: The draft's PURE TEST seed of the issuer key (its Appendix A.1), written out: a shipped test builds a
#: throwaway key from a literal and loads no key from outside (tests/test_sdist_ohne_signierwerkzeug.py).
#: The fixture carries the same seed, and a test below holds the two equal.
_DRAFT_TEST_SEED = b'#eR\x04\x10t\x8d\xe8w\x8bTD\x10\xb1W\x92\xfc\xf1t\xe0\xfb\xa4\x80j\x8c\x1a\xfb\xdb\xb0\x94k\x07'

#: Appendix A.2 of -04, vector by vector: expected verdict, first failing step, and the size and SHA-256 of
#: the receipt bytes as the draft states them in each vector's list items.
DRAFT04_A2 = {
    "P1": ("PASS", "all", 871, "02036d1f57509858330383755ec16c532bdc58b0f2d949464488d57abc9f95e7"),
    "P2": ("PASS", "all", 871, "2405d1783d1803ddea207c027622fba40b3e82161686505ee96988e306e17278"),
    "P4": ("PASS", "all", 872, "c2a7943f0ea3de6e9da88c11925b1e112d32f697a403f07fcfbc3776bca10e72"),
    "P6": ("PASS", "all", 818, "2c8144d50b4cc42a712d84e4d0417e52b0d8cbc484ad8e6d8d4b36a429b94ec1"),
    "N5": ("FAIL", "5", 923, "f4573f3c66570e347f4fa305b61cd189211824d9c02c603942766ff082c391c4"),
    "N7": ("FAIL", "11 (profile 4)", 871, "18b1b6dc631cf0f00d8b0d2c237b28a67b12c2d7088ae0313a2fb27760f96bdd"),
    "N12": ("FAIL", "11 (profile 2, key)", 871, "19d798c4199635a8bc637e09466633a270f1502ce5f802e57908a063443b3e60"),
    "N13": ("FAIL", "3", 871, "31a34194edd90bade6568a3cb00dbb983dabab9efccfd7a8b38650bd3e8d5201"),
    "N14": ("FAIL", "1", 968, "8966f27c5f2566d986b0ab7821060ea0c901504fe984d450dfc7f8ca7d1c27e1"),
    "N59": ("FAIL", "11 (profile 2, R)", 871, "2c913638dc4b977574a2582a60aeb934a87b3492a0da5dc451e1de84d9e4c3cc"),
}


def _ser():
    """The module under test, loaded in each case, so that a missing module fails every case on its own."""
    return importlib.import_module("proofbundle.signed_eval_receipt")


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
BY_ID = {v["id"]: v for v in VECTORS}


def _neu_signiert(**geaendert) -> bytes:
    """P1 with members of its payload replaced, B formed anew under RFC 8785 and signed with the draft's PURE TEST seed."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from proofbundle.dsse import pae
    ser = _ser()
    p1 = json.loads(BY_ID["P1"]["receipt"])
    payload = {**json.loads(base64.b64decode(p1["payload_b64"])), **geaendert}
    b = ser._jcs(payload).encode("utf-8")
    sig = Ed25519PrivateKey.from_private_bytes(_DRAFT_TEST_SEED).sign(pae(ser.RECEIPT_TYPE, b))
    return json.dumps({"schema": ser.RECEIPT_TYPE, "payload_b64": base64.b64encode(b).decode("ascii"),
                       "signature": {"alg": "ed25519", "sig": base64.b64encode(sig).decode("ascii")}}).encode("utf-8")


def _run(*args):
    return subprocess.run([sys.executable, "-m", "proofbundle.cli", *args], capture_output=True, text=True,
                          cwd=REPO, env={**os.environ, "PYTHONPATH": str(REPO / "src")})


class TheTenVectorsOfAppendixA2(unittest.TestCase):
    def test_the_fixture_holds_the_ten_as_the_draft_states_them(self):
        for vid, (expected, step, size, sha) in DRAFT04_A2.items():
            with self.subTest(vector=vid):
                v = BY_ID[vid]
                self.assertEqual((v["expected"], v["step"], len(v["receipt"]), v["receipt_sha256"]),
                                 (expected, step, size, sha))

    def test_each_of_the_ten_is_judged_as_the_draft_judges_it(self):
        ser = _ser()
        for vid, (expected, step, _size, _sha) in DRAFT04_A2.items():
            with self.subTest(vector=vid):
                got = ser.verify_signed_eval_receipt(BY_ID[vid]["receipt"], BY_ID[vid]["key"])
                self.assertEqual(("PASS" if got.ok else "FAIL", got.step_label), (expected, step), got.reason)


class TheFixtureIsTheDraftsVectors(unittest.TestCase):
    def test_the_written_seed_is_the_drafts_test_seed(self):
        self.assertEqual(_DRAFT_TEST_SEED.hex(), DOC["issuer_seed_hex"])

    def test_every_rebuilt_receipt_has_the_published_sha256(self):
        self.assertEqual(len(VECTORS), 66)
        for v in VECTORS:
            with self.subTest(vector=v["id"]):
                self.assertEqual(hashlib.sha256(v["receipt"]).hexdigest(), v["receipt_sha256"])

    def test_an_identifier_is_a_label_for_the_expected_verdict(self):
        """The draft's Appendix A: a P vector expects PASS and an N vector FAIL."""
        self.assertEqual({(v["id"][0], v["expected"]) for v in VECTORS}, {("P", "PASS"), ("N", "FAIL")})
        self.assertEqual(sum(v["id"][0] == "P" for v in VECTORS), 10)
        self.assertEqual(sum(v["id"][0] == "N" for v in VECTORS), 56)


class EveryVectorIsJudgedAsTheDraftJudgesIt(unittest.TestCase):
    def test_verdict_and_first_failing_step(self):
        ser = _ser()
        for v in VECTORS:
            with self.subTest(vector=v["id"]):
                got = ser.verify_signed_eval_receipt(v["receipt"], v["key"])
                self.assertEqual(("PASS" if got.ok else "FAIL", got.step_label), (v["expected"], v["step"]),
                                 got.reason)

    def test_each_of_the_eleven_steps_decides_some_vector(self):
        steps = {int(v["step"].split()[0]) for v in VECTORS if v["expected"] == "FAIL"}
        self.assertEqual(steps, set(range(1, 12)))

    def test_a_receipt_with_a_former_inclusion_member_fails_at_step_1(self):
        """The member set is exactly schema, payload_b64 and signature: P1 with an inclusion object, the
        same B and signature, is refused at step 1, not verified."""
        ser = _ser()
        former = json.loads(BY_ID["P1"]["receipt"])
        former["inclusion"] = {"tree_size": 1, "leaf_index": 0, "inclusion_path": [],
                               "root": hashlib.sha256(b"\x00" + base64.b64decode(former["payload_b64"])).hexdigest()}
        got = ser.verify_signed_eval_receipt(json.dumps(former).encode("utf-8"), BY_ID["P1"]["key"])
        self.assertEqual((got.ok, got.step_label), (False, "1"), got.reason)

    def test_whitespace_after_the_json_text_is_admitted_and_b_must_still_be_its_own_form(self):
        """Step 1 admits insignificant whitespace after the receipt's JSON text, and step 4 admits it after B
        under the rules of step 1 (RFC 8259 Section 2). P12 is P1's receipt followed by a line feed and
        verifies; N60 is P1's B followed by a line feed, signed anew, and fails at step 5, not at step 4."""
        ser = _ser()
        p1, p12, n60 = BY_ID["P1"], BY_ID["P12"], BY_ID["N60"]
        self.assertEqual(p12["receipt"], p1["receipt"] + b"\n")
        b_p1 = base64.b64decode(json.loads(p1["receipt"])["payload_b64"])
        self.assertEqual(base64.b64decode(json.loads(n60["receipt"])["payload_b64"]), b_p1 + b"\n")
        got = ser.verify_signed_eval_receipt(p12["receipt"], p12["key"])
        self.assertEqual((got.ok, got.step_label), (True, "all"), got.reason)
        self.assertEqual(got.payload, b_p1)
        got = ser.verify_signed_eval_receipt(n60["receipt"], n60["key"])
        self.assertEqual((got.ok, got.step_label), (False, "5"), got.reason)

    def test_whitespace_before_the_json_text_is_admitted(self):
        """P13 is a line feed followed by P1's receipt and verifies, with the B of P1."""
        ser = _ser()
        p1, p13 = BY_ID["P1"], BY_ID["P13"]
        self.assertEqual(p13["receipt"], b"\n" + p1["receipt"])
        got = ser.verify_signed_eval_receipt(p13["receipt"], p13["key"])
        self.assertEqual((got.ok, got.step_label), (True, "all"), got.reason)
        self.assertEqual(got.payload, base64.b64decode(json.loads(p1["receipt"])["payload_b64"]))

    def test_a_pass_returns_b_and_a_fail_returns_none(self):
        ser = _ser()
        got = ser.verify_signed_eval_receipt(BY_ID["P1"]["receipt"], BY_ID["P1"]["key"])
        self.assertEqual(base64.b64encode(got.payload).decode("ascii"),
                         json.loads(BY_ID["P1"]["receipt"])["payload_b64"])
        self.assertIsNone(ser.verify_signed_eval_receipt(BY_ID["N7"]["receipt"], BY_ID["N7"]["key"]).payload)


class TheProfileIsTheDraftsProfile(unittest.TestCase):
    def test_taming_the_many_eddsas_cases_get_the_strict_row(self):
        """The 12 cases of "Taming the Many EdDSAs" (vendored, tests/fixtures). The draft's profile refuses
        non-canonical encodings and every key or R that is not a point of order L, and uses the cofactorless
        equation; measured, it refuses all twelve."""
        ser = _ser()
        row = []
        for case in json.loads(SPECCHECK.read_text(encoding="utf-8")):
            try:
                ser._profile(bytes.fromhex(case["pub_key"]), bytes.fromhex(case["signature"]),
                             bytes.fromhex(case["message"]))
                row.append("V")
            except ser._Fail:
                row.append("X")
        self.assertEqual("".join(row), "XXXXXXXXXXXX")


class AKeyThatIsNot32OctetsIsAnInputError(unittest.TestCase):
    """Section 5 of -04: a verification-key input that is not exactly 32 octets is an input error, the steps
    are not run, and the result is neither PASS nor the FAIL of a step. A 32-octet key that is no canonical
    point, or not of order L, is no input error and fails step 11 (Section 11 of -04)."""

    def test_no_step_runs_for_a_key_of_another_length(self):
        ser = _ser()
        for key in (b"", b"\x00" * 31, b"\x00" * 33, BY_ID["P1"]["key"] + b"\x00", None, "not bytes"):
            for vid in ("P1", "N14", "N7"):
                with self.subTest(key=repr(key)[:20], vector=vid):
                    got = ser.verify_signed_eval_receipt(BY_ID[vid]["receipt"], key)
                    self.assertEqual((got.ok, got.step, got.rule, got.input_error, got.resource_limit,
                                      got.step_label), (False, None, None, True, False, "input error"))

    def test_a_32_octet_key_that_is_no_point_of_order_l_fails_step_11(self):
        ser = _ser()
        for vid in ("N12", "N18", "N53", "N54", "N61"):
            with self.subTest(vector=vid):
                got = ser.verify_signed_eval_receipt(BY_ID[vid]["receipt"], BY_ID[vid]["key"])
                self.assertEqual((got.ok, got.step, got.input_error), (False, 11, False))


class NoReceiptBytesRaise(unittest.TestCase):
    def test_every_prefix_of_p1_is_judged_not_raised(self):
        ser = _ser()
        p1 = BY_ID["P1"]
        for cut in range(0, len(p1["receipt"]), 7):
            got = ser.verify_signed_eval_receipt(p1["receipt"][:cut], p1["key"])
            self.assertFalse(got.ok)
            self.assertEqual(got.step, 1)

    def test_deep_nesting_is_a_resource_limit_not_a_step_failure(self):
        ser = _ser()
        got = ser.verify_signed_eval_receipt(b"[" * 100000 + b"]" * 100000, BY_ID["P1"]["key"])
        self.assertEqual((got.ok, got.step, got.resource_limit, got.input_error, got.step_label),
                         (False, None, True, False, "resource limit"))

    def test_the_depth_bound_is_the_packages_and_not_the_interpreters(self):
        """One level past ``budget.json_depth`` is a resource limit, and a receipt at the bound is read and fails step
        1. No interpreter raises RecursionError at this depth, so only the reader's own bound can decide it; at
        bd1bdf6b the Python 3.14 of CI parsed 100000 levels and step 1 failed."""
        from proofbundle.budget import DEFAULT_BUDGET
        ser, n = _ser(), DEFAULT_BUDGET.json_depth
        formen = {"lists": lambda k: b"[" * k + b"]" * k,
                  "objects": lambda k: b'{"a":' * (k - 1) + b"{}" + b"}" * (k - 1)}
        for form, bau in formen.items():
            with self.subTest(form=form):
                got = ser.verify_signed_eval_receipt(bau(n + 1), BY_ID["P1"]["key"])
                self.assertEqual((got.ok, got.step, got.resource_limit, got.step_label),
                                 (False, None, True, "resource limit"))
                got = ser.verify_signed_eval_receipt(bau(n), BY_ID["P1"]["key"])
                self.assertEqual((got.ok, got.step, got.resource_limit), (False, 1, False), got.reason)

    def test_a_b_past_the_depth_bound_is_a_resource_limit_not_step_4(self):
        """The same bound holds for B, read at step 4: past it no step fails, at it step 4 fails, since B is no
        object."""
        from proofbundle.budget import DEFAULT_BUDGET
        ser, n = _ser(), DEFAULT_BUDGET.json_depth
        for tiefe, erwartet in ((n + 1, (False, None, True)), (n, (False, 4, False))):
            b = b"[" * tiefe + b"]" * tiefe
            receipt = json.dumps({"schema": ser.RECEIPT_TYPE, "payload_b64": base64.b64encode(b).decode("ascii"),
                                  "signature": {"alg": "ed25519", "sig": "AA=="}}).encode("utf-8")
            with self.subTest(depth=tiefe):
                got = ser.verify_signed_eval_receipt(receipt, BY_ID["P1"]["key"])
                self.assertEqual((got.ok, got.step, got.resource_limit), erwartet, got.reason)

    def test_a_string_past_the_budget_is_a_resource_limit_and_one_below_it_passes(self):
        """Codex thread 4437338037 at bd1bdf6b: P1 with a `suite` of 1,000,001 characters, signed anew with the draft's
        test seed, verified with ok=True, and show-eval then refused it while rendering. The verifier now holds the
        package's whole structural budget (budget.string_len, json_nodes, json_depth), so the verdict says so itself;
        700,000 characters stay a PASS."""
        ser = _ser()
        for laenge, erwartet in ((1_000_001, (False, None, True)), (700_000, (True, None, False))):
            with self.subTest(length=laenge):
                got = ser.verify_signed_eval_receipt(_neu_signiert(suite="a" * laenge), BY_ID["P1"]["key"])
                self.assertEqual((got.ok, got.step, got.resource_limit), erwartet, got.reason)

    def test_a_long_member_name_and_too_many_items_are_a_resource_limit_too(self):
        """The other two axes of the budget, at the receipt: without them both receipts would fail step 1."""
        from proofbundle.budget import DEFAULT_BUDGET
        ser = _ser()
        lang = json.dumps({"schema": ser.RECEIPT_TYPE, "n" * (DEFAULT_BUDGET.string_len + 1): 1}).encode("utf-8")
        viele = json.dumps({"schema": ser.RECEIPT_TYPE, "x": [0] * (DEFAULT_BUDGET.json_nodes + 1)}).encode("utf-8")
        glieder = json.dumps({"schema": ser.RECEIPT_TYPE,
                              "x": {f"k{i}": 0 for i in range(DEFAULT_BUDGET.json_nodes + 1)}}).encode("utf-8")
        for name, receipt in (("name", lang), ("items", viele), ("members", glieder)):
            with self.subTest(axis=name):
                got = ser.verify_signed_eval_receipt(receipt, BY_ID["P1"]["key"])
                self.assertEqual((got.ok, got.step, got.resource_limit), (False, None, True), got.reason)

    def test_a_receipt_that_is_no_bytes_value_fails_step_1(self):
        ser = _ser()
        self.assertEqual(ser.verify_signed_eval_receipt("not bytes", BY_ID["P1"]["key"]).step, 1)
        self.assertEqual(ser.verify_signed_eval_receipt(None, BY_ID["P1"]["key"]).step, 1)


class TheCliReadsTheFormatOnlyOnItsSwitch(unittest.TestCase):
    PIN = "ed25519:" + DOC["issuer_public_b64"]

    def _file(self, d, name, data):
        path = os.path.join(d, name)
        Path(path).write_bytes(data)
        return path

    def test_without_the_switch_show_eval_is_what_it_was(self):
        """A receipt of the format is no eval-claim v0.1 bundle: without the switch it is refused as before
        (exit 1), and the refusal names the switch."""
        with tempfile.TemporaryDirectory() as d:
            r = _run("show-eval", self._file(d, "P1.json", BY_ID["P1"]["receipt"]), "--expect-issuer", self.PIN)
            self.assertEqual(r.returncode, 1, r.stderr)
            self.assertIn("not a valid, issuer-bound eval receipt", r.stderr)
            self.assertIn("--format eval-receipt-v1", r.stderr)
            self.assertNotIn("=> OK", r.stdout)

    def test_an_eval_claim_bundle_keeps_its_path(self):
        from proofbundle import evalclaim as ec
        from proofbundle.emit import generate_signer
        claim, _ = ec.build_eval_claim(
            suite="s", suite_version="v1", metric="acc", comparator=">=", threshold="0.80", score="0.90",
            n=100, model_id="m", dataset_id="d", issuer="x", timestamp="2026-07-01T12:00:00Z",
            model_salt=b"0" * 16, dataset_salt=b"1" * 16)
        with tempfile.TemporaryDirectory() as d:
            path = self._file(d, "v01.json",
                              json.dumps(ec.emit_eval_receipt(claim, generate_signer())).encode("utf-8"))
            r = _run("show-eval", path)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertNotIn("eval-receipt-v1", r.stdout + r.stderr)
            r = _run("show-eval", path, "--format", "eval-receipt-v1", "--expect-issuer", self.PIN)
            self.assertEqual(r.returncode, 1, r.stderr)
            self.assertIn("=> FAILED at step 1", r.stderr)

    def test_on_the_switch_each_vector_gets_the_drafts_verdict_and_step(self):
        with tempfile.TemporaryDirectory() as d:
            for vid, code, text in (("P1", 0, "=> OK"), ("P10", 0, "=> OK"), ("P13", 0, "=> OK"),
                                    ("N2", 1, "=> FAILED at step 2"), ("N7", 1, "=> FAILED at step 11 (profile 4)"),
                                    ("N14", 1, "=> FAILED at step 1"), ("N23", 1, "=> FAILED at step 1"),
                                    ("N44", 1, "=> FAILED at step 1"), ("N59", 1, "=> FAILED at step 11 (profile 2, R)")):
                with self.subTest(vector=vid):
                    r = _run("show-eval", self._file(d, vid + ".json", BY_ID[vid]["receipt"]),
                             "--format", "eval-receipt-v1", "--expect-issuer", self.PIN)
                    self.assertEqual(r.returncode, code, r.stderr)
                    self.assertIn(text, r.stdout + r.stderr)

    def test_a_pass_says_what_a_receipt_does_not_prove(self):
        with tempfile.TemporaryDirectory() as d:
            r = _run("show-eval", self._file(d, "P1.json", BY_ID["P1"]["receipt"]),
                     "--format", "eval-receipt-v1", "--expect-issuer", self.PIN)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("draft-gruszka-signed-evaluation-receipts-04", r.stdout)
            self.assertIn("does not show that it was published or logged", r.stdout)
            self.assertIn("that the score is true", r.stdout)

    def test_the_receiver_fixes_exactly_one_key(self):
        with tempfile.TemporaryDirectory() as d:
            path = self._file(d, "P1.json", BY_ID["P1"]["receipt"])
            for extra in ((), ("--expect-issuer", self.PIN, "--expect-issuer", self.PIN),
                          ("--expect-issuer", "ed25519:" + base64.b64encode(b"\x07" * 31).decode("ascii"))):
                with self.subTest(extra=extra):
                    r = _run("show-eval", path, "--format", "eval-receipt-v1", *extra)
                    self.assertEqual(r.returncode, 2, r.stderr)
            # SPEC 4b: a pin naming a small-order key is refused before the receipt is read (Section 11 of -04).
            r = _run("show-eval", self._file(d, "N12.json", BY_ID["N12"]["receipt"]), "--format", "eval-receipt-v1",
                     "--expect-issuer", "ed25519:" + BY_ID["N12"]["key_b64"])
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertIn("low-order Ed25519 key", r.stderr)

    def test_a_resource_limit_is_no_verdict(self):
        with tempfile.TemporaryDirectory() as d:
            deep = self._file(d, "deep.json", b"[" * 100000 + b"]" * 100000)
            large = self._file(d, "large.json", b" " * (8 * 1024 * 1024 + 1))
            # Codex thread 4437338037: a receipt that verified and then failed the render was exit 2, not 4.
            long_suite = self._file(d, "long_suite.json", _neu_signiert(suite="a" * 1_000_001))
            for path in (deep, large, long_suite):
                with self.subTest(path=os.path.basename(path)):
                    r = _run("show-eval", path, "--format", "eval-receipt-v1", "--expect-issuer", self.PIN)
                    self.assertEqual(r.returncode, 4, r.stderr)
                    self.assertIn("NO VERDICT, neither PASS nor FAIL", r.stderr)
                    self.assertNotIn("=> OK", r.stdout)


class TheRenderOfAPassStaysInsideTheExitCodes(unittest.TestCase):
    def test_a_refusal_while_rendering_a_pass_is_no_verdict(self):
        """The mapping of exit codes is total: if the second reading of B for the output refuses it after a PASS, the
        command says NO VERDICT with exit 4, never exit 2 for an invocation that was well formed."""
        import contextlib
        import io
        from unittest import mock
        from proofbundle import cli
        from proofbundle.budget import BudgetExceeded
        err, out = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "P1.json")
            Path(path).write_bytes(BY_ID["P1"]["receipt"])
            with mock.patch.object(cli, "loads_strict", side_effect=BudgetExceeded("string_len", 2, 1)), \
                    contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
                code = cli.main(["show-eval", path, "--format", "eval-receipt-v1", "--expect-issuer",
                                 TheCliReadsTheFormatOnlyOnItsSwitch.PIN])
        self.assertEqual(code, 4, err.getvalue())
        self.assertIn("NO VERDICT, neither PASS nor FAIL", err.getvalue())
        self.assertNotIn("=> OK", out.getvalue())


if __name__ == "__main__":
    unittest.main()
