"""verify --matrix / --json check matrix + the honest meaning block (Paket 4). Additive and
non-breaking: the existing ok/checks JSON keys are unchanged; the human default output is unchanged
unless --matrix is passed."""
import contextlib
import io
import json
import os
import tempfile
import unittest

from proofbundle import emit_bundle, generate_signer
from proofbundle.cli import VERIFY_MEANING, VERIFY_NON_MEANING, main


def _bundle_file() -> str:
    bundle = emit_bundle(b'{"suite": "safety", "passed": true}', generate_signer())
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(bundle, f)
    return path


def _run(argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = main(argv)
    return rc, out.getvalue()


class TestVerifyMatrixJson(unittest.TestCase):
    def test_json_has_matrix_and_meaning_without_breaking_existing_keys(self):
        path = _bundle_file()
        try:
            rc, out = _run(["verify", path, "--json"])
            data = json.loads(out)
        finally:
            os.unlink(path)
        self.assertEqual(rc, 0)
        # existing contract intact
        self.assertIn("ok", data)
        self.assertIn("checks", data)
        self.assertTrue(data["ok"])
        # new additive fields
        self.assertIn("matrix", data)
        self.assertEqual(data["meaning"], VERIFY_MEANING)
        self.assertEqual(data["nonMeaning"], VERIFY_NON_MEANING)
        for row in data["matrix"]:
            self.assertIn(row["status"], ("PASS", "FAIL", "WARN", "SKIP"))
            self.assertIn("check", row)

    def test_non_meaning_is_honest(self):
        # No-Fake: the block must say what verification does NOT prove.
        self.assertIn("NON_CLAIMS", VERIFY_NON_MEANING)
        self.assertIn("NOT that the result is true", VERIFY_NON_MEANING)
        self.assertIn("authenticity and integrity", VERIFY_MEANING)


class TestVerifyMatrixHuman(unittest.TestCase):
    def test_matrix_flag_prints_the_block(self):
        path = _bundle_file()
        try:
            rc, out = _run(["verify", path, "--matrix"])
        finally:
            os.unlink(path)
        self.assertEqual(rc, 0)
        self.assertIn("check matrix", out)
        self.assertIn("proves", out)
        self.assertIn("proves NOT", out)

    def test_default_human_output_unchanged_no_matrix(self):
        path = _bundle_file()
        try:
            rc, out = _run(["verify", path])
        finally:
            os.unlink(path)
        self.assertEqual(rc, 0)
        self.assertNotIn("check matrix", out)   # default output stays clean (backward-compatible)
        # WP-B2: the bare `=> OK` is replaced by the context-labelled block. Crypto success is now
        # explicitly a CRYPTO result, and POLICY says it was not evaluated (no policy supplied).
        self.assertIn("CRYPTO: OK", out)
        self.assertNotIn("=> OK", out)
        self.assertIn("POLICY: NOT_EVALUATED", out)


if __name__ == "__main__":
    unittest.main()
