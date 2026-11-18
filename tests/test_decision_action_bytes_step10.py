"""Step 10 of Section 3.2 of draft-gruszka-audit-decision-receipts-05: where the relying party supplies the action
bytes, their SHA-256 MUST equal ``proposedAction.parametersDigest.sha256``.

Finding B1 of the list of 2 November 2026 (vector F5 of the draft's test package: the good receipt V2 with the
action bytes of V1). Measured on main 6f5955d1: ``decision verify`` took no action bytes, so it could not fail F5 and
ended with exit 0. These tests ask for the input (``action_bytes`` in the library, ``--action PATH`` on the command
line) and for the verdict the draft gives. Step 8 (F3) is not here: main refuses it with exit 3 once the trust policy
binds the key to the expected ``decisionMaker.id`` (measured with ``trusted_decision_makers``).

unittest-style like tests/test_decision_cli.py."""
from __future__ import annotations

import base64
import contextlib
import copy
import hashlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from proofbundle.cli import main
from proofbundle.decision import emit_decision_receipt, verify_decision_receipt
from proofbundle.emit import generate_signer

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
ACTION = b'{"export":"customers","limit":10}\n'
OTHER_ACTION = b'{"export":"customers","limit":100000}\n'


def _run(argv):
    """cli.main(argv) as (exit code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = main(argv)
        except SystemExit as exc:
            rc = exc.code
    return rc, out.getvalue(), err.getvalue()


def _predicate(parameters_digest=True):
    p = json.loads((EXAMPLES / "decision_receipt_deny.json").read_text(encoding="utf-8"))
    if parameters_digest:
        p["proposedAction"]["parametersDigest"] = {"sha256": hashlib.sha256(ACTION).hexdigest()}
    else:
        # A receipt may name its parameters by reference only; then no supplied bytes can match a digest.
        del p["proposedAction"]["parametersDigest"]
        p["proposedAction"]["parametersRef"] = {"uri": "https://example.org/params/1"}
    return p


class TestActionBytesLibrary(unittest.TestCase):
    def setUp(self):
        self.signer = generate_signer()
        self.pub = self.signer.public_key().public_bytes_raw()
        self.env = emit_decision_receipt(_predicate(), self.signer)

    def test_matching_action_bytes_pass(self):
        r = verify_decision_receipt(self.env, self.pub, strict=True, action_bytes=ACTION)
        self.assertIs(r["action_bytes_ok"], True)
        self.assertTrue(r["ok"], r["errors"])

    def test_other_action_bytes_fail(self):
        # F5 of the draft: a good receipt, the bytes of another action.
        r = verify_decision_receipt(self.env, self.pub, strict=True, action_bytes=OTHER_ACTION)
        self.assertIs(r["action_bytes_ok"], False)
        self.assertFalse(r["ok"])
        self.assertTrue(any("parametersDigest" in e for e in r["errors"]), r["errors"])
        self.assertFalse(r["automation"]["safeForAutomation"])

    def test_without_action_bytes_nothing_changes(self):
        r = verify_decision_receipt(self.env, self.pub, strict=True)
        self.assertIsNone(r["action_bytes_ok"])
        self.assertTrue(r["ok"], r["errors"])

    def test_empty_action_bytes_are_bytes(self):
        # An empty action is an action whose bytes are empty, not "no action given".
        r = verify_decision_receipt(self.env, self.pub, strict=True, action_bytes=b"")
        self.assertIs(r["action_bytes_ok"], False)
        self.assertFalse(r["ok"])

    def test_receipt_without_parameters_digest_fails_given_bytes(self):
        env = emit_decision_receipt(_predicate(parameters_digest=False), self.signer)
        r = verify_decision_receipt(env, self.pub, strict=True, action_bytes=ACTION)
        self.assertIs(r["action_bytes_ok"], False)
        self.assertFalse(r["ok"])

    def test_not_judged_over_unauthenticated_bytes(self):
        other = generate_signer().public_key().public_bytes_raw()
        r = verify_decision_receipt(self.env, other, strict=True, action_bytes=ACTION)
        self.assertFalse(r["crypto_ok"])
        self.assertIsNone(r["action_bytes_ok"])
        self.assertFalse(r["ok"])

    def test_tampered_payload_digest_is_not_rescued(self):
        # The comparison reads the digest of the SIGNED predicate: a receipt re-signed with the digest of the
        # other action passes only for the other action.
        p = _predicate()
        p["proposedAction"]["parametersDigest"] = {"sha256": hashlib.sha256(OTHER_ACTION).hexdigest()}
        env = emit_decision_receipt(copy.deepcopy(p), self.signer)
        self.assertIs(verify_decision_receipt(env, self.pub, action_bytes=ACTION)["action_bytes_ok"], False)
        self.assertIs(verify_decision_receipt(env, self.pub, action_bytes=OTHER_ACTION)["action_bytes_ok"], True)

    def test_action_bytes_must_be_bytes(self):
        r = verify_decision_receipt(self.env, self.pub, strict=True, action_bytes="not bytes")
        self.assertIs(r["action_bytes_ok"], False)
        self.assertFalse(r["ok"])


class TestActionBytesCli(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.signer = generate_signer()
        self.pub_b64 = base64.b64encode(self.signer.public_key().public_bytes_raw()).decode()
        self.receipt = self.tmp / "r.json"
        self.receipt.write_text(json.dumps(emit_decision_receipt(_predicate(), self.signer)), encoding="utf-8")
        self.action = self.tmp / "action.bin"
        self.action.write_bytes(ACTION)
        self.other = self.tmp / "other.bin"
        self.other.write_bytes(OTHER_ACTION)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _verify(self, *extra):
        return _run(["decision", "verify", str(self.receipt), "--pub", self.pub_b64, "--strict", *extra])

    def test_cli_matching_action_exit_0(self):
        rc, out, _ = self._verify("--action", str(self.action))
        self.assertEqual(rc, 0)
        self.assertIn("ACTION: OK", out)

    def test_cli_other_action_exit_2(self):
        # F5: the draft fails step 10; the command must not end with exit 0. A requested binding that does not
        # hold ends with exit 2 here, like --aud/--nonce.
        rc, out, err = self._verify("--action", str(self.other))
        self.assertEqual(rc, 2)
        self.assertIn("ACTION: MISMATCH", out)
        self.assertIn("parametersDigest", err)

    def test_cli_without_action_unchanged(self):
        rc, out, _ = self._verify()
        self.assertEqual(rc, 0)
        self.assertNotIn("ACTION:", out)

    def test_cli_unreadable_action_exit_2(self):
        rc, _, _ = self._verify("--action", str(self.tmp / "absent.bin"))
        self.assertEqual(rc, 2)

    def test_cli_empty_value_is_not_dropped(self):
        # `--action ''` names a file that cannot be read, never "no action".
        rc, _, _ = self._verify("--action", "")
        self.assertEqual(rc, 2)

    def test_cli_json_reports_the_axis(self):
        rc, out, _ = self._verify("--action", str(self.other), "--json")
        self.assertEqual(rc, 2)
        rep = json.loads(out)
        self.assertIs(rep["action_bytes_ok"], False)
        self.assertFalse(rep["ok"])


if __name__ == "__main__":
    unittest.main()
