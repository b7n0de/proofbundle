"""Z309 review round 6a, F4 group 1, at the merged head: valid and invalid bundle signature, each with a valid
and an invalid checkpoint, through the real ``verify --policy --trusted-checkpoint --json`` command.

Per cell: the exit code, whether the result is (re-)stamped (origin before the checkpoint re-stamp, 46f), and that
the JSON report carries no ``verified_origin`` (46g). One further case drives the CLI re-stamp sequence on a real
``verify_bundle`` result and changes a check after the re-stamp: ``evaluate_policy`` must refuse it (46c/46d).

Existing tests that cover single cells of the same group are named in the Z309 report; this file is the matrix.
"""
from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization

from proofbundle import checkpoint as cp
from proofbundle import generate_signer, verify_bundle
from proofbundle.cli import main
from proofbundle.errors import VerificationResult
from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt
from proofbundle.policy import evaluate_policy

_ORIGIN = "verifier.example/log"


def _raw_pub(signer) -> bytes:
    return signer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _bundle_and_signer():
    signer = generate_signer()
    claim, _ = build_eval_claim(
        suite="s", suite_version="1", metric="acc", comparator=">=", threshold="0.5",
        score="0.9", n=10, model_id="m", dataset_id="d", issuer="iss",
        timestamp="2026-07-09T10:00:00Z")
    return emit_eval_receipt(claim, signer), signer


def _policy(signer) -> dict:
    pub_b64 = base64.b64encode(_raw_pub(signer)).decode("ascii")
    return {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "z309-f4-g1",
            "allowed_schema_versions": ["proofbundle/v0.1"],
            "allowed_issuers": [{"issuer": "iss", "public_key_b64": pub_b64, "kid": "k"}],
            "signature": {"allowed_algs": ["ed25519"], "require_expected_signer": True},
            "merkle": {"required_hash_alg": "sha256-rfc6962"},
            "assurance": {"minimum_level": "self_attested"}}


def _flip_signature(bundle: dict) -> None:
    s = bundle["signature"]["sig_b64"]
    bundle["signature"]["sig_b64"] = ("B" if s[0] != "B" else "C") + s[1:]


def _run_cell(bundle, signer, *, checkpoint_valid: bool):
    """Run the CLI on one cell; return (rc, stdout, stderr, number of stamp_origin calls). An invalid checkpoint
    is a note over the bundle's own root and size, signed by a different key than the one in --checkpoint-vkey."""
    root = base64.b64decode(bundle["merkle"]["root_b64"])
    size = bundle["merkle"]["tree_size"]
    note_signer = signer if checkpoint_valid else generate_signer()
    note = cp.sign_checkpoint(_ORIGIN, size, root, note_signer, _ORIGIN)
    vkey = cp.vkey(_ORIGIN, _raw_pub(signer))
    calls = {"n": 0}
    original = VerificationResult.stamp_origin

    def _spy(self):   # noqa: ANN001 - test spy
        calls["n"] += 1
        return original(self)

    with tempfile.TemporaryDirectory() as d:
        paths = {}
        for name, text in (("b.json", json.dumps(bundle)), ("c.txt", note), ("p.json", json.dumps(_policy(signer)))):
            paths[name] = os.path.join(d, name)
            with open(paths[name], "w", encoding="utf-8") as fh:
                fh.write(text)
        out, err = io.StringIO(), io.StringIO()
        VerificationResult.stamp_origin = _spy   # type: ignore[assignment]
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rc = main(["verify", paths["b.json"], "--policy", paths["p.json"], "--trusted-checkpoint",
                           paths["c.txt"], "--checkpoint-vkey", vkey, "--json"])
        finally:
            VerificationResult.stamp_origin = original   # type: ignore[assignment]
    return rc, out.getvalue(), err.getvalue(), calls["n"]


class SignatureTimesCheckpointMatrix(unittest.TestCase):

    def _cell(self, *, signature_valid: bool, checkpoint_valid: bool):
        bundle, signer = _bundle_and_signer()
        if not signature_valid:
            _flip_signature(bundle)
        rc, out, err, stamps = _run_cell(bundle, signer, checkpoint_valid=checkpoint_valid)
        self.assertNotIn("verified_origin", out + err, "the per-process origin token never travels in CLI output")
        return rc, out, err, stamps

    def test_valid_signature_valid_checkpoint_passes_and_is_restamped(self):
        rc, out, err, stamps = self._cell(signature_valid=True, checkpoint_valid=True)
        report = json.loads(out)
        self.assertEqual(rc, 0, f"{out}\n{err}")
        self.assertIs(report.get("policy_ok"), True)
        self.assertGreaterEqual(stamps, 2, "stamped by verify_bundle and re-stamped after the checkpoint check")

    def test_valid_signature_invalid_checkpoint_fails_the_crypto_verdict(self):
        rc, out, err, stamps = self._cell(signature_valid=True, checkpoint_valid=False)
        self.assertEqual(rc, 1, f"a checkpoint that does not verify fails the crypto verdict; {out}\n{err}")
        self.assertIsNot(json.loads(out).get("policy_ok"), True)
        self.assertGreaterEqual(stamps, 2, "the authentic result is re-stamped over the failing checkpoint check")

    def test_invalid_signature_valid_checkpoint_gains_no_origin(self):
        rc, out, err, stamps = self._cell(signature_valid=False, checkpoint_valid=True)
        self.assertEqual(rc, 1, f"{out}\n{err}")
        self.assertIsNot(json.loads(out).get("policy_ok"), True)
        self.assertEqual(stamps, 0, "a result without origin before the checkpoint step gains none from it")

    def test_invalid_signature_invalid_checkpoint_gains_no_origin(self):
        rc, out, err, stamps = self._cell(signature_valid=False, checkpoint_valid=False)
        self.assertEqual(rc, 1, f"{out}\n{err}")
        self.assertIsNot(json.loads(out).get("policy_ok"), True)
        self.assertEqual(stamps, 0, "neither failing step stamps an origin")


class ACheckChangedAfterTheRestampIsRefusedByThePolicy(unittest.TestCase):

    def test_the_cli_restamp_sequence_then_a_changed_check_fails_the_policy(self):
        bundle, signer = _bundle_and_signer()
        result = verify_bundle(bundle)
        was_authentic = result.origin_authentic()
        self.assertTrue(was_authentic, "a genuine verify_bundle result is origin-authentic")
        result.add("checkpoint-authenticity", True, "ok")
        if was_authentic:   # the 46f gate of the CLI
            result.stamp_origin()
        self.assertIs(evaluate_policy(bundle, result, _policy(signer)).get("policy_ok"), True,
                      "control: the re-stamped genuine result passes the policy")
        # Change the detail, not ok: ok=False would already fail the crypto verdict before the policy runs, so
        # only a change that keeps result.ok True reaches the origin gate this case is about.
        result.checks[-1].detail = "ok, edited after the re-stamp"
        self.assertTrue(result.ok, "precondition: the changed check still passes, only its detail differs")
        out = evaluate_policy(bundle, result, _policy(signer))
        self.assertIsNot(out.get("policy_ok"), True, f"a check changed after the re-stamp must be refused: {out!r}")
        self.assertIn("policy:result_origin", [c.get("name") for c in out.get("checks", [])])


if __name__ == "__main__":
    unittest.main()
