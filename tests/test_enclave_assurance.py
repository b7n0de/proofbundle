"""enclave_assurance_proven — wires assurance_level=enclave_attested to an actual verified EAT
(analogous to decision.py's action_outcome_proven: presence + binding makes the declared level
verifiable, not merely asserted). Additive; the EXPERIMENTAL enclave bridge is reached only when
the caller actually supplies an eat_jws — evalclaim.py's own import surface stays warning-free."""
import base64
import json
import subprocess
import sys
import unittest
import warnings
from pathlib import Path

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle.emit import generate_signer
from proofbundle.evalclaim import build_eval_claim, decode_eval_claim, emit_eval_receipt, enclave_assurance_proven, \
    issuer_fingerprint

REPO = Path(__file__).resolve().parents[1]


def _raw(k):
    return k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _claim(signer, assurance_level="self_attested"):
    claim, _ = build_eval_claim(
        suite="safety-refusal", suite_version="v1", metric="refusal_rate",
        comparator=">=", threshold="0.80", score="0.92", n=500,
        model_id="acme/model-x", dataset_id="acme/dataset-y",
        issuer=issuer_fingerprint(signer), timestamp="2026-07-01T12:00:00Z",
        model_salt=b"0" * 16, dataset_salt=b"1" * 16, assurance_level=assurance_level)
    return claim


class TestNotApplicable(unittest.TestCase):
    def test_none_when_not_enclave_attested(self):
        signer = generate_signer()
        claim = _claim(signer, "self_attested")
        bundle = emit_eval_receipt(claim, signer)
        decoded = decode_eval_claim(bundle)
        self.assertIsNone(enclave_assurance_proven(decoded, bundle))

    def test_none_for_every_non_enclave_level(self):
        signer = generate_signer()
        for level in ("self_attested", "third_party", "reproduced"):
            claim = _claim(signer, level)
            bundle = emit_eval_receipt(claim, signer)
            decoded = decode_eval_claim(bundle)
            self.assertIsNone(enclave_assurance_proven(decoded, bundle), f"level={level}")

    def test_none_for_non_dict_claim(self):
        self.assertIsNone(enclave_assurance_proven(None, {}))
        self.assertIsNone(enclave_assurance_proven("not-a-dict", {}))


class TestHonestyLimit(unittest.TestCase):
    def test_false_when_enclave_attested_but_no_eat_supplied(self):
        signer = generate_signer()
        claim = _claim(signer, "enclave_attested")
        bundle = emit_eval_receipt(claim, signer)
        decoded = decode_eval_claim(bundle)
        self.assertFalse(enclave_assurance_proven(decoded, bundle))
        # never upgrades/downgrades the signed claim itself
        self.assertEqual(decoded["assurance_level"], "enclave_attested")

    def test_false_when_verifier_pubkey_missing(self):
        signer = generate_signer()
        claim = _claim(signer, "enclave_attested")
        bundle = emit_eval_receipt(claim, signer)
        decoded = decode_eval_claim(bundle)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            self.assertFalse(enclave_assurance_proven(decoded, bundle, eat_jws="whatever"))

    def test_false_when_bundle_missing(self):
        signer = generate_signer()
        claim = _claim(signer, "enclave_attested")
        bundle = emit_eval_receipt(claim, signer)
        decoded = decode_eval_claim(bundle)
        self.assertFalse(enclave_assurance_proven(decoded, None, eat_jws="whatever", verifier_pubkey=b"\x00" * 32))


class TestGreenRoundtrip(unittest.TestCase):
    def _setup_enclave_attested(self):
        signer = generate_signer()
        claim = _claim(signer, "enclave_attested")
        bundle = emit_eval_receipt(claim, signer)
        decoded = decode_eval_claim(bundle)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from proofbundle.experimental.enclave import enclave_binding_for, issue_enclave_attestation
        binding = enclave_binding_for(bundle)
        verifier = generate_signer()
        eat = issue_enclave_attestation(binding, verifier, profile="p", tier="affirming")
        return decoded, bundle, verifier, eat

    def test_true_when_eat_verifies_and_binds(self):
        decoded, bundle, verifier, eat = self._setup_enclave_attested()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            proven = enclave_assurance_proven(decoded, bundle, eat_jws=eat, verifier_pubkey=_raw(verifier))
        self.assertTrue(proven)

    def test_true_respects_expected_profile(self):
        decoded, bundle, verifier, eat = self._setup_enclave_attested()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            ok = enclave_assurance_proven(decoded, bundle, eat_jws=eat, verifier_pubkey=_raw(verifier),
                                          expected_profile="p")
            bad = enclave_assurance_proven(decoded, bundle, eat_jws=eat, verifier_pubkey=_raw(verifier),
                                           expected_profile="wrong-profile")
        self.assertTrue(ok)
        self.assertFalse(bad)


class TestAdversarial(unittest.TestCase):
    def test_false_when_eat_binds_different_receipt(self):
        signer = generate_signer()
        claim = _claim(signer, "enclave_attested")
        bundle = emit_eval_receipt(claim, signer)
        decoded = decode_eval_claim(bundle)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from proofbundle.experimental.enclave import enclave_binding_for, issue_enclave_attestation
            from proofbundle.emit import emit_bundle
            other_bundle = emit_bundle(b"unrelated payload", generate_signer())
            binding = enclave_binding_for(other_bundle)   # binds a DIFFERENT bundle
            verifier = generate_signer()
            eat = issue_enclave_attestation(binding, verifier, profile="p", tier="affirming")
            proven = enclave_assurance_proven(decoded, bundle, eat_jws=eat, verifier_pubkey=_raw(verifier))
        self.assertFalse(proven)

    def test_false_when_verifier_key_wrong(self):
        signer = generate_signer()
        claim = _claim(signer, "enclave_attested")
        bundle = emit_eval_receipt(claim, signer)
        decoded = decode_eval_claim(bundle)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from proofbundle.experimental.enclave import enclave_binding_for, issue_enclave_attestation
            binding = enclave_binding_for(bundle)
            verifier = generate_signer()
            eat = issue_enclave_attestation(binding, verifier, profile="p", tier="affirming")
            proven = enclave_assurance_proven(decoded, bundle, eat_jws=eat,
                                              verifier_pubkey=_raw(generate_signer()))  # WRONG key
        self.assertFalse(proven)

    def test_false_for_malformed_bundle_no_raise(self):
        signer = generate_signer()
        claim = _claim(signer, "enclave_attested")
        bundle = emit_eval_receipt(claim, signer)
        decoded = decode_eval_claim(bundle)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            proven = enclave_assurance_proven(
                decoded, {"no": "payload_b64"}, eat_jws="whatever", verifier_pubkey=b"\x00" * 32)
        self.assertFalse(proven)

    def test_garbage_eat_no_raise(self):
        signer = generate_signer()
        claim = _claim(signer, "enclave_attested")
        bundle = emit_eval_receipt(claim, signer)
        decoded = decode_eval_claim(bundle)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            for bad in ("", "not.a.jws", "a.b", "x.y.z"):
                proven = enclave_assurance_proven(decoded, bundle, eat_jws=bad, verifier_pubkey=b"\x00" * 32)
                self.assertFalse(proven, f"bad eat {bad!r} must not raise and must not prove")


class TestExperimentalGatingPreserved(unittest.TestCase):
    def test_import_evalclaim_never_warns(self):
        # The lazy, function-local import must not turn evalclaim.py into an implicit dependency
        # on proofbundle.experimental at import time — this is checked at the process boundary
        # (a fresh interpreter) so no earlier test's import caches the warning-already-fired state.
        proc = subprocess.run(
            [sys.executable, "-W", "error::UserWarning", "-c",
             "import proofbundle.evalclaim"],
            capture_output=True, text=True, cwd=REPO,
            env={"PYTHONPATH": str(REPO / "src")})
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_not_added_to_top_level_surface(self):
        import proofbundle
        self.assertFalse(hasattr(proofbundle, "enclave_assurance_proven"))


class TestCliShowEvalIntegration(unittest.TestCase):
    def _run(self, *args):
        return subprocess.run([sys.executable, "-m", "proofbundle.cli", *args],
                              capture_output=True, text=True, cwd=REPO,
                              env={"PYTHONPATH": str(REPO / "src")})

    def test_show_eval_baseline_unaffected_when_not_enclave_attested(self):
        # Regression floor: a self_attested claim (the common case) must print exactly as before —
        # no new "attested" line at all.
        signer = generate_signer()
        claim = _claim(signer, "self_attested")
        bundle = emit_eval_receipt(claim, signer)
        import tempfile
        import os
        with tempfile.TemporaryDirectory() as d:
            rp = os.path.join(d, "receipt.json")
            json.dump(bundle, open(rp, "w"))
            out = self._run("show-eval", rp)
            self.assertEqual(out.returncode, 0)
            # No new "attested   ..." corroboration LINE — a bare substring check would false-positive
            # on the pre-existing self_attested warning text, which legitimately mentions
            # "enclave_attested" as an upgrade suggestion.
            lines = [ln for ln in out.stdout.splitlines() if ln.startswith("attested")]
            self.assertEqual(lines, [])

    def test_show_eval_reports_proven_and_not_corroborated(self):
        import os
        import tempfile
        signer = generate_signer()
        claim = _claim(signer, "enclave_attested")
        bundle = emit_eval_receipt(claim, signer)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from proofbundle.experimental.enclave import enclave_binding_for, issue_enclave_attestation
        binding = enclave_binding_for(bundle)
        verifier = generate_signer()
        eat = issue_enclave_attestation(binding, verifier, profile="p", tier="affirming")
        vkey = base64.b64encode(_raw(verifier)).decode()
        with tempfile.TemporaryDirectory() as d:
            rp = os.path.join(d, "receipt.json")
            json.dump(bundle, open(rp, "w"))
            ep = os.path.join(d, "att.eat")
            open(ep, "w").write(eat)

            no_eat = self._run("show-eval", rp)
            self.assertIn("NOT corroborated", no_eat.stdout)
            self.assertIn("issuer-declared only", no_eat.stdout)

            proven = self._run("show-eval", rp, "--eat", ep, "--verifier-key", vkey)
            self.assertIn("PROVEN", proven.stdout)

            wrong_key = self._run("show-eval", rp, "--eat", ep, "--verifier-key",
                                  base64.b64encode(_raw(generate_signer())).decode())
            self.assertIn("NOT corroborated", wrong_key.stdout)
            self.assertIn("did not verify", wrong_key.stdout)


if __name__ == "__main__":
    unittest.main()
