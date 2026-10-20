"""Addendum 46f (`KRAXO-CLOUD-N46F-NEU-STEMPEL-NUR-NACH-HERKUNFT-01`, Z309 / 6.2.0).

The 46d checkpoint re-stamp in the ``verify`` command ran UNCONDITIONALLY: after appending the
``checkpoint-authenticity`` check it called ``result.stamp_origin()`` even for a bundle whose signature
had failed, which ``verify_bundle`` had deliberately left UNSTAMPED (``bundle.py`` stamps only on
``sig_ok is True``). A re-stamp must authenticate nothing that was not authenticated before
(OA-a9986c2e64 A.1): a result with no origin must not gain one from the checkpoint step. 46f reads
``origin_authentic()`` BEFORE appending the checkpoint check and re-stamps only when it was already
authentic. Narrowing only; a genuine bundle still re-stamps and passes.

R (VERTRAG 2) — a genuine bundle with ONE flipped signature byte + a valid checkpoint + a policy: after
the run the result carries no origin (no stamp). Measured RED at the 46e head
932867f134d586c8d478b31147732de495ece8fb (``stamp_origin`` was called once on the unauthentic result),
GREEN at the 46f head (it is not called). The checkpoint is still valid because the Merkle root is
unchanged — only the payload signature byte differs — so this isolates the re-stamp, not the checkpoint.
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
from proofbundle import generate_signer
from proofbundle.cli import main
from proofbundle.errors import VerificationResult
from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt

_ORIGIN = "verifier.example/log"


def _raw_pub(signer) -> bytes:
    return signer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = main(argv)
    return rc, out.getvalue(), err.getvalue()


def _eval_bundle_and_signer():
    signer = generate_signer()
    claim, _ = build_eval_claim(
        suite="s", suite_version="1", metric="acc", comparator=">=", threshold="0.5",
        score="0.9", n=10, model_id="m", dataset_id="d", issuer="iss",
        timestamp="2026-07-09T10:00:00Z")
    bundle = emit_eval_receipt(claim, signer)
    return bundle, signer


def _trusting_policy(signer) -> dict:
    pub_b64 = base64.b64encode(_raw_pub(signer)).decode("ascii")
    return {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "n46f",
            "allowed_schema_versions": ["proofbundle/v0.1"],
            "allowed_issuers": [{"issuer": "iss", "public_key_b64": pub_b64, "kid": "k"}],
            "signature": {"allowed_algs": ["ed25519"], "require_expected_signer": True},
            "merkle": {"required_hash_alg": "sha256-rfc6962"},
            "assurance": {"minimum_level": "self_attested"}}


def _flip_one_sig_char(bundle: dict) -> None:
    """Change one base64 character of the payload signature: the Merkle root is untouched (the checkpoint
    still verifies), only the signature no longer matches, so sig_ok becomes False."""
    s = bundle["signature"]["sig_b64"]
    swapped = ("B" if s[0] != "B" else "C") + s[1:]
    bundle["signature"]["sig_b64"] = swapped


def _write_case(d, bundle, signer):
    root = base64.b64decode(bundle["merkle"]["root_b64"])
    tree_size = bundle["merkle"]["tree_size"]
    note = cp.sign_checkpoint(_ORIGIN, tree_size, root, signer, _ORIGIN)
    vkey = cp.vkey(_ORIGIN, _raw_pub(signer))
    bpath = os.path.join(d, "b.json")
    npath = os.path.join(d, "ckpt.txt")
    ppath = os.path.join(d, "p.json")
    with open(bpath, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(bundle))
    with open(npath, "w", encoding="utf-8") as fh:
        fh.write(note)
    with open(ppath, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(_trusting_policy(signer)))
    return bpath, npath, vkey, ppath


class AFailedSignatureNeverGainsOriginFromTheCheckpointRestamp(unittest.TestCase):
    """VERTRAG 2: a flipped-signature bundle + a valid checkpoint + a policy leaves the result WITHOUT an
    origin — stamp_origin is not called on it. RED at 932867f1 (called once), GREEN at head (not called)."""

    def _count_stamps_on_run(self, bundle, signer):
        calls = {"n": 0}
        original = VerificationResult.stamp_origin

        def _spy(self):   # noqa: ANN001 - test spy
            calls["n"] += 1
            return original(self)

        with tempfile.TemporaryDirectory() as d:
            bpath, npath, vkey, ppath = _write_case(d, bundle, signer)
            VerificationResult.stamp_origin = _spy   # type: ignore[assignment]
            try:
                rc, out, err = _run(["verify", bpath, "--policy", ppath, "--trusted-checkpoint", npath,
                                     "--checkpoint-vkey", vkey, "--json"])
            finally:
                VerificationResult.stamp_origin = original   # type: ignore[assignment]
        return rc, out, err, calls["n"]

    def test_a_flipped_signature_bundle_is_not_restamped(self):
        bundle, signer = _eval_bundle_and_signer()
        _flip_one_sig_char(bundle)
        rc, out, err, stamps = self._count_stamps_on_run(bundle, signer)
        self.assertEqual(rc, 1, f"a flipped-signature bundle fails the crypto verdict (exit 1); got {rc}\n{out}\n{err}")
        self.assertEqual(
            stamps, 0,
            "a result verify_bundle left unstamped (signature failed) must NOT be re-stamped after the "
            f"checkpoint-authenticity add (46f); stamp_origin was called {stamps} time(s)")

    def test_the_genuine_control_is_restamped_and_passes(self):
        # VERTRAG 3 control: the unflipped bundle + the same valid checkpoint + policy still re-stamps
        # (origin was authentic before the add), so POLICY OK and exit 0 are preserved (the 46d behaviour).
        bundle, signer = _eval_bundle_and_signer()
        rc, out, err, stamps = self._count_stamps_on_run(bundle, signer)
        report = json.loads(out) if out.strip().startswith("{") else {}
        self.assertEqual(rc, 0, f"a genuine bundle+checkpoint+policy must verify (exit 0); got {rc}\n{out}\n{err}")
        self.assertIs(report.get("policy_ok"), True, "policy_ok must stay True for the genuine control")
        self.assertGreaterEqual(stamps, 1, "the genuine result is stamped (verify_bundle) and re-stamped (CLI)")
        self.assertNotIn("result_origin", out + err,
                         "the genuine re-stamp must still cover the checkpoint check (no policy:result_origin)")


class TheRestampGateIsFailClosed(unittest.TestCase):
    """VERTRAG 1/3 at the unit level: the exact CLI gate — read origin_authentic() BEFORE the add, re-stamp
    only if it was True — neither invents origin for an unauthentic result nor weakens an authentic one."""

    def test_an_unauthentic_result_stays_unauthentic(self):
        # A result verify_bundle never stamped (verified_origin None): origin_authentic() is False, so the
        # gate skips the re-stamp and the result stays without origin even after the checkpoint check is added.
        r = VerificationResult()
        r.add("ed25519-signature", False, "signature did not verify")
        was_authentic = r.origin_authentic()          # the CLI reads this BEFORE the add
        self.assertFalse(was_authentic, "a never-stamped result is not origin_authentic")
        r.add("checkpoint-authenticity", True, "ok")
        if was_authentic:                              # the 46f gate
            r.stamp_origin()
        self.assertFalse(r.origin_authentic(),
                         "a result unauthentic before the checkpoint add must not become authentic after it")

    def test_an_authentic_result_is_restamped_and_a_later_mutation_still_fails(self):
        # An authentic result (stamped) is re-stamped over the full list, and a check mutated AFTER the
        # re-stamp is still rejected — the narrowing does not weaken the 46c/46d coverage.
        r = VerificationResult()
        r.add("ed25519-signature", True, "ok")
        r.stamp_origin()                               # the verify_bundle stamp (authentic)
        was_authentic = r.origin_authentic()
        self.assertTrue(was_authentic, "a freshly stamped result is origin_authentic")
        r.add("checkpoint-authenticity", True, "ok")
        if was_authentic:
            r.stamp_origin()
        self.assertTrue(r.origin_authentic(), "the authentic result is re-stamped over the full check list")
        r.checks[-1].ok = False                        # mutate a check AFTER the re-stamp (Check is a dataclass)
        self.assertFalse(r.origin_authentic(),
                         "a check mutated after the re-stamp must still break the origin token")


if __name__ == "__main__":
    unittest.main()
