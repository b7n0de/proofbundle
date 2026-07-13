"""WP-C1/C2 — the verify PATH binds an sd_jwt_vc to its bundle and refuses unauthenticated disclosures.

check_binds_bundle is unit-tested in test_sdjwt_issue.py; here we test that verify_bundle actually WIRES
it (C-1) and that an unsigned sd_jwt_vc fails crypto (C-2). Effect-grounded: we run the real CLI verify
and assert the exit code, the named check, its reason string, and the derived sd_jwt_ok summary field.
"""
import base64
import contextlib
import io
import json
import os
import tempfile
import unittest

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from pathlib import Path

from proofbundle import emit_bundle, generate_signer, verify_bundle
from proofbundle.cli import main
from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt
from proofbundle.sdjwt_issue import issue_sd_jwt, present_with_key_binding

_REPO = Path(__file__).resolve().parents[1]
_IAT = 1_780_000_000


def _raw_pub(key) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _eval_bundle_with_sd_jwt(*, bind_root: bool, signed: bool):
    """An eval-claim bundle carrying an sd_jwt_vc. ``bind_root`` commits the SD-JWT to THIS bundle's
    merkle root (bound) or to a wrong root (unbound); ``signed`` supplies the issuer key or not."""
    signer = generate_signer()
    holder = generate_signer()
    ev_claim, _ = build_eval_claim(
        suite="safety", suite_version="1", metric="acc", comparator=">=", threshold="0.8",
        score="0.9", n=100, model_id="m", dataset_id="d", issuer="placeholder",
        timestamp="2026-07-09T10:00:00Z", assurance_level="reproduced")
    # Ed25519 is deterministic (RFC 8032) → re-emitting the same payload yields the same merkle root.
    plain = emit_eval_receipt(ev_claim, signer)
    real_root = (plain.get("merkle") or {}).get("root_b64")
    payload_claim = json.loads(base64.b64decode(plain["payload_b64"]))
    sd_claim = {"passed": True, "threshold": "0.8", "comparator": ">=", "suite": "safety",
                "issuer": payload_claim["issuer"]}
    commit_root = real_root if bind_root else "d3Jvbmc="   # "wrong"
    compact = issue_sd_jwt(sd_claim, signer, root_b64=commit_root, exact_score="0.9",
                           holder_public_key=_raw_pub(holder))
    presented = present_with_key_binding(compact, holder, aud="v.example", nonce="n", iat=_IAT)
    vc = {"compact": presented}
    if signed:
        vc["issuer_public_key_b64"] = base64.b64encode(_raw_pub(signer)).decode("ascii")
    bundle = emit_eval_receipt(ev_claim, signer, sd_jwt=vc)
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(bundle, f)
    return path


def _verify_json(path):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = main(["verify", "--json", path])
    return rc, json.loads(out.getvalue())


class TestSdJwtVerifyBinding(unittest.TestCase):
    def _checks(self, data):
        return {c["name"]: c for c in data["checks"]}

    def test_signed_and_bound_passes(self):   # C-1 positive control
        path = _eval_bundle_with_sd_jwt(bind_root=True, signed=True)
        try:
            rc, data = _verify_json(path)
        finally:
            os.unlink(path)
        self.assertEqual(rc, 0)
        checks = self._checks(data)
        self.assertTrue(checks["sd-jwt-bundle-binding"]["ok"])
        self.assertTrue(data["sd_jwt_ok"])

    def test_signed_but_unbound_fails_with_reason(self):   # C-1: cross-receipt substitution
        path = _eval_bundle_with_sd_jwt(bind_root=False, signed=True)
        try:
            rc, data = _verify_json(path)
        finally:
            os.unlink(path)
        self.assertEqual(rc, 1)                                # crypto fail, not a pass-with-warning
        checks = self._checks(data)
        self.assertTrue(checks["sd-jwt-issuer-signature"]["ok"])   # signature IS valid…
        self.assertFalse(checks["sd-jwt-bundle-binding"]["ok"])    # …but it binds the wrong bundle
        self.assertIn("unbound", checks["sd-jwt-bundle-binding"]["detail"])
        self.assertFalse(data["sd_jwt_ok"])                    # summary must NOT read True (No-Fake, WP-C1)

    def test_unsigned_fails_with_reason(self):   # C-2: unauthenticated disclosures
        path = _eval_bundle_with_sd_jwt(bind_root=True, signed=False)
        try:
            rc, data = _verify_json(path)
        finally:
            os.unlink(path)
        self.assertEqual(rc, 1)
        checks = self._checks(data)
        self.assertFalse(checks["sd-jwt-issuer-signature"]["ok"])
        self.assertIn("unsigned", checks["sd-jwt-issuer-signature"]["detail"])
        self.assertFalse(data["sd_jwt_ok"])
        self.assertFalse(data["sd_jwt_issuer_verified"])

    def test_forged_issuer_identity_fails(self):   # C-1 2nd-lens: self-signed, discloses a trusted issuer
        # Attacker self-signs the SD-JWT with their OWN key but names the trusted bundle issuer in the
        # always-open `issuer` claim (and binds the real root + forges exact_score). The issuer signature
        # is VALID under the attacker key — only the key↔claimed-issuer identity check catches it.
        signer = generate_signer()          # the trusted bundle signer
        att = generate_signer()             # the attacker's own key
        holder = generate_signer()
        ev_claim, _ = build_eval_claim(
            suite="safety", suite_version="1", metric="acc", comparator=">=", threshold="0.8",
            score="0.9", n=100, model_id="m", dataset_id="d", issuer="placeholder",
            timestamp="2026-07-09T10:00:00Z", assurance_level="reproduced")
        plain = emit_eval_receipt(ev_claim, signer)
        real_root = (plain.get("merkle") or {}).get("root_b64")
        trusted_issuer = json.loads(base64.b64decode(plain["payload_b64"]))["issuer"]
        forged = {"passed": True, "threshold": "0.8", "comparator": ">=", "suite": "safety",
                  "issuer": trusted_issuer}   # names the trusted issuer…
        compact = issue_sd_jwt(forged, att, root_b64=real_root, exact_score="0.99999",   # …but signed by att
                               holder_public_key=_raw_pub(holder))
        presented = present_with_key_binding(compact, holder, aud="v", nonce="n", iat=_IAT)
        vc = {"compact": presented, "issuer_public_key_b64": base64.b64encode(_raw_pub(att)).decode("ascii")}
        bundle = emit_eval_receipt(ev_claim, signer, sd_jwt=vc)
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump(bundle, f)
        try:
            rc, data = _verify_json(path)
        finally:
            os.unlink(path)
        self.assertEqual(rc, 1)
        checks = self._checks(data)
        self.assertTrue(checks["sd-jwt-issuer-signature"]["ok"])      # signature IS valid (under att)…
        self.assertFalse(checks["sd-jwt-issuer-identity"]["ok"])      # …but by the wrong signer
        self.assertIn("issuer-key-mismatch", checks["sd-jwt-issuer-identity"]["detail"])
        self.assertFalse(data["sd_jwt_ok"])

    def test_missing_eval_field_no_raw_traceback(self):   # C-1 robustness: attacker-shaped incomplete claim
        # A signed eval-claim payload missing a required field (here: no `passed`) must NOT crash the binding
        # check with a raw KeyError — verify must return a documented exit code, never a traceback.
        att = generate_signer()
        holder = generate_signer()
        bad_payload = json.dumps({"schema": "proofbundle/eval-claim/v0.1",
                                  "issuer": "ed25519:" + base64.b64encode(_raw_pub(att)).decode("ascii"),
                                  "suite": "safety", "comparator": ">=", "threshold": "0.8"}).encode()
        sd_claim = {"passed": True, "threshold": "0.8", "comparator": ">=", "suite": "safety",
                    "issuer": "ed25519:" + base64.b64encode(_raw_pub(att)).decode("ascii")}
        compact = issue_sd_jwt(sd_claim, att, root_b64="cm9vdA==", exact_score="0.9",
                               holder_public_key=_raw_pub(holder))
        presented = present_with_key_binding(compact, holder, aud="v", nonce="n", iat=_IAT)
        vc = {"compact": presented, "issuer_public_key_b64": base64.b64encode(_raw_pub(att)).decode("ascii")}
        from proofbundle import emit_bundle  # noqa: PLC0415
        bundle = emit_bundle(bad_payload, att, sd_jwt_vc=vc)
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump(bundle, f)
        try:
            rc, _ = _verify_json(path)   # must not raise
        finally:
            os.unlink(path)
        self.assertIn(rc, (1, 2))        # documented failure/malformed, never a crash


if __name__ == "__main__":
    unittest.main()


class TestN1UnbindableEvalSdJwt(unittest.TestCase):
    """N1 (audit 2026-07-13, L1 live PoC): an EVAL SD-JWT (always-open passed/threshold/comparator/suite/
    root) grafted onto a NON-eval-claim payload has nothing to bind to and is refused fail-closed. A
    GENERIC SD-JWT-VC (iss/vct, no eval fields) carries no eval claim to substitute and stays in scope."""

    @staticmethod
    def _raw(k):
        return k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def test_eval_sd_jwt_on_non_eval_payload_is_refused(self):
        signer = generate_signer()
        sd_claim = {"passed": True, "threshold": "0.8", "comparator": ">=", "suite": "safety",
                    "issuer": "ed25519:" + base64.b64encode(self._raw(signer)).decode()}
        # issued with a root from ELSEWHERE (the graft) — issuer-VALID but bound to no real bundle
        compact = issue_sd_jwt(sd_claim, signer, root_b64="c29tZS1vdGhlci1yb290", exact_score="0.9")
        vc = {"compact": compact, "issuer_public_key_b64": base64.b64encode(self._raw(signer)).decode()}
        bundle = emit_bundle(b'{"x":1}', signer, sd_jwt_vc=vc)   # NON-eval-claim payload
        r = verify_bundle(bundle)
        by = {c.name: c.ok for c in r.checks}
        self.assertIn("sd-jwt-bundle-binding", by, "an unbindable eval SD-JWT must add a FAILING binding check")
        self.assertFalse(by["sd-jwt-bundle-binding"])
        self.assertFalse(r.ok, "an unbindable eval SD-JWT graft must fail the whole bundle (CRYPTO: FAILED)")

    def test_generic_sd_jwt_vc_on_non_eval_payload_stays_out_of_scope(self):
        # examples/example_bundle.json is a generic SD-JWT-VC (iss/vct, no eval fields) on a non-eval
        # payload and MUST still verify — N1 refuses only the eval-carrying graft, never a generic VC.
        bundle = json.loads((_REPO / "examples" / "example_bundle.json").read_text())
        r = verify_bundle(bundle)
        self.assertTrue(r.ok, "a generic SD-JWT-VC on a non-eval payload must stay valid (backward-compatible)")
        self.assertNotIn("sd-jwt-bundle-binding", [c.name for c in r.checks],
                         "a generic VC carries no eval fields → the eval binding check is skipped")

    @staticmethod
    def _sd_jwt(signer, payload: dict) -> str:
        """A minimal signed, disclosure-free compact SD-JWT with an arbitrary always-open payload —
        mirrors sdjwt_issue's JWT signing so a test can shape the always-open claims directly."""
        from proofbundle.sdjwt_issue import _b64url  # noqa: PLC0415
        header = {"alg": "EdDSA", "typ": "dc+sd-jwt"}
        signing_input = _b64url(json.dumps(header).encode()) + "." + _b64url(json.dumps(payload).encode())
        sig = signer.sign(signing_input.encode("ascii"))
        return signing_input + "." + _b64url(sig) + "~"

    def test_generic_vc_with_marker_word_but_no_receipt_stays_valid(self):
        # L1 pre-land review F2: the OLD discriminator was a word-match on {passed,threshold,comparator,
        # suite,root}; a legitimate generic VC that merely carries one of those common words (here an exam
        # credential with `passed`) but NO receipt.root_b64 commitment must NOT be false-refused.
        signer = generate_signer()
        payload = {"iss": "https://university.example", "vct": "https://university.example/exam-credential",
                   "iat": _IAT, "passed": True, "suite": "chemistry-101"}   # marker WORDS, no receipt commitment
        vc = {"compact": self._sd_jwt(signer, payload),
              "issuer_public_key_b64": base64.b64encode(self._raw(signer)).decode()}
        bundle = emit_bundle(b'{"generic":"vc"}', signer, sd_jwt_vc=vc)   # non-eval payload
        r = verify_bundle(bundle)
        self.assertTrue(r.ok, "a generic VC with a marker WORD but no receipt commitment must stay valid")
        self.assertNotIn("sd-jwt-bundle-binding", [c.name for c in r.checks])

    def test_eval_root_commitment_without_open_markers_is_refused(self):
        # L1 pre-land review F1/F3: the hardened discriminator keys on the real substitution vector
        # (receipt.root_b64), NOT on passed/threshold — so an eval SD-JWT whose only always-open eval signal
        # is the root commitment (its pass/threshold facts moved into disclosures) is STILL refused on a
        # non-eval payload.
        signer = generate_signer()
        payload = {"iss": "ed25519:x", "vct": "https://b7n0de.com/proofbundle/vct/eval-receipt/v1",
                   "iat": _IAT, "receipt": {"root_b64": "c29tZS1vdGhlci1yb290"}}   # only the root commitment
        vc = {"compact": self._sd_jwt(signer, payload),
              "issuer_public_key_b64": base64.b64encode(self._raw(signer)).decode()}
        bundle = emit_bundle(b'{"x":1}', signer, sd_jwt_vc=vc)   # NON-eval payload
        r = verify_bundle(bundle)
        by = {c.name: c.ok for c in r.checks}
        self.assertIn("sd-jwt-bundle-binding", by, "a root-committing eval SD-JWT graft must add a FAILING check")
        self.assertFalse(by["sd-jwt-bundle-binding"])
        self.assertFalse(r.ok, "an unbindable eval root commitment must fail the whole bundle")

    def test_empty_root_commitment_still_refused(self):
        # L1 pre-land audit F3: an always-open receipt.root_b64 == "" also carries the eval-binding SHAPE and
        # must not evade N1 (the earlier bool()-non-empty guard let it through). A generic VC has no receipt
        # object at all, so firing on a present-but-empty root never false-refuses one.
        signer = generate_signer()
        payload = {"iss": "ed25519:x", "vct": "https://b7n0de.com/proofbundle/vct/eval-receipt/v1",
                   "iat": _IAT, "receipt": {"root_b64": ""}}
        vc = {"compact": self._sd_jwt(signer, payload),
              "issuer_public_key_b64": base64.b64encode(self._raw(signer)).decode()}
        bundle = emit_bundle(b'{"x":1}', signer, sd_jwt_vc=vc)
        r = verify_bundle(bundle)
        by = {c.name: c.ok for c in r.checks}
        self.assertIn("sd-jwt-bundle-binding", by)
        self.assertFalse(by["sd-jwt-bundle-binding"])
        self.assertFalse(r.ok)
