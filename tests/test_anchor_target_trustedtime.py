"""WP-A1 / WP-A2 / WP-A7 — anchor TARGET gate, structured trustedTime, and small regressions.

A1: `--require-anchor` matched the TYPE only — a `receipt` anchor stamped today satisfied a
relying party who demanded backdating protection (`preRegistration`). Existence-now proves nothing
about existence-before-the-run. Now: matched = ok ∧ ¬warn ∧ type ∧ TARGET.

A2: a verifier could not build a time-window policy (t1 < run < t2) because the trusted time lived
only in detail prose. Now `results[]` carries `trustedTime` — `{source: rfc3161_gen_time, time,
tz}` or `{source: bitcoin_block, height}` — ONLY when the proof genuinely carries it, never
guessed, never taken from the informative `anchoredAt`.
"""
import base64
import json
import pathlib
import unittest

from proofbundle.anchors import verify_anchors
from proofbundle.anchors_markovian import register
from proofbundle.errors import BundleFormatError

_FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "markovian_anchor_confirmed.json"


def _confirmed_anchor():
    register()
    anchor = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    root = base64.b64decode(anchor["canonicalRoot"])
    return anchor, {"preRegistration": root, "receipt": b"\x01" * 32}


class TestTargetGate(unittest.TestCase):
    def test_matching_target_satisfies(self):
        anchor, roots = _confirmed_anchor()
        res = verify_anchors([anchor], target_roots=roots, require="any",
                             require_target="preRegistration")
        self.assertTrue(res["require_met"])
        self.assertEqual(res["status"], "PASS")

    def test_wrong_target_fails_the_requirement(self):
        # The A1 acceptance case: a verifying preRegistration anchor exists, but the relying party
        # demands a RECEIPT anchor — the requirement is NOT met (and vice versa: a receipt anchor
        # can never satisfy a preRegistration demand).
        anchor, roots = _confirmed_anchor()
        res = verify_anchors([anchor], target_roots=roots, require="any",
                             require_target="receipt")
        self.assertFalse(res["require_met"])
        self.assertIn("target", res["detail"])

    def test_target_requirement_implies_anchor_requirement(self):
        anchor, roots = _confirmed_anchor()
        res = verify_anchors([anchor], target_roots=roots, require_target="preRegistration")
        self.assertTrue(res.get("require_met"), "require_target alone must arm the gate")
        empty = verify_anchors([], target_roots=roots, require_target="preRegistration")
        self.assertFalse(empty["require_met"])

    def test_unknown_target_value_fails_closed(self):
        anchor, roots = _confirmed_anchor()
        with self.assertRaises(BundleFormatError):
            verify_anchors([anchor], target_roots=roots, require="any",
                           require_target="somewhere")


class TestTrustedTime(unittest.TestCase):
    def test_confirmed_bitcoin_anchor_reports_structured_height(self):
        anchor, roots = _confirmed_anchor()
        res = verify_anchors([anchor], target_roots=roots)
        entry = res["results"][0]
        self.assertTrue(entry["ok"])
        self.assertEqual(entry["trustedTime"]["source"], "bitcoin_block")
        self.assertEqual(entry["trustedTime"]["height"], 956857)
        self.assertNotIn("time", entry["trustedTime"],
                         "a block HEIGHT is the native unit — no wall-clock guess")

    def test_anchored_at_never_feeds_trusted_time(self):
        # anchoredAt is informative; tampering it must change NEITHER the verdict NOR trustedTime
        # (the A7 'anchoredAt-Tamper ⇒ Verdikt identisch' regression).
        anchor, roots = _confirmed_anchor()
        base = verify_anchors([anchor], target_roots=roots)["results"][0]
        tampered = dict(anchor, anchoredAt="1999-01-01T00:00:00Z")
        after = verify_anchors([tampered], target_roots=roots)["results"][0]
        self.assertEqual((base["ok"], base["warn"], base["status"], base.get("trustedTime")),
                         (after["ok"], after["warn"], after["status"], after.get("trustedTime")))

    def test_unconfirmed_anchor_carries_no_trusted_time(self):
        anchor, roots = _confirmed_anchor()
        stripped = dict(anchor)
        stripped["frozen"] = {}   # no block header supplied → not confirmed → no trustedTime
        res = verify_anchors([stripped], target_roots=roots)["results"][0]
        self.assertFalse(res["ok"])
        self.assertNotIn("trustedTime", res)


class TestA7Regressions(unittest.TestCase):
    def test_anchored_at_wrong_type_fails_closed(self):
        anchor, roots = _confirmed_anchor()
        bad = dict(anchor, anchoredAt=12345)
        res = verify_anchors([bad], target_roots=roots)["results"][0]
        self.assertFalse(res["ok"])
        self.assertIn("anchoredAt", res["detail"])

    def test_bundle_with_statement_target_is_malformed_exit_two(self):
        # A v0.1 BUNDLE's own anchors[] may only use receipt|preRegistration (SPEC §7i);
        # target:"statement" applies exclusively to detached decision-receipt evidence.
        import contextlib
        import io
        import os
        import tempfile
        from proofbundle import emit_bundle, generate_signer
        from proofbundle.cli import main
        bundle = emit_bundle(b'{"x":1}', generate_signer())
        bundle["anchors"] = [{"type": "opentimestamps", "target": "statement",
                              "canonicalRoot": base64.b64encode(b"\x00" * 32).decode(),
                              "proof": base64.b64encode(b"junk").decode()}]
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump(bundle, f)
        try:
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rc = main(["verify", path, "--require-anchor"])
        finally:
            os.unlink(path)
        self.assertEqual(rc, 2, "a bundle carrying target:'statement' is malformed (schema enum)")


class TestPolicyAnchorsSection(unittest.TestCase):
    def _policy(self, **anchors):
        return {"schema": "proofbundle/trust-policy/v0.2", "policy_id": "urn:t", "anchors": anchors}

    def test_v01_schema_rejects_anchors_section(self):
        from proofbundle.policy import PolicyError, load_policy
        with self.assertRaises(PolicyError):
            load_policy({"schema": "proofbundle/trust-policy/v0.1", "policy_id": "x",
                         "anchors": {"require_anchor": "any"}})

    def test_bad_target_value_rejected(self):
        from proofbundle.policy import PolicyError, load_policy
        with self.assertRaises(PolicyError):
            load_policy(self._policy(require_anchor_target="elsewhere"))

    def test_policy_supplies_the_requirement_and_conflicts_are_ambiguous(self):
        import contextlib
        import io
        import os
        import tempfile
        from proofbundle import emit_bundle, generate_signer
        from proofbundle.cli import main
        bundle = emit_bundle(b'{"x":1}', generate_signer())   # no anchors at all
        fd, bpath = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump(bundle, f)
        fd, ppath = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump(self._policy(require_anchor="any", require_anchor_target="preRegistration"), f)
        try:
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                rc = main(["verify", bpath, "--policy", ppath])
            self.assertEqual(rc, 3, "policy-armed anchor requirement unmet → exit 3")
            self.assertIn("ANCHOR: REQUIRED_NOT_MET", out.getvalue())
            # conflicting CLI flag → ambiguity, exit 2 (mirrors the expected_aud rule)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                rc2 = main(["verify", bpath, "--policy", ppath, "--anchor-target", "receipt"])
            self.assertEqual(rc2, 2)
        finally:
            os.unlink(bpath), os.unlink(ppath)


if __name__ == "__main__":
    unittest.main()
