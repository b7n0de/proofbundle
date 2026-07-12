"""WP3 (v2-audit) — named trust-policy profiles shipped with the package.

Every profile in ``proofbundle.policy_profiles.PROFILE_NAMES`` MUST be a real, loadable trust policy:
it loads (``load_policy``), lints clean (``lint_policy(...).ok`` — a real pin exists, so it is not the
TP1 vacuous-policy trap), and ``explain_policy`` lists at least one pin. Every profile deliberately
pins no signer identity (that is deployment-specific), so each is expected to carry EXACTLY the
"attributes to nobody" warning and nothing else — a regression that accidentally makes a profile
vacuous (zero pins) or unsatisfiable (e.g. ``require_expected_signer`` with no ``allowed_issuers``)
must fail these tests, not slip through as a syntactically-valid-but-useless JSON file.
"""
import contextlib
import io
import json
import os
import unittest

from proofbundle import emit_bundle, generate_signer
from proofbundle.cli import main
from proofbundle.policy import PolicyError, explain_policy, lint_policy, load_policy
from proofbundle.policy_profiles import PROFILE_ID_PREFIX, list_profiles, profile_path, resolve_policy_source


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = main(argv)
    return rc, out.getvalue(), err.getvalue()


class TestNamedProfilesLoadExplainLint(unittest.TestCase):
    """Each shipped profile, exercised individually (subTest) so one broken profile does not hide
    another's failure."""

    def test_every_profile_loads_explains_and_lints_clean(self):
        self.assertEqual(list_profiles(),
                         ["decision-receipt-v1", "research-preview-v1", "strict-eval-v1", "strict-prereg-v1"])
        for name in list_profiles():
            with self.subTest(profile=name):
                path = profile_path(name)
                self.assertTrue(os.path.isfile(path), f"{name} -> {path} is not a real file")
                policy = load_policy(path)   # raises PolicyError (fail-closed) on any structural defect
                self.assertEqual(policy.get("policy_id"), f"{PROFILE_ID_PREFIX}{name}")
                pins = explain_policy(policy)
                self.assertTrue(pins, f"{name} pins nothing (would be a vacuous POLICY: OK)")
                res = lint_policy(policy)
                self.assertTrue(res["ok"], f"{name} failed lint: {res['errors']}")
                self.assertEqual(res["errors"], [])
                # Deliberate design (module docstring): no profile ships a pinned signer identity, so
                # every one of them carries EXACTLY the attributes-to-nobody warning — not zero (that
                # would mean the warning silently stopped firing) and not more (an unexpected second
                # warning would mean something else about the profile quietly broke).
                self.assertEqual(len(res["warnings"]), 1)
                self.assertIn("attributes to nobody", res["warnings"][0])
                # A profile is a TEMPLATE a relying party completes with their own signer pin; strict
                # lint (which promotes attributes-to-nobody to an error) must therefore fail on the
                # profile AS SHIPPED — this is the honest, documented state, not a bug.
                strict = lint_policy(policy, strict=True)
                self.assertFalse(strict["ok"])

    def test_decision_receipt_profile_needs_v0_2_schema(self):
        policy = load_policy(profile_path("decision-receipt-v1"))
        self.assertEqual(policy["schema"], "proofbundle/trust-policy/v0.2")
        self.assertIn("decision_receipt", policy)

    def test_strict_prereg_profile_pins_a_real_anchor_requirement(self):
        # Regression guard for the explain_policy anchors fix this profile exercises: the anchors
        # section is a REAL pin the CLI's --policy path enforces (see _cmd_verify), so it must show up
        # in explain_policy — otherwise `policy lint` on an anchors-only policy would wrongly call it
        # vacuous even though `verify --policy` genuinely gates exit 3 on it.
        policy = load_policy(profile_path("strict-prereg-v1"))
        self.assertEqual(policy["schema"], "proofbundle/trust-policy/v0.2")
        pins = explain_policy(policy)
        self.assertTrue(any("external time anchor required" in p for p in pins))
        self.assertTrue(any("preRegistration" in p for p in pins))


class TestExplainPolicyAnchorsPin(unittest.TestCase):
    """Direct unit coverage of the explain_policy() anchors fix, independent of any named profile."""

    def test_anchors_only_policy_is_not_vacuous(self):
        policy = load_policy({
            "schema": "proofbundle/trust-policy/v0.2", "policy_id": "urn:test:anchors-only",
            "anchors": {"require_anchor": "rfc3161-tsa", "require_anchor_target": "receipt",
                       "allow_pending": True},
        })
        pins = explain_policy(policy)
        self.assertTrue(pins)
        line = next(p for p in pins if "external time anchor required" in p)
        self.assertIn("rfc3161-tsa", line)
        self.assertIn("receipt", line)
        self.assertIn("pending accepted", line)
        res = lint_policy(policy)
        self.assertTrue(res["ok"])
        self.assertNotIn("pins nothing", " ".join(res["errors"]))

    def test_policy_with_no_anchors_section_shows_no_anchor_pin(self):
        policy = load_policy({"schema": "proofbundle/trust-policy/v0.1", "policy_id": "urn:test:none",
                              "allowed_schema_versions": ["proofbundle/v0.1"]})
        pins = explain_policy(policy)
        self.assertFalse(any("anchor" in p for p in pins))


class TestResolvePolicySource(unittest.TestCase):
    def test_bare_name_resolves_to_packaged_profile(self):
        resolved = resolve_policy_source("strict-eval-v1")
        self.assertTrue(os.path.isfile(resolved))
        self.assertEqual(load_policy(resolved)["policy_id"], "proofbundle-policy/strict-eval-v1")

    def test_prefixed_name_resolves_the_same_profile(self):
        self.assertEqual(resolve_policy_source("strict-eval-v1"),
                         resolve_policy_source("proofbundle-policy/strict-eval-v1"))

    def test_unknown_name_is_returned_unchanged_and_load_policy_still_fails_closed(self):
        unresolved = resolve_policy_source("not-a-real-profile-or-file")
        self.assertEqual(unresolved, "not-a-real-profile-or-file")
        with self.assertRaises(PolicyError):
            load_policy(unresolved)

    def test_a_real_local_file_always_wins_over_a_same_named_profile(self):
        # A relying party's own file must never be silently shadowed by a packaged profile of the
        # same name (No-Fake: the CLI must load what the user pointed it at).
        import tempfile
        fd, path = tempfile.mkstemp(suffix=".json")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump({"schema": "proofbundle/trust-policy/v0.1",
                          "policy_id": "urn:local:override",
                          "allowed_schema_versions": ["proofbundle/v0.1"]}, f)
            local_dir = os.path.dirname(path)
            local_name = os.path.basename(path)
            cwd = os.getcwd()
            os.chdir(local_dir)
            try:
                resolved = resolve_policy_source(local_name)
            finally:
                os.chdir(cwd)
            self.assertEqual(resolved, local_name)
            self.assertEqual(load_policy(os.path.join(local_dir, local_name))["policy_id"],
                             "urn:local:override")
        finally:
            os.unlink(path)


class TestCliIntegration(unittest.TestCase):
    def test_policy_explain_by_name(self):
        rc, out, _ = _run(["policy", "explain", "--json", "research-preview-v1"])
        self.assertEqual(rc, 0)
        data = json.loads(out)
        self.assertEqual(data["policy_id"], "proofbundle-policy/research-preview-v1")
        self.assertTrue(data["pins"])

    def test_policy_lint_by_name(self):
        rc, out, _ = _run(["policy", "lint", "--json", "strict-eval-v1"])
        self.assertEqual(rc, 0)
        self.assertTrue(json.loads(out)["ok"])

    def test_policy_list_profiles(self):
        rc, out, _ = _run(["policy", "list-profiles", "--json"])
        self.assertEqual(rc, 0)
        rows = json.loads(out)
        names = {r["name"] for r in rows}
        self.assertEqual(names, set(list_profiles()))
        for row in rows:
            self.assertGreater(row["pin_count"], 0)

    def test_verify_accepts_a_named_profile(self):
        signer = generate_signer()
        bundle = emit_bundle(b"named-profile-e2e", signer)
        import tempfile
        fd, bpath = tempfile.mkstemp(suffix=".json")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(bundle, f)
            rc, out, _ = _run(["verify", "--json", bpath, "--policy", "research-preview-v1"])
        finally:
            os.unlink(bpath)
        self.assertEqual(rc, 0)   # only the attributes-to-nobody WARNING, not a failure
        data = json.loads(out)
        self.assertTrue(data["policy_ok"])
        self.assertEqual(data["policy_id"], "proofbundle-policy/research-preview-v1")

    def test_verify_unknown_policy_name_is_a_clean_exit_2(self):
        signer = generate_signer()
        bundle = emit_bundle(b"unknown-profile", signer)
        import tempfile
        fd, bpath = tempfile.mkstemp(suffix=".json")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(bundle, f)
            rc, _, err = _run(["verify", bpath, "--policy", "no-such-profile-xyz"])
        finally:
            os.unlink(bpath)
        self.assertEqual(rc, 2)
        self.assertIn("ERROR", err)


if __name__ == "__main__":
    unittest.main()
