"""AP-2 §6.5 — policy TEMPLATES, instantiation and the deployment-ready lifecycle.

A relying party must not be able to depend on a raw template for an automation decision without the
output and exit behaviour making that visible (§6.6). These are the eight mandatory regressions from
the hardening spec §6.5, effect-grounded against the real CLI and library:

    template_profile_is_not_deployment_ready
    template_without_identity_overlay_never_safe_for_automation
    instantiated_profile_pins_signer
    instantiated_profile_pins_root_or_checkpoint_when_required
    expired_instantiated_profile_fails
    unknown_identity_overlay_field_fails
    alias_resolution_warns_and_resolves
    lint_strict_fails_on_raw_template
"""
import base64
import contextlib
import io
import json
import os
import tempfile
import unittest

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle.cli import main
from proofbundle.emit import generate_signer
from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt
from proofbundle.policy import PolicyError, lint_policy, load_policy, policy_expired
from proofbundle.policy_profiles import (
    PROFILE_ALIASES, canonical_profile_name, instantiate_template, list_profiles, profile_path,
)

_TEMPLATES = ["strict-eval-template-v1", "strict-eval-authenticated-root-template-v1",
              "strict-prereg-template-v1", "decision-receipt-template-v1"]


def _raw_pub(k):
    return k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _pub_b64(k):
    return base64.b64encode(_raw_pub(k)).decode("ascii")


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = main(argv)
    return rc, out.getvalue(), err.getvalue()


class TestPolicyTemplatesAP2(unittest.TestCase):
    def setUp(self):
        self.signer = generate_signer()
        self.pub = _pub_b64(self.signer)

    def test_template_profile_is_not_deployment_ready(self):
        # every shipped strict profile is a template: deploymentReady:false + requiresIdentityOverlay:true.
        for name in _TEMPLATES:
            with self.subTest(template=name):
                pol = load_policy(profile_path(name))
                self.assertIs(pol.get("deploymentReady"), False, f"{name} must be deploymentReady:false")
                self.assertIs(pol.get("requiresIdentityOverlay"), True,
                              f"{name} must be requiresIdentityOverlay:true")
        # the one non-template profile carries neither flag (it is a preview, not a template)
        preview = load_policy(profile_path("research-preview-v1"))
        self.assertNotIn("deploymentReady", preview)
        self.assertNotIn("requiresIdentityOverlay", preview)

    def test_template_without_identity_overlay_never_safe_for_automation(self):
        # AP-1 §5 + AP-2 §6.2: a raw template pins no signer, so verify under it must report
        # safeForAutomation:false with TEMPLATE_NOT_INSTANTIATED among the blockers — its OWN honest reason
        # (L2 pre-land audit fixed the earlier mislabel as SIGNER_NOT_PINNED) — even if every other pin passes.
        claim, _ = build_eval_claim(
            suite="safety", suite_version="1", metric="acc", comparator=">=", threshold="0.8",
            score="0.9", n=100, model_id="m", dataset_id="d", issuer="placeholder",
            timestamp="2026-07-09T10:00:00Z", assurance_level="reproduced")
        bundle = emit_eval_receipt(claim, self.signer)
        fd, path = tempfile.mkstemp(suffix=".json")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(bundle, f)
            rc, out, _ = _run(["verify", "--json", path, "--policy", "strict-eval-template-v1"])
        finally:
            os.unlink(path)
        data = json.loads(out)
        ra = data["root_authenticity"]
        self.assertFalse(ra["safeForAutomation"],
                         "a raw template must never yield safeForAutomation:true")
        self.assertIn("TEMPLATE_NOT_INSTANTIATED", ra["automationBlockers"])

    def test_instantiated_profile_pins_signer(self):
        inst = instantiate_template("strict-eval-template-v1", issuer_keys=[self.pub],
                                    policy_id="org/strict-eval-v1")
        self.assertEqual([e["public_key_b64"] for e in inst["allowed_issuers"]], [self.pub])
        self.assertTrue(inst["signature"]["require_expected_signer"])
        self.assertIs(inst["requiresIdentityOverlay"], False)
        self.assertIs(inst["deploymentReady"], True)
        # a pinned decision template routes the identity to trusted_decision_makers instead
        instd = instantiate_template("decision-receipt-template-v1", issuer_keys=[self.pub],
                                     policy_id="org/dr-v1")
        self.assertEqual([e["public_key_b64"] for e in instd["decision_receipt"]["trusted_decision_makers"]],
                         [self.pub])

    def test_instantiated_profile_pins_root_or_checkpoint_when_required(self):
        root_b64 = base64.b64encode(b"\x11" * 32).decode("ascii")
        # WITH the required root: pinned as trusted_roots and deployment-ready
        ok = instantiate_template("strict-eval-authenticated-root-template-v1", issuer_keys=[self.pub],
                                  policy_id="org/ar-v1", expected_root=root_b64)
        self.assertEqual(ok["merkle"]["trusted_roots"], [root_b64])
        self.assertIs(ok["deploymentReady"], True)
        # WITHOUT it: the authenticated-root template stays deploymentReady:false (required field missing)
        missing = instantiate_template("strict-eval-authenticated-root-template-v1", issuer_keys=[self.pub],
                                       policy_id="org/ar-v1")
        self.assertIs(missing["deploymentReady"], False)
        self.assertFalse(lint_policy(missing, strict=True)["ok"])

    def test_expired_instantiated_profile_fails(self):
        past = instantiate_template("strict-eval-template-v1", issuer_keys=[self.pub],
                                    policy_id="org/exp-v1", valid_until="2020-01-01T00:00:00Z")
        self.assertTrue(policy_expired(past))
        res = lint_policy(past)                      # expiry fails lint in BOTH modes
        self.assertFalse(res["ok"])
        self.assertTrue(any("expired" in e for e in res["errors"]))
        future = instantiate_template("strict-eval-template-v1", issuer_keys=[self.pub],
                                      policy_id="org/fut-v1", valid_until="2099-01-01T00:00:00Z")
        self.assertFalse(policy_expired(future))
        self.assertTrue(lint_policy(future, strict=True)["ok"])

    def test_unknown_identity_overlay_field_fails(self):
        with self.assertRaises(PolicyError):
            instantiate_template("strict-eval-template-v1", issuer_keys=[self.pub],
                                 policy_id="org/x", overlay={"bogus_field": 1})
        # a malformed pinned key is also fail-closed (never a policy that only LOOKS instantiated)
        with self.assertRaises(PolicyError):
            instantiate_template("strict-eval-template-v1", issuer_keys=["!!!not-base64!!!"],
                                 policy_id="org/y")

    def test_alias_resolution_warns_and_resolves(self):
        for old, canonical in PROFILE_ALIASES.items():
            with self.subTest(alias=old):
                self.assertEqual(canonical_profile_name(old), canonical)   # pure resolver, no warning
                err = io.StringIO()
                with contextlib.redirect_stderr(err):
                    path = profile_path(old)
                self.assertTrue(os.path.isfile(path))
                self.assertEqual(os.path.basename(path), f"{canonical}.json")
                self.assertIn("deprecated alias", err.getvalue())
                self.assertIn(old, err.getvalue())

    def test_lint_strict_fails_on_raw_template(self):
        for name in _TEMPLATES:
            with self.subTest(template=name):
                raw = load_policy(profile_path(name))
                res = lint_policy(raw, strict=True)
                self.assertFalse(res["ok"], f"{name} must fail lint --strict as a raw template")
                self.assertTrue(any("deploymentReady:false" in e for e in res["errors"]))
        # non-strict lint of the same raw template is OK (rawness is a --strict concern)
        self.assertTrue(lint_policy(load_policy(profile_path("strict-eval-template-v1")))["ok"])

    def test_overlay_wiping_identity_is_not_deployment_ready(self):
        # L2 pre-land review F2: deploymentReady must reflect the FINAL policy, not the input args — an
        # overlay that empties the just-pinned allowed_issuers must NOT stay labelled production-ready.
        inst = instantiate_template("strict-eval-template-v1", issuer_keys=[self.pub],
                                    policy_id="org/wiped", overlay={"allowed_issuers": []})
        self.assertEqual(inst["allowed_issuers"], [])
        self.assertIs(inst["deploymentReady"], False,
                      "an overlay that wipes the pinned identity must not stay deploymentReady:true")
        self.assertFalse(lint_policy(inst, strict=True)["ok"])

    def test_instantiate_rejects_a_non_template_profile(self):
        # research-preview-v1 is not a template — there is nothing to instantiate (clear error, no crash)
        with self.assertRaises(PolicyError):
            instantiate_template("research-preview-v1", issuer_keys=[self.pub], policy_id="org/z")

    def test_list_profiles_are_all_canonical(self):
        # No alias leaks into the canonical list; every alias target is a real canonical name.
        self.assertNotIn("strict-eval-v1", list_profiles())
        for canonical in PROFILE_ALIASES.values():
            self.assertIn(canonical, list_profiles())


if __name__ == "__main__":
    unittest.main()
