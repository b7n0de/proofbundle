"""WP-TP1 — `policy explain` / `policy lint` and the vacuous-pass warning.

The trap this closes: `evaluate_policy` returns ``policy_ok = all(checks)`` — with a policy that
pins nothing, ``checks`` is empty and ``all([]) is True``, so `verify --policy` printed a green
``POLICY: OK`` that evaluated NOTHING (a vacuous pass). Now: `policy lint` fails such a policy,
`policy explain` shows what a policy actually pins, and `verify` marks a passing-but-signerless
policy inline with ``(WARNING: attributes to nobody)`` + a machine-readable ``policy_warnings[]``
(exit code unchanged — a warning, not a failure)."""
import contextlib
import io
import json
import os
import tempfile
import unittest

from proofbundle import emit_bundle, generate_signer
from proofbundle.cli import main
from proofbundle.policy import explain_policy, lint_policy, load_policy, policy_warnings


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = main(argv)
    return rc, out.getvalue(), err.getvalue()


def _write(obj) -> str:
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(obj, f)
    return path


MINIMAL = {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "urn:example:empty"}
SCHEMA_ONLY_PIN = {**MINIMAL, "allowed_schema_versions": ["proofbundle/v0.1"]}


def _signer_policy(signer) -> dict:
    import base64
    pub = base64.b64encode(signer.public_key().public_bytes_raw()).decode("ascii")
    return {**MINIMAL, "policy_id": "urn:example:pinned",
            "allowed_issuers": [{"public_key_b64": pub}],
            "signature": {"require_expected_signer": True}}


class TestLint(unittest.TestCase):
    def test_empty_policy_is_a_lint_failure(self):
        res = lint_policy(load_policy(MINIMAL))
        self.assertFalse(res["ok"])
        self.assertTrue(any("vacuous" in e for e in res["errors"]))
        self.assertEqual(res["pins"], [])

    def test_cli_lint_exits_one_on_empty_and_zero_on_pinned(self):
        p1, p2 = _write(MINIMAL), _write(_signer_policy(generate_signer()))
        try:
            rc1, out1, _ = _run(["policy", "lint", "--json", p1])
            rc2, out2, _ = _run(["policy", "lint", "--json", p2])
        finally:
            os.unlink(p1), os.unlink(p2)
        self.assertEqual(rc1, 1)
        self.assertFalse(json.loads(out1)["ok"])
        self.assertEqual(rc2, 0)
        self.assertTrue(json.loads(out2)["ok"])

    def test_strict_promotes_attributes_to_nobody(self):
        pol = load_policy(SCHEMA_ONLY_PIN)   # pins SOMETHING, but no signer
        self.assertTrue(lint_policy(pol)["ok"])                 # normal: warning only
        self.assertTrue(lint_policy(pol)["warnings"])
        strict = lint_policy(pol, strict=True)
        self.assertFalse(strict["ok"])                          # strict: failure
        self.assertTrue(any("nobody" in e for e in strict["errors"]))

    def test_malformed_policy_exits_two(self):
        path = _write({"schema": "nope"})
        try:
            rc, _, err = _run(["policy", "lint", path])
        finally:
            os.unlink(path)
        self.assertEqual(rc, 2)
        self.assertIn("ERROR", err)


class TestExplain(unittest.TestCase):
    def test_explain_lists_the_effective_pins(self):
        signer = generate_signer()
        pins = explain_policy(load_policy(_signer_policy(signer)))
        self.assertTrue(any("public key pinned" in x for x in pins))
        self.assertTrue(any("require_expected_signer" in x for x in pins))

    def test_cli_explain_json(self):
        path = _write(SCHEMA_ONLY_PIN)
        try:
            rc, out, _ = _run(["policy", "explain", "--json", path])
        finally:
            os.unlink(path)
        self.assertEqual(rc, 0)
        data = json.loads(out)
        self.assertEqual(data["policy_id"], "urn:example:empty")
        self.assertTrue(data["pins"])
        self.assertTrue(any("nobody" in w for w in data["warnings"]))


class TestVerifyVacuousWarning(unittest.TestCase):
    def _bundle_path(self, signer) -> str:
        return _write(emit_bundle(b'{"x":1}', signer))

    def test_signerless_policy_warns_but_exit_stays_zero(self):
        signer = generate_signer()
        bpath, ppath = self._bundle_path(signer), _write(SCHEMA_ONLY_PIN)
        try:
            rc, out, _ = _run(["verify", bpath, "--policy", ppath])
            rcj, outj, _ = _run(["verify", "--json", bpath, "--policy", ppath])
        finally:
            os.unlink(bpath), os.unlink(ppath)
        self.assertEqual(rc, 0)                     # a warning, never a new failure mode
        self.assertIn("POLICY: OK (WARNING: attributes to nobody)", out)
        self.assertEqual(rcj, 0)
        data = json.loads(outj)
        self.assertTrue(data["policy_ok"])
        self.assertTrue(any("attributes to nobody" in w for w in data["policy_warnings"]))

    def test_signer_pinned_policy_stays_clean(self):
        signer = generate_signer()
        bpath, ppath = self._bundle_path(signer), _write(_signer_policy(signer))
        try:
            rc, out, _ = _run(["verify", bpath, "--policy", ppath])
            _, outj, _ = _run(["verify", "--json", bpath, "--policy", ppath])
        finally:
            os.unlink(bpath), os.unlink(ppath)
        self.assertEqual(rc, 0)
        self.assertIn("POLICY: OK\n", out)
        self.assertNotIn("WARNING: attributes to nobody", out)
        self.assertEqual(json.loads(outj)["policy_warnings"], [])

    def test_library_warning_source(self):
        self.assertTrue(policy_warnings(load_policy(MINIMAL)))
        self.assertEqual(policy_warnings(load_policy(_signer_policy(generate_signer()))), [])


if __name__ == "__main__":
    unittest.main()
