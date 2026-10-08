"""Nachtrag 32 (Z309, 6.2.0 security fix): the secure behaviour of the two findings, fail-closed only.

Critical — sd_jwt.expected_vct trusts an attacker-grafted self-signed SD-JWT. The verifying key comes from
sd_jwt_vc.issuer_public_key_b64, which lives outside the bundle's signed payload, so a self-signed SD-JWT with
any vct verifies. After the fix expected_vct is trusted only when the issuer key matches an independently set,
algorithm-bound pin (sd_jwt.issuer_key_pin) or the SD-JWT is bound to the signed payload.
  - without a pin: fails (was a PASS at f65e9ec1 — the vulnerability)
  - with a pin and a foreign key: fails
  - with a pin and the matching key: passes

High — anchor verify-pack does not bind the timestamp to the expected target. After the fix it requires exactly
one of --target-file / --expected-root, computes/decodes the expected root independently and refuses a mismatch
before the OTS proof is read.
  - without a target: exit 2
  - with the wrong target: exit 1 (target_mismatch), before the proof is evaluated
  - with the right target: confirms (exit 0)

Red at f65e9ec1, green after. No attack rebuilds beyond these fail-closed cases.
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import io
import json
import pathlib
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from proofbundle import cli
from proofbundle.bundle import verify_bundle
from proofbundle.policy import evaluate_policy

REPO = pathlib.Path(__file__).resolve().parents[1]
EXAMPLE = REPO / "examples" / "example_bundle.json"
_NOW = datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc)


# ── Critical: sd_jwt.expected_vct requires a pinned issuer key (or a payload binding) ─────────────────
class ExpectedVctRequiresAPinnedIssuerKey(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not EXAMPLE.is_file():
            raise unittest.SkipTest("examples/example_bundle.json is not in this tree")
        cls.bundle = json.loads(EXAMPLE.read_text(encoding="utf-8"))
        cls.result = verify_bundle(cls.bundle)
        if not cls.result.ok:
            raise unittest.SkipTest("the example bundle does not verify in this tree")
        sd = cls.bundle["sd_jwt_vc"]
        cls.pub_b64 = sd["issuer_public_key_b64"]
        from proofbundle.sdjwt_issue import _jwt_payload
        cls.vct = _jwt_payload(sd["compact"])["vct"]

    def _vct_check(self, sdj_extra):
        policy = {"schema": "proofbundle/trust-policy/v0.2", "policy_id": "n32",
                  "sd_jwt": {"require_key_binding_when_cnf_present": False, "require_nonce": False,
                             "expected_vct": self.vct, **sdj_extra}}
        res = evaluate_policy(self.bundle, self.result, policy, now=_NOW)
        chk = [c for c in res["checks"] if c["name"] == "policy:expected_vct"]
        self.assertEqual(len(chk), 1, res["checks"])
        return res["policy_ok"], chk[0]["ok"]

    def test_without_a_pin_the_vct_is_not_trusted(self):
        # the vulnerability: at f65e9ec1 this returned policy_ok True / expected_vct True
        policy_ok, vct_ok = self._vct_check({})
        self.assertFalse(vct_ok, "expected_vct must fail closed without an issuer pin")
        self.assertIsNot(policy_ok, True)

    def test_with_a_pin_and_a_foreign_key_the_vct_is_not_trusted(self):
        foreign = "ed25519:" + base64.b64encode(b"\x09" * 32).decode("ascii")
        _policy_ok, vct_ok = self._vct_check({"issuer_key_pin": foreign})
        self.assertFalse(vct_ok, "a pin that is not the verifying key must fail closed")

    def test_with_a_pin_and_the_matching_key_the_vct_is_trusted(self):
        matching = "ed25519:" + self.pub_b64
        policy_ok, vct_ok = self._vct_check({"issuer_key_pin": matching})
        self.assertTrue(vct_ok, "a pin equal to the verifying key trusts the vct")
        self.assertIs(policy_ok, True)


# ── High: anchor verify-pack binds the timestamp to the target the relying party means ────────────────
try:
    import opentimestamps  # noqa: F401
    _HAS_OTS = True
except ImportError:
    _HAS_OTS = False

FIXTURE_DIR = REPO / "tests" / "fixtures" / "ots"
_SYNTH = "synthetic-upgraded-sha256"


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    try:
        with redirect_stdout(out), redirect_stderr(err):
            rc = cli.main(argv)
    except SystemExit as exc:            # argparse exits via SystemExit on a usage error
        rc = exc.code if isinstance(exc.code, int) else 2
    return rc, out.getvalue()


@unittest.skipUnless(_HAS_OTS and (FIXTURE_DIR / f"{_SYNTH}.txt.ots").is_file(),
                     "needs proofbundle[anchors] and the synthetic OTS fixture")
class VerifyPackBindsTheTimestampToTheTarget(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="n32-vp-")
        self.synth_proof = str(FIXTURE_DIR / f"{_SYNTH}.txt.ots")
        self.synth_target = str(FIXTURE_DIR / f"{_SYNTH}.txt")
        block = json.loads((FIXTURE_DIR / f"{_SYNTH}.block.json").read_text())
        self.height, self.mr = block["height"], block["merkle_root_internal_le_hex"]
        self.pack = str(pathlib.Path(self.dir) / "pack.json")
        rc, txt = _run(["anchor", "upgrade", "--proof", self.synth_proof, "--target-file", self.synth_target,
                        "--out", self.pack])
        self.assertEqual(rc, 0, txt)

    def test_without_a_target_it_refuses(self):
        rc, _ = _run(["anchor", "verify-pack", self.pack, "--bitcoin-header", f"{self.height}:{self.mr}"])
        self.assertEqual(rc, 2, "verify-pack must refuse without --target-file/--expected-root")

    def test_with_the_wrong_target_it_refuses_before_the_proof(self):
        wrong = base64.b64encode(hashlib.sha256(b"a different artifact").digest()).decode("ascii")
        rc, txt = _run(["anchor", "verify-pack", self.pack, "--expected-root", wrong,
                        "--bitcoin-header", f"{self.height}:{self.mr}", "--json"])
        self.assertEqual(rc, 1, txt)
        self.assertEqual(json.loads(txt)["status"], "target_mismatch")

    def test_with_the_right_target_it_confirms(self):
        rc, txt = _run(["anchor", "verify-pack", self.pack, "--target-file", self.synth_target,
                        "--bitcoin-header", f"{self.height}:{self.mr}"])
        self.assertEqual(rc, 0, txt)
        self.assertIn("CONFIRMED", txt)

    def test_the_expected_root_of_the_genuine_target_also_confirms(self):
        root_b64 = base64.b64encode(hashlib.sha256(pathlib.Path(self.synth_target).read_bytes()).digest()).decode()
        rc, txt = _run(["anchor", "verify-pack", self.pack, "--expected-root", root_b64,
                        "--bitcoin-header", f"{self.height}:{self.mr}"])
        self.assertEqual(rc, 0, txt)


if __name__ == "__main__":
    unittest.main()
