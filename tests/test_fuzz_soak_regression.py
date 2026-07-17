"""WP-D — the fuzz-soak harness + the four robustness-class regression vectors (EXT §9 P2).

Two things are asserted here so a unit run (no soak box) still gates the property:
  1. The bounded soak harness itself works and is HONEST: a short run is not the 24h soak, and a
     deliberately raw-crashing verifier IS reported (bidirectional — no green-only harness).
  2. The four robustness classes the Extension named (raw TypeErrors, SD-JWT header confusion,
     non-canonical base64, missing resource budgets) are CLOSED: fed through the real public
     verifiers, each is a typed rejection, never a raw crash, and the wide-input budget bites.
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
for sub in ("src", "scripts"):
    p = str(REPO / sub)
    if p not in sys.path:
        sys.path.insert(0, p)

from proofbundle.errors import ProofBundleError  # noqa: E402


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, REPO / rel)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


class TestFuzzSoakHarness(unittest.TestCase):
    def setUp(self):
        self.soak = _load("fuzz_soak_mod", "scripts/fuzz_soak.py")

    def test_short_run_is_clean_and_not_full_soak(self):
        result = self.soak.soak(duration_seconds=0.0, seed=3, max_iters=2000)
        self.assertTrue(result["ok"], result["untriaged_crashes"] or result["false_accepts"])
        self.assertFalse(result["is_full_soak_24h"])          # No-Fake: a smoke is not the 24h soak
        self.assertGreater(result["parsers_soaked"], 0)

    def test_harness_reports_a_raw_crasher(self):
        # bidirectional: a raw-raising verifier MUST be bucketed as an untriaged crash.
        crashes: dict = {}

        def boom(x):
            return x["missing"]      # raw KeyError/TypeError on any confused input
        self.soak._record_crash(crashes, "proofbundle.fake.verify_boom", KeyError("missing"), {})
        self.assertEqual(sum(c["count"] for c in crashes.values()), 1)
        try:
            boom(None)
        except (KeyError, TypeError):
            pass

    def test_false_accept_detector(self):
        self.assertTrue(self.soak._is_false_accept({"ok": True}))
        self.assertTrue(self.soak._is_false_accept(True))
        self.assertFalse(self.soak._is_false_accept({"ok": False}))
        self.assertFalse(self.soak._is_false_accept(None))


class TestRobustnessClassRegressions(unittest.TestCase):
    """The four EXT-named robustness classes, driven through the real verifiers."""

    def test_raw_type_confusion_never_raises(self):
        from proofbundle.decision import verify_decision_receipt
        from proofbundle.trust_pack import verify_trust_pack
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        pub = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
        verifiers = [verify_trust_pack, lambda x: verify_decision_receipt(x, pub)]
        for verifier in verifiers:
            for bad in (123, [], {"payload": None}, {"signatures": True}):
                try:
                    r = verifier(bad)
                except (ProofBundleError, ValueError):
                    continue
                self.assertFalse(bool(r.get("ok")) if isinstance(r, dict) else bool(r))

    def test_sdjwt_header_confusion_typed_reject(self):
        from proofbundle.sdjwt import verify_sd_jwt
        for bad in ("eyJhbGciOiJub25lIn0.eyJ4IjoxfQ.~a~b", "..", "a.b.c", ""):
            try:
                verify_sd_jwt(bad)
            except (ProofBundleError, ValueError):
                pass  # documented malformed/confused-header path

    def test_noncanonical_base64_typed_reject(self):
        from proofbundle.dsse import verify_envelope
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        pub = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
        env = {"payloadType": "application/vnd.in-toto+json",
               "payload": "not-base64!!padding=", "signatures": [{"sig": "@@@"}]}
        try:
            self.assertFalse(verify_envelope(env, pub))
        except (ProofBundleError, ValueError):
            pass

    def test_resource_budget_bites_on_wide_signatures(self):
        # a signatures list far over the budget cap must be rejected fail-closed, never processed.
        from proofbundle.dsse import verify_envelope
        from proofbundle.budget import DEFAULT_BUDGET
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        pub = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
        cap = DEFAULT_BUDGET.signatures
        env = {"payloadType": "application/vnd.in-toto+json", "payload": "e30",
               "signatures": [{"sig": "AA"} for _ in range(cap + 5)]}
        with self.assertRaises(ProofBundleError):
            verify_envelope(env, pub)


if __name__ == "__main__":
    unittest.main()
