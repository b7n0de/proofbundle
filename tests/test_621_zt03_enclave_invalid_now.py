"""6.2.1 ZT-03: ``verify_enclave_attestation`` never turns an invalid explicit ``now`` (bool, float, str) into a
positive verdict.

Red at v6.2.0.
"""



from __future__ import annotations

import sys
import unittest
import warnings
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
for _p in (str(REPO / "src"), str(REPO / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from proofbundle import emit_bundle, generate_signer  # noqa: E402

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from proofbundle.experimental.enclave import (  # noqa: E402
        enclave_binding_for,
        issue_enclave_attestation,
        verify_enclave_attestation,
    )


class ZT03EnclaveInvalidNow(unittest.TestCase):
    def _setup(self):
        bundle = emit_bundle(b"zt-03", generate_signer())
        binding = enclave_binding_for(bundle)
        verifier = generate_signer()
        eat = issue_enclave_attestation(binding, verifier, profile="p", tier="affirming", exp=200)
        return eat, verifier.public_key().public_bytes_raw(), binding

    def _ok(self, now):
        eat, pub, binding = self._setup()
        try:
            return verify_enclave_attestation(eat, verifier_pubkey=pub, expected_binding=binding, now=now)["ok"]
        except (TypeError, ValueError):
            return "refused"

    def test_an_invalid_explicit_now_is_never_a_positive_verdict(self):
        for bad in (False, True, 150.5, "150"):
            with self.subTest(now=bad):
                self.assertIsNot(self._ok(bad), True)

    def test_control_a_valid_now_inside_and_at_the_end(self):
        self.assertIs(self._ok(150), True)
        self.assertIs(self._ok(200), False)


if __name__ == "__main__":
    unittest.main()
