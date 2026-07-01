"""proofbundle verifies a real Sigstore Rekor inclusion proof (offline, from a committed fixture).

Rekor is an RFC 6962 log, so proofbundle's verify_inclusion checks a real proof from the world's
largest public transparency log. Fixture: tests/fixtures/rekor_inclusion_25579.json (public log
data fetched from rekor.sigstore.dev). No network needed.
"""
import unittest
from pathlib import Path

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "rekor_inclusion_25579.json"


@unittest.skipIf(not FIXTURE.exists(), "rekor fixture not present")
class TestRekorInterop(unittest.TestCase):
    def test_verifies_real_rekor_proof(self):
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples"))
        import rekor_interop
        self.assertTrue(rekor_interop.verify_rekor_fixture(), "proofbundle failed a real Rekor proof")

    def test_checkpoint_root_matches(self):
        import base64
        import json
        f = json.loads(FIXTURE.read_text(encoding="utf-8"))
        # C2SP signed-note line 3 = base64(rootHash); must match the hex rootHash.
        lines = f.get("checkpoint", "").split("\n")
        if len(lines) >= 3 and lines[2]:
            self.assertEqual(base64.b64decode(lines[2]).hex(), f["rootHash"],
                             "checkpoint root does not match inclusionProof rootHash")


if __name__ == "__main__":
    unittest.main()
