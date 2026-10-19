"""6.2.1 key identity Fund 2: a hybrid executor role is not met by its classical half alone.

``verify_outcome_receipt``: an ``outcomeExecutors`` key declared ``hybrid-ed25519-mldsa65`` was satisfied by a
plain Ed25519 outcome signature, because the binding compared only the 32 classical bytes.

Property: a pin whose identity is a hybrid key never yields a positive trust verdict for an Ed25519 signature.
Red at v6.2.0.
"""
from __future__ import annotations

import base64
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
for _p in (str(REPO / "src"), str(REPO / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from proofbundle.outcome import verify_outcome_receipt  # noqa: E402
from test_security_fix_620_trustpack_n45_anchor import _Base, _content_root  # noqa: E402

_PQ_TEST_BYTES = base64.b64encode(b"\x01" * 1952).decode("ascii")


class Fund2HybridExecutorRole(_Base):
    def _verify(self, alg: str):
        env, out_pub, pred, _root_sks = self._exec_fixtures()
        entry = {"alg": alg, "publicKey": base64.b64encode(out_pub).decode("ascii")}
        if alg.startswith("hybrid"):
            entry["publicKeyPq"] = _PQ_TEST_BYTES
        pred["keys"]["kid-exec"] = entry
        return verify_outcome_receipt(env, out_pub, trust_pack=pred,
                                      trust_pack_expected_genesis_digest=_content_root(pred))

    def test_a_hybrid_executor_role_is_not_met_by_a_plain_ed25519_signature(self):
        r = self._verify("hybrid-ed25519-mldsa65")
        self.assertIsNot(r["executor_role_trusted"], True, f"hybrid role met by Ed25519 alone: {r!r}")
        self.assertIsNot(r["executor_key_bound"], True)
        self.assertIs(r["ok"], False)
        self.assertIs(r["automation"]["safeForAutomation"], False)

    def test_control_an_ed25519_executor_role_is_met(self):
        r = self._verify("ed25519")
        self.assertIs(r["executor_role_trusted"], True)
        self.assertIs(r["executor_key_bound"], True)
        self.assertIs(r["ok"], True)
        self.assertIs(r["automation"]["safeForAutomation"], True)


if __name__ == "__main__":
    unittest.main()
