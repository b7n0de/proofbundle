"""6.2.1 Codex P3: ``verify_anchor``: an invalid explicit ``now`` is refused before any registered verifier sees it.

Red at v6.2.0.
"""



from __future__ import annotations

import base64
import sys
import unittest
import warnings
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
for _p in (str(REPO / "src"), str(REPO / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)


from proofbundle import (  # noqa: E402
    anchors,  # noqa: E402
    )

with warnings.catch_warnings():
    warnings.simplefilter("ignore")


class CodexP3AnchorNowCheckedCentrally(unittest.TestCase):
    _TYPE = "test-621-p3-now/v1"

    def setUp(self):
        self.seen: list = []
        anchors.register_anchor_type(self._TYPE, lambda proof, root, *, frozen, now: (
            self.seen.append(now) or {"ok": True}))

    def tearDown(self):
        anchors._VERIFIERS.pop(self._TYPE, None)

    def _verify(self, now):
        root = b"\x22" * 32
        entry = {"type": self._TYPE, "target": "statement", "canonicalRoot": base64.b64encode(root).decode(),
                 "proof": base64.b64encode(b"p").decode()}
        try:
            return anchors.verify_anchor(entry, target_roots={"statement": root}, now=now)["ok"]
        except (TypeError, ValueError):
            return "refused"

    def test_an_invalid_explicit_now_never_reaches_a_registered_verifier_as_a_positive(self):
        for bad in (True, "1700000000", 1.5):
            with self.subTest(now=bad):
                self.seen.clear()
                verdict = self._verify(bad)
                self.assertIsNot(verdict, True, f"invalid now {bad!r} passed to the verifier: {self.seen!r}")

    def test_control_an_integer_now_and_no_now_reach_the_verifier(self):
        self.assertIs(self._verify(1_700_000_000), True)
        self.assertIs(self._verify(None), True)


if __name__ == "__main__":
    unittest.main()
