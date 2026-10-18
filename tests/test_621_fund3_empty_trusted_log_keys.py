"""6.2.1 key identity Fund 3: a present but empty ``trustedLogKeys`` allows no log key.

``evaluate_public_transparency``: a PRESENT but empty ``trustedLogKeys`` under ``requireSignedCheckpoint`` was
treated like no allowlist, so any caller-supplied log key that matched the signature passed. The sibling at the
origin allowlist: a present empty ``trustedLogOrigins`` allowed any origin.

Property: an empty pin never yields a positive trust verdict. Red at v6.2.0.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
for _p in (str(REPO / "src"), str(REPO / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from proofbundle.public_transparency import (  # noqa: E402
    PublicTransparencyError,
    evaluate_public_transparency,
)
from test_public_transparency import _ORIGIN, _signed_note  # noqa: E402


class Fund3EmptyTrustedLogKeys(unittest.TestCase):
    def _statuses(self, keys):
        note, attacker_vkey = _signed_note()
        try:
            out = evaluate_public_transparency(
                note, {"requireSignedCheckpoint": True, "trustedLogKeys": keys(attacker_vkey)},
                log_vkey=attacker_vkey)
        except PublicTransparencyError as exc:   # a refused policy is fail-closed too
            return {"refused": str(exc)}
        return {"CHECKPOINT_SIGNATURE": out["statuses"].get("CHECKPOINT_SIGNATURE"),
                "PUBLIC_TRANSPARENCY": out.get("PUBLIC_TRANSPARENCY")}

    def test_a_present_empty_allowlist_allows_no_key(self):
        got = self._statuses(lambda _vk: [])
        self.assertNotEqual(got.get("CHECKPOINT_SIGNATURE"), "PASS", got)
        self.assertNotEqual(got.get("PUBLIC_TRANSPARENCY"), "PASS", got)

    def test_control_the_named_key_passes(self):
        self.assertEqual(self._statuses(lambda vk: [vk]),
                         {"CHECKPOINT_SIGNATURE": "PASS", "PUBLIC_TRANSPARENCY": "PASS"})

    def test_a_present_empty_origin_allowlist_allows_no_origin(self):
        """The sibling at the origin allowlist: present and empty, it allowed any origin (measured at v6.2.0:
        LOG_ORIGIN NOT_EVALUATED, PUBLIC_TRANSPARENCY PASS)."""
        note, vkey = _signed_note()
        out = evaluate_public_transparency(
            note, {"requireSignedCheckpoint": True, "trustedLogKeys": [vkey], "trustedLogOrigins": []},
            log_vkey=vkey)
        self.assertEqual(out["statuses"].get("LOG_ORIGIN"), "FAIL", out)
        self.assertNotEqual(out.get("PUBLIC_TRANSPARENCY"), "PASS", out)

    def test_control_the_named_origin_passes(self):
        note, vkey = _signed_note()
        out = evaluate_public_transparency(
            note, {"requireSignedCheckpoint": True, "trustedLogKeys": [vkey], "trustedLogOrigins": [_ORIGIN]},
            log_vkey=vkey)
        self.assertEqual((out["statuses"].get("LOG_ORIGIN"), out.get("PUBLIC_TRANSPARENCY")), ("PASS", "PASS"))

    def test_control_a_different_key_fails(self):
        other = _signed_note()[1]
        self.assertEqual(self._statuses(lambda _vk: [other]),
                         {"CHECKPOINT_SIGNATURE": "FAIL", "PUBLIC_TRANSPARENCY": "FAIL"})


if __name__ == "__main__":
    unittest.main()
