"""6.2.1, final text review: `VerificationResult` is exported, so a call in the form of 6.2.0 must set the same
fields in 6.2.1. The new field `verified_inclusion_context` stood before `verified_origin`, and the positional call
`VerificationResult([], None, None, None, None, None, "ORIGIN")` set it instead of the origin token.

Red at 9b0d6520 (the new field before `verified_origin`), green with the field at the end.
"""

from __future__ import annotations

import dataclasses
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))

from proofbundle.errors import Check, VerificationResult  # noqa: E402

#: The init fields of 6.2.0 in their order, read at 621bca9e. A later release may add fields after them.
FELDER_620 = ("checks", "verified_signer_pub", "verified_payload_digest", "verified_merkle_root",
              "verified_inclusion_root", "verified_sd_jwt_vc_compact", "verified_origin")


class DieFormVon620BelegtDieselbenFelder(unittest.TestCase):
    def test_a_positional_call_of_6_2_0_sets_the_origin_token(self):
        r = VerificationResult([], None, None, None, None, None, "ORIGIN")
        self.assertEqual(r.verified_origin, "ORIGIN")
        self.assertIsNone(r.verified_inclusion_context)

    def test_the_fields_of_6_2_0_keep_their_positions(self):
        felder = tuple(f.name for f in dataclasses.fields(VerificationResult) if f.init)
        self.assertEqual(felder[:len(FELDER_620)], FELDER_620,
                         "a field inserted before an existing one moves every positional argument after it")

    def test_control_the_new_field_is_still_set_by_name(self):
        r = VerificationResult([], verified_inclusion_context=b"ctx")
        self.assertEqual(r.verified_inclusion_context, b"ctx")
        self.assertIsNone(r.verified_origin)


class GleichheitReprUndAsDictBleiben(unittest.TestCase):
    """The new field takes no part in equality, repr or as_dict, wherever it stands."""

    def test_equality_repr_and_as_dict_ignore_the_verified_fields(self):
        a = VerificationResult([Check("a", True, "d")])
        b = VerificationResult([Check("a", True, "d")], verified_inclusion_context=b"x", verified_origin="y")
        self.assertEqual(a, b)
        self.assertEqual(repr(a), repr(b))
        self.assertEqual(repr(a), "VerificationResult(checks=[Check(name='a', ok=True, detail='d')])")
        self.assertEqual(a.as_dict(), b.as_dict())
        self.assertEqual(a.as_dict(), {"ok": True, "checks": [{"name": "a", "ok": True, "detail": "d"}]})

    def test_the_origin_stamp_covers_the_inclusion_context(self):
        r = VerificationResult([Check("a", True)], verified_inclusion_context=b"ctx")
        r.stamp_origin()
        self.assertTrue(r.origin_authentic())
        r.verified_inclusion_context = b"other"
        self.assertFalse(r.origin_authentic(), "a changed context after stamping is no longer authentic")


if __name__ == "__main__":
    unittest.main()
