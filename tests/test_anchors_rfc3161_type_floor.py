"""`verify_rfc3161` must hold the never-raise rule it prescribes to third-party authors.

`register_anchor_type` documents that a verifier "MUST be fail-closed … never raise for an ordinary
bad proof". The self-gate run of 2026-07-31 recorded as F3 that this FIRST-PARTY implementation did
not hold it: `frozen` and `rp_trust` are consumed with `.get(...)`, so a non-dict raised a raw
`AttributeError` out of a verdict-returning surface. Re-measured against `main` on 2026-08-16, sixteen
days later, it still reproduced.

WHY THE FAMILY PROPERTY NEVER CAUGHT IT, and why this file has to exist separately. Two axes of the
same instrument were blind here:

  * the MODULE axis — `anchors_rfc3161` was outside `_MODULES`, so the property never entered it.
    That is closed by tests/test_never_raise_population_guard.py.
  * the ARGUMENT axis — the property fuzzes only the PRIMARY parameter. `frozen` and `rp_trust` are
    keyword-only, so even inside the population the property does not reach them. That axis is the
    finding the self-gate recorded as F2 and it is NOT closed; this file covers this one surface
    directly rather than pretending the general sweep does.

MEASUREMENT PRECONDITION, learned the hard way on 2026-08-16. Without `rfc3161_client` installed the
function returns at its optional-import guard BEFORE reaching the lines under test, and a probe reads
green for a reason that has nothing to do with the defence it names — the exact class the fixture
manifest calls `vacuous_seam_passes_for_a_reason_other_than_the_defence_it_names`. These tests
therefore SKIP honestly when the extra is absent instead of passing vacuously.
"""
from __future__ import annotations

import unittest

from proofbundle.anchors_rfc3161 import verify_rfc3161
from proofbundle.errors import BundleFormatError


def _anchors_extra_present() -> bool:
    try:
        import rfc3161_client  # noqa: F401, PLC0415
        return True
    except ImportError:
        return False


@unittest.skipUnless(_anchors_extra_present(),
                     "needs proofbundle[anchors]: without it the function returns at its import guard "
                     "before the lines under test, and a pass here would be vacuous")
class TestRfc3161TrustConfigTypeFloor(unittest.TestCase):
    """Every hostile TYPE on the trust-config arguments must yield a typed error, never a raw one."""

    HOSTILE = [None, 123, 1.5, True, b"bytes", "a string", ["a", "list"], ("t", "u"), object()]

    def test_non_mapping_frozen_is_a_typed_error(self):
        for bad in self.HOSTILE:
            if bad is None:
                continue          # None is the documented "absent" case, handled below
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(BundleFormatError):
                    verify_rfc3161(b"", b"", frozen=bad)

    def test_non_mapping_rp_trust_is_a_typed_error(self):
        for bad in self.HOSTILE:
            if bad is None:
                continue          # None is the documented default
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(BundleFormatError):
                    verify_rfc3161(b"", b"", frozen={}, rp_trust=bad)

    def test_no_raw_attributeerror_survives(self):
        """The regression this closes, stated as the shape it had rather than as a description.

        `AttributeError` is in the property's `_FORBIDDEN` set: it is a type-confusion crash signature,
        which is precisely what a verdict-returning surface must not emit.
        """
        for arg, bad in (("frozen", 123), ("rp_trust", 123)):
            with self.subTest(arg=arg):
                kwargs = {"frozen": {}, "rp_trust": None}
                kwargs[arg] = bad
                try:
                    verify_rfc3161(b"", b"", **kwargs)
                except BundleFormatError:
                    pass                                  # typed, fail-closed: accepted
                except AttributeError as exc:             # the regression
                    self.fail(f"{arg}={bad!r} still raises a raw AttributeError: {exc}")

    def test_the_documented_defaults_still_reach_a_verdict(self):
        """Bidirectional validation: the floor must not turn a legitimate call into an error.

        `rp_trust=None` is the documented default and `frozen={}` is a legitimate empty block. Both must
        still return the `needs_rp_trust` verdict rather than raise — otherwise the floor has broken the
        surface it was meant to protect.
        """
        res = verify_rfc3161(b"", b"", frozen={}, rp_trust=None)
        self.assertIsInstance(res, dict)
        self.assertIs(res.get("ok"), False)
        self.assertEqual(res.get("status"), "needs_rp_trust")

    def test_a_valid_mapping_is_not_rejected_by_the_floor(self):
        """A dict passes the floor and the function proceeds to its real work (and fails closed there)."""
        res = verify_rfc3161(b"", b"", frozen={"rootCertsDerB64": []},
                             rp_trust={"trusted_tsa_roots": []})
        self.assertIsInstance(res, dict)
        self.assertIs(res.get("ok"), False)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
