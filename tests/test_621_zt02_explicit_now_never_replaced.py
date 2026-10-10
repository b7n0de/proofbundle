"""6.2.1 ZT-02: an explicit ``now`` is never replaced by the wall clock: a falsy or mistyped ``now`` fails
closed (``policy_expired``, ``policy_not_yet_valid``, ``_authenticate_trusted_checkpoint``).

Red at v6.2.0.
"""



from __future__ import annotations

import sys
import unittest
import warnings
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
for _p in (str(REPO / "src"), str(REPO / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from test_tree_context_authenticity import _checkpoint_entry  # noqa: E402

from proofbundle import policy as _policy  # noqa: E402

with warnings.catch_warnings():
    warnings.simplefilter("ignore")


class _WallClock:
    """``policy.datetime`` with a ``now()`` that returns the given readings in turn and counts them."""

    def __init__(self, *readings):
        self.readings, self.count = list(readings), 0
        owner = self

        class _DT(datetime):
            @classmethod
            def now(cls, tz=None):
                value = owner.readings[min(owner.count, len(owner.readings) - 1)]
                owner.count += 1
                return value
        self.cls = _DT


_D2026 = datetime(2026, 1, 1, tzinfo=timezone.utc)
_D2028 = datetime(2028, 1, 1, tzinfo=timezone.utc)


class ZT02ExplicitNowNeverReplaced(unittest.TestCase):
    INVALID = (0, 0.0, False, "")

    def _call(self, fn, *args, **kwargs):
        clock = _WallClock(_D2028)
        with mock.patch.object(_policy, "datetime", clock.cls):
            try:
                return fn(*args, **kwargs), clock.count
            except (TypeError, ValueError, _policy.PolicyError):
                return "refused", clock.count

    def test_policy_expired_does_not_read_the_wall_clock_for_an_explicit_value(self):
        for bad in self.INVALID:
            with self.subTest(now=bad):
                verdict, reads = self._call(_policy.policy_expired, {"valid_until": "2027-01-01T00:00:00Z"}, now=bad)
                self.assertEqual(reads, 0)
                self.assertIn(verdict, ("refused", True))

    def test_policy_not_yet_valid_does_not_read_the_wall_clock_for_an_explicit_value(self):
        for bad in self.INVALID:
            with self.subTest(now=bad):
                verdict, reads = self._call(_policy.policy_not_yet_valid, {"valid_from": "2025-01-01T00:00:00Z"},
                                            now=bad)
                self.assertEqual(reads, 0)
                self.assertIn(verdict, ("refused", True))

    def test_the_checkpoint_helper_does_not_read_the_wall_clock_for_an_explicit_value(self):
        entry = _checkpoint_entry(b"\x11" * 32, 4, valid_until="2027-01-01T00:00:00Z")
        for bad in self.INVALID:
            with self.subTest(now=bad):
                verdict, reads = self._call(_policy._authenticate_trusted_checkpoint, entry, now=bad)
                self.assertEqual(reads, 0)
                self.assertTrue(verdict == "refused" or verdict[0] is False, verdict)

    def test_control_an_aware_instant_is_used_as_given(self):
        self.assertEqual(self._call(_policy.policy_expired, {"valid_until": "2027-01-01T00:00:00Z"}, now=_D2026),
                         (False, 0))
        self.assertEqual(self._call(_policy.policy_not_yet_valid, {"valid_from": "2025-01-01T00:00:00Z"},
                                    now=_D2026), (False, 0))
        entry = _checkpoint_entry(b"\x11" * 32, 4, valid_until="2027-01-01T00:00:00Z")
        (ok, _reason), reads = self._call(_policy._authenticate_trusted_checkpoint, entry, now=_D2026)
        self.assertEqual((ok, reads), (True, 0))


if __name__ == "__main__":
    unittest.main()
