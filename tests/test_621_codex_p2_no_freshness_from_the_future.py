"""6.2.1 Codex P2: ``check_freshness``: a claim dated (even fractionally) after the reference time is never fresh.

The sibling at the other end of the bound: a claim older than ``max_age_seconds`` by a fraction of a second was
truncated to the bound and read as fresh. Both ends are judged on the exact age now.

Red at v6.2.0.
"""



from __future__ import annotations

import sys
import unittest
import warnings
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
for _p in (str(REPO / "src"), str(REPO / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from proofbundle.evalclaim import check_freshness  # noqa: E402

with warnings.catch_warnings():
    warnings.simplefilter("ignore")


class CodexP2NoFreshnessFromTheFuture(unittest.TestCase):
    _REF = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def test_a_claim_dated_a_fraction_of_a_second_ahead_is_not_fresh(self):
        for ts in ("2026-01-01T00:00:00.400000Z", "2026-01-01T00:00:00.999000Z"):
            with self.subTest(timestamp=ts):
                self.assertIsNot(check_freshness({"timestamp": ts}, max_age_seconds=60, now=self._REF)["fresh"], True)

    def test_a_claim_a_fraction_past_the_bound_is_not_fresh(self):
        r = check_freshness({"timestamp": "2025-12-31T23:58:59.500000Z"}, max_age_seconds=60, now=self._REF)
        self.assertIs(r["fresh"], False, r)

    def test_the_reported_age_rounds_down(self):
        ahead = check_freshness({"timestamp": "2026-01-01T00:00:00.400000Z"}, max_age_seconds=60, now=self._REF)
        past = check_freshness({"timestamp": "2025-12-31T23:59:29.500000Z"}, max_age_seconds=60, now=self._REF)
        self.assertEqual((ahead["age_seconds"], past["age_seconds"]), (-1, 30))

    def test_control_exactly_at_the_bound_is_fresh(self):
        r = check_freshness({"timestamp": "2025-12-31T23:59:00Z"}, max_age_seconds=60, now=self._REF)
        self.assertEqual((r["age_seconds"], r["fresh"]), (60, True), r)

    def test_control_a_second_ahead_is_not_fresh_and_a_past_claim_is(self):
        self.assertIs(check_freshness({"timestamp": "2026-01-01T00:00:01Z"}, max_age_seconds=60,
                                      now=self._REF)["fresh"], False)
        self.assertIs(check_freshness({"timestamp": "2025-12-31T23:59:30Z"}, max_age_seconds=60,
                                      now=self._REF)["fresh"], True)


if __name__ == "__main__":
    unittest.main()
