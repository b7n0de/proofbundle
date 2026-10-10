"""6.2.1 R6b-5: a ``--verification-time`` with any nonzero fractional second is a format error, whatever its
length; the whole-second contract is checked on the input text, before a lossy parse (``cli._historical_now_posix``,
shared with ``verify-enclave``).

Red at v6.2.0.
"""



from __future__ import annotations

import sys
import tempfile
import unittest
import warnings
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
for _p in (str(REPO / "src"), str(REPO / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import test_security_fix_620_zeit_r6a as R6A  # noqa: E402

from proofbundle.cli import _historical_now_posix  # noqa: E402

with warnings.catch_warnings():
    warnings.simplefilter("ignore")


_T0 = 1767225600   # 2026-01-01T00:00:00Z


class R6b5FractionRefusedOnTheText(unittest.TestCase):
    def test_a_sub_microsecond_fraction_is_a_format_error(self):
        for text in ("2026-01-01T00:00:00.0000001Z", "2026-01-01T00:00:00.0000000001Z"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                _historical_now_posix(text)

    def test_a_comma_separated_sub_microsecond_fraction_is_a_format_error(self):
        """ISO 8601 allows a comma as the decimal sign. From Python 3.11 the parser takes it and keeps six
        digits, so `,0000001Z` reached the guard as microsecond 0 while the text check looked only after a
        period. Red at 9b0d6520 under Python 3.11; under 3.10 the parse already refuses the form."""
        for text in ("2026-01-01T00:00:00,0000001Z", "2026-01-01T00:00:00,0000000001Z"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                _historical_now_posix(text)

    def test_the_cli_refuses_it_and_judges_no_policy(self):
        env, pub, aud, nonce, _sk = R6A._signed_receipt()
        pol = {"schema": "proofbundle/trust-policy/v0.2", "policy_id": "r6b-5",
               "decision_receipt": {"trusted_decision_makers": [{"public_key_b64": pub}]},
               "valid_until": "2026-01-01T00:00:00Z"}
        with tempfile.TemporaryDirectory() as tmp:
            rp, pp = R6A._write(tmp, "r.json", env), R6A._write(tmp, "p.json", pol)
            rc, _out = R6A._cli_run(["decision", "verify", rp, "--pub", pub, "--strict", "--aud", aud,
                                     "--nonce", nonce, "--policy", pp,
                                     "--verification-time", "2026-01-01T00:00:00.0000001Z", "--json"])
        self.assertEqual(rc, 2, "a nonzero fraction of any length is a format error (exit 2)")

    def test_control_a_microsecond_fraction_and_a_whole_second(self):
        with self.assertRaises(ValueError):
            _historical_now_posix("2026-01-01T00:00:00.000001Z")
        self.assertEqual(_historical_now_posix("2026-01-01T00:00:00Z"), _T0)
        self.assertEqual(_historical_now_posix("2026-01-01T00:00:00.000Z"), _T0)


if __name__ == "__main__":
    unittest.main()
