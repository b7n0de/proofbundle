"""OQ-19 (owner answer of 2026-10-26): the trust-policy loader takes a Bitcoin block header map only when every height is
a string of ASCII digits and every merkle root is 64 hex digits.

Before this, the loader asked `str.isdigit()` of a height, which also holds for digits of other scripts (an Arabic-Indic
"٣", a fullwidth "８００"), and only the length of a root, so a root of 64 characters that are not hex was taken; its own
message already asked for "a decimal height string to a 64-char hex merkle root". `--bitcoin-header` on the command line
refuses such a root (exit 2), and the policy file now refuses it too, so the two ways of supplying relying-party trust
material agree. The OTS verdict `bad_header` stays reachable through the library API, which takes any mapping.
"""
import unittest

from proofbundle.policy import PolicyError, load_policy

_ROOT = "ab" * 32


def _policy(headers):
    return {"schema": "proofbundle/trust-policy/v0.2", "policy_id": "oq19",
            "anchors": {"bitcoin_block_headers": headers}}


class TestBitcoinBlockHeadersAreAsciiAndHex(unittest.TestCase):
    def test_ascii_height_and_hex_root_are_taken(self):
        for headers in ({"800000": _ROOT}, {"0": _ROOT.upper()}, {"1": "0123456789abcdefABCDEF" + "0" * 42}, {}):
            with self.subTest(headers=headers):
                load_policy(_policy(headers))

    def test_a_height_of_digits_of_another_script_is_refused(self):
        for height in ("٣", "８００", "8٠", "²"):
            with self.subTest(height=height), self.assertRaises(PolicyError):
                load_policy(_policy({height: _ROOT}))

    def test_a_root_of_64_characters_that_are_not_hex_is_refused(self):
        for root in ("zz" * 32, "g" + "a" * 63, " " * 64, "ab" * 31 + "a ", "٣" * 64):
            with self.subTest(root=root), self.assertRaises(PolicyError):
                load_policy(_policy({"800000": root}))

    def test_a_root_of_another_length_is_still_refused(self):
        for root in ("ab" * 31, "ab" * 33, ""):
            with self.subTest(root=root), self.assertRaises(PolicyError):
                load_policy(_policy({"800000": root}))


if __name__ == "__main__":
    unittest.main()
