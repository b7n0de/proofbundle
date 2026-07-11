"""WP-D1 (6-lens review): a pre-auth parser must never surface a raw ValueError from Python's
int<->str conversion cap (CWE-674 / CVE-2020-10735). An oversized decimal (a JSON integer literal,
or a checkpoint tree-size / tlog-proof index line) is bounded BEFORE int() and mapped to a clean
BundleFormatError — never an uncaught traceback."""
import unittest

from proofbundle import checkpoint as cp
from proofbundle._strict_json import loads_strict
from proofbundle.emit import generate_signer
from proofbundle.errors import BundleFormatError


def _raw_pub(s):
    return s.public_key().public_bytes_raw()


class TestOversizedIntGuard(unittest.TestCase):
    def test_loads_strict_huge_integer_literal_is_clean_error(self):
        huge = '{"n": ' + "9" * 5000 + "}"
        try:
            loads_strict(huge)
            self.fail("expected a BundleFormatError for an oversized integer literal")
        except BundleFormatError:
            pass                                  # mapped, fail-closed
        except ValueError as exc:                 # a RAW int-conversion ValueError is the regression
            if "integer string conversion" in str(exc):
                self.fail("oversized integer literal surfaced a raw ValueError (D-1 regression)")
            raise

    def test_checkpoint_oversized_tree_size_is_clean_error(self):
        s = generate_signer()
        note = cp.sign_checkpoint("origin.example", 42, b"\x00" * 32, s, "origin.example")
        vk = cp.vkey("origin.example", _raw_pub(s))
        lines = note.split("\n")
        lines[1] = "9" * 5000                      # oversized tree_size, valid vkey
        with self.assertRaises(BundleFormatError):  # bounded before int(), never a raw ValueError
            cp.verify_checkpoint("\n".join(lines), vk)


if __name__ == "__main__":
    unittest.main()
