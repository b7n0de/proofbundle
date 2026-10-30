"""OQ-20 (owner answer of 2026-10-27): `--bitcoin-header` takes a height only when it is a string of ASCII digits, as the
trust-policy loader does since OQ-19.

Before this, the command line asked `str.isdigit()` of a height, which also holds for digits of other scripts (an
Arabic-Indic "٣", a fullwidth "８００", a superscript "²"), and put such a height into the relying party's header map,
where no attested height can ever match it: a required anchor then stayed unmet (exit 3) instead of the flag being
refused. Such a height is now malformed input (exit 2), like a root that is not 32 bytes of hex.
"""
import argparse
import contextlib
import io
import json
import os
import tempfile
import unittest

from proofbundle import emit_bundle, generate_signer
from proofbundle.cli import _build_rp_trust, main

_ROOT = "ab" * 32


def _rp(*specs):
    return _build_rp_trust(argparse.Namespace(trusted_tsa_root=None, bitcoin_header=list(specs)))


class TestBitcoinHeaderHeightIsAscii(unittest.TestCase):
    def test_an_ascii_height_is_taken(self):
        for spec, height in (("800000:" + _ROOT, "800000"), ("0:" + _ROOT, "0"), (" 800001 :" + _ROOT, "800001")):
            with self.subTest(spec=spec):
                self.assertEqual(_rp(spec)["bitcoin_block_headers"], {height: _ROOT})

    def test_a_height_of_digits_of_another_script_is_refused(self):
        for height in ("٣", "８００", "8٠", "²"):
            with self.subTest(height=height), self.assertRaises(ValueError):
                _rp(f"{height}:{_ROOT}")

    def test_the_command_line_refuses_it_as_malformed_input(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump(emit_bundle(b'{"x": 1}', generate_signer()), f)
        self.addCleanup(os.remove, path)

        def run(height):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                return main(["verify", path, "--require-anchor", "--bitcoin-header", f"{height}:{_ROOT}"])

        self.assertEqual(run("800000"), 3)   # taken; the bundle carries no anchor, so the requirement is unmet
        for height in ("٣", "８００"):
            with self.subTest(height=height):
                self.assertEqual(run(height), 2)


if __name__ == "__main__":
    unittest.main()
