"""The two command-line readers of `HEIGHT:MERKLEROOT_HEX` build what the trust-policy loader takes.

Follow-up of the reading of pull request 439 (a P2 on its target Z2) and of its neighbour. `--bitcoin-header`
(`cli._build_rp_trust`, read by `verify`, `decision verify` and `anchor verify-pack`) checked a root with
`bytes.fromhex`, which takes ASCII white space between the byte pairs, and put that root, white space and all, into the
relying party's header map, while the policy loader takes a root only as 64 hex digits (OQ-19). So the two ways of
supplying the same trust material took different values. `--bundled-header` of `anchor upgrade`
(`cli._parse_bundled_headers`) read the same form with the same root check, and its height with `str.isdigit()`, which
also holds for digits of other scripts, the defect OQ-20 closed for `--bitcoin-header` alone.

The oracle here is written out by hand and does not use the patterns of the policy loader: a height is ASCII digits and
a root is 64 characters of 0-9, a-f and A-F, each after the white space around it is stripped.
"""
import argparse
import contextlib
import io
import json
import os
import random
import tempfile
import unittest

from proofbundle import emit_bundle, generate_signer
from proofbundle.cli import _build_rp_trust, _parse_bundled_headers, main

_DIGITS = frozenset("0123456789")
_HEX = frozenset("0123456789abcdefABCDEF")
_ROOT = "ab" * 32


def _oracle(spec: str):
    """(height, root) as the policy loader would hold them, or None when it would refuse them."""
    if ":" not in spec:
        return None
    height, _, root = spec.partition(":")
    height, root = height.strip(), root.strip()
    if not height or not set(height) <= _DIGITS:
        return None
    if len(root) != 64 or not set(root) <= _HEX:
        return None
    return height, root.lower()


def _rp(spec: str) -> dict:
    return _build_rp_trust(argparse.Namespace(trusted_tsa_root=None, bitcoin_header=[spec]))["bitcoin_block_headers"]


def _bundled(spec: str) -> dict:
    return _parse_bundled_headers([spec])


READERS = {"--bitcoin-header": _rp, "--bundled-header": _bundled}


def _specs(n: int = 600, seed: int = 20261030) -> list[str]:
    """Generated specs around the boundary: valid ones, and valid ones with one change each."""
    rnd = random.Random(seed)
    changes = [
        lambda h, r: (h, r[:2] + " " + r[2:]),           # a space between two byte pairs
        lambda h, r: (h, " ".join(r[i:i + 2] for i in range(0, 64, 2))),
        lambda h, r: (h, r[:10] + "\t" + r[10:]),
        lambda h, r: (h, r[:-1]),                        # 63 digits
        lambda h, r: (h, r + "0"),                       # 65 digits
        lambda h, r: (h, r[:5] + "g" + r[6:]),
        lambda h, r: (h, r[:5] + "\uff21" + r[6:]),      # a fullwidth A
        lambda h, r: (h, r.upper()),
        lambda h, r: (" " + h + " ", " " + r + "\n"),    # white space around both
        lambda h, r: ("\u0663", r),                      # an Arabic-Indic three
        lambda h, r: ("8\u0660", r),
        lambda h, r: ("\uff18\uff10\uff10", r),          # fullwidth digits
        lambda h, r: ("\u00b2", r),
        lambda h, r: (h + " 1", r),
        lambda h, r: ("", r),
        lambda h, r: ("-1", r),
        lambda h, r: (h, ""),
    ]
    out = []
    for _ in range(n):
        h = str(rnd.randrange(0, 10 ** rnd.randrange(1, 8)))
        r = "".join(rnd.choice("0123456789abcdef") for _ in range(64))
        if rnd.random() < 0.8:
            h, r = rnd.choice(changes)(h, r)
        out.append(f"{h}:{r}")
    return out


class TestBothHeaderOptionsBuildWhatThePolicyTakes(unittest.TestCase):
    def test_a_generated_spec_is_taken_exactly_when_the_policy_would_take_it(self):
        specs = _specs()
        self.assertTrue(any(_oracle(s) is None for s in specs) and any(_oracle(s) for s in specs))
        for flag, read in READERS.items():
            for spec in specs:
                expected = _oracle(spec)
                with self.subTest(flag=flag, spec=spec):
                    if expected is None:
                        with self.assertRaises(ValueError):
                            read(spec)
                    else:
                        self.assertEqual(read(spec), {expected[0]: expected[1]})

    def test_a_root_with_white_space_between_its_pairs_is_refused(self):
        spaced = " ".join(_ROOT[i:i + 2] for i in range(0, 64, 2))
        for flag, read in READERS.items():
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                read(f"800000:{spaced}")

    def test_control_a_plain_root_and_white_space_around_it_are_taken(self):
        for flag, read in READERS.items():
            with self.subTest(flag=flag):
                self.assertEqual(read("800000:" + _ROOT.upper()), {"800000": _ROOT})
                self.assertEqual(read(" 800001 : " + _ROOT + " "), {"800001": _ROOT})

    def test_the_command_line_refuses_a_spaced_root_as_malformed_input(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump(emit_bundle(b'{"x": 1}', generate_signer()), f)
        self.addCleanup(os.remove, path)

        def run(root):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                return main(["verify", path, "--require-anchor", "--bitcoin-header", f"800000:{root}"])

        self.assertEqual(run(_ROOT), 3)   # taken; the bundle carries no anchor, so the requirement is unmet
        self.assertEqual(run(" ".join(_ROOT[i:i + 2] for i in range(0, 64, 2))), 2)


if __name__ == "__main__":
    unittest.main()
