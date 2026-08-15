"""`verify-proof` must let a relying party pin the checkpoint ORIGIN from the command line.

`verify_tlog_proof` has taken `expected_origin` since the release-review origin-acceptance fix, but
the argparse parser carried no flag and the command never passed one. A command-line verifier could
therefore not reject a validly signed checkpoint issued by a DIFFERENT log than the one it meant to
trust: the signature check passes, and without the origin constraint nothing else looks wrong. The
library-level path is already covered by tests/test_anchors_markovian_log.py; these tests pin the
CLI pass-through so the gap cannot silently reopen.

Vectors are the frozen markovianprotocol.com/log leaf 7271 fixture. Nothing is fetched, and no
optional extra is needed: Ed25519 verification rides on `cryptography`, a hard dependency.
"""
from __future__ import annotations

import contextlib
import io
import json
import pathlib
import unittest

_FIXDIR = pathlib.Path(__file__).parent / "fixtures" / "anchors" / "markovian_log" / "proof_7271"
_PROOF = _FIXDIR / "proof_7271.tlog-proof"
_LEAF = _FIXDIR / "leaf_7271.raw"
_KEYS = _FIXDIR / "keys_unabhaengig.txt"
_ORIGIN = "markovianprotocol.com/log"
_WRONG_ORIGIN = "example.invalid/some-other-log"


def _log_vkey() -> str:
    """The log's verifier key, read from the fixture's key list, not from the audited log."""
    for line in _KEYS.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and line.startswith(_ORIGIN + "+"):
            return line
    raise AssertionError("log vkey not found in keys_unabhaengig.txt")


def _run(*extra: str) -> tuple[int, str]:
    """Run the CLI in-process and return (exit code, stdout)."""
    from proofbundle.cli import main
    argv = ["verify-proof", str(_PROOF), "--payload-file", str(_LEAF),
            "--log-vkey", _log_vkey(), "--json", *extra]
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = main(argv)
    return rc, buf.getvalue()


@unittest.skipUnless(_PROOF.is_file(), "markovian_log fixture not vendored")
class TestVerifyProofExpectedOrigin(unittest.TestCase):

    def test_flag_is_discoverable(self) -> None:
        """A capability nobody can find is not a capability."""
        from proofbundle.cli import main
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), self.assertRaises(SystemExit):
            main(["verify-proof", "--help"])
        self.assertIn("--expected-origin", buf.getvalue())

    def test_default_leaves_origin_unconstrained(self) -> None:
        """Omitting the flag keeps the documented default, so existing invocations keep their verdict."""
        rc, out = _run()
        self.assertEqual(rc, 0)
        res = json.loads(out)
        self.assertTrue(res["ok"])
        self.assertEqual(res["origin"], _ORIGIN)

    def test_matching_origin_still_passes(self) -> None:
        """Pinning the origin the checkpoint actually carries must not change the verdict."""
        rc, out = _run("--expected-origin", _ORIGIN)
        self.assertEqual(rc, 0)
        res = json.loads(out)
        self.assertTrue(res["ok"])
        self.assertTrue(res["log_ok"])

    def test_mismatching_origin_fails_closed(self) -> None:
        """A validly signed checkpoint from the wrong log is rejected, and the reason is the origin."""
        rc, out = _run("--expected-origin", _WRONG_ORIGIN)
        self.assertEqual(rc, 1)
        res = json.loads(out)
        self.assertFalse(res["ok"])
        self.assertFalse(res["log_ok"])
        # the crypto is untouched: inclusion still holds and the reported origin is the real one
        self.assertTrue(res["inclusion_ok"])
        self.assertEqual(res["origin"], _ORIGIN)

    def test_text_output_names_the_expectation(self) -> None:
        """On the human path a FAIL must not read like a broken signature."""
        from proofbundle.cli import main
        buf = io.StringIO()
        argv = ["verify-proof", str(_PROOF), "--payload-file", str(_LEAF),
                "--log-vkey", _log_vkey(), "--expected-origin", _WRONG_ORIGIN]
        with contextlib.redirect_stdout(buf):
            rc = main(argv)
        self.assertEqual(rc, 1)
        self.assertIn(_WRONG_ORIGIN, buf.getvalue())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
