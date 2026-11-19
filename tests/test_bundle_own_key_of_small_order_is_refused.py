"""The bundle's own Ed25519 key is judged by the trust-anchor rule (SPEC section 4b, since 6.6.1).

Until 6.6.0 `bundle.py` and `verify_bundle` in `pb_verify_rs` checked the bundle's own
`signature.public_key_b64` with the bare section 4a profile, because trust in it comes from a policy pin
that has the rule. Without a pin, a forgery under a key of small order, made with no private key, read
"payload signed by stated key" with exit 0, in Python and in Rust, for each of the fourteen 32-byte
encodings of the eight points of small order (measured on 2026-11-19 at ca4c7afe).

The fixtures in tests/fixtures/ed25519_small_order_inband are those forgeries, one bundle per encoding
(`ord<order>_<first three bytes>_bundle.json`), a bundle with an ordinary key and a wrong signature
(`gegenfall_…`) and one with an ordinary key and a right signature (`kontrolle_…`). They were built from
examples/example_bundle.json with only the signature block replaced, each forgery as R = [S]B - [k]A with
k = SHA-512(R || A || M), retried until [k]A is the identity.

WHICH encodings are the fourteen is not read from the fixtures nor from `signature.py`. The oracle below
derives the 8-torsion subgroup with its own curve arithmetic, [L]Q for points Q of the curve, and spells
each point in every 32-byte way: y and, where y + p < 2**255, also y + p, each with the x-sign bit of the
point, and with both sign bits where x = 0. The fixtures must cover exactly those spellings, and the bare
section 4a check must accept each forgery, so every refusal below can fall: with the rule removed from the
bundle path the forgeries pass again (measured as mutants on this change).
"""

from __future__ import annotations

import contextlib
import io
import json
import pathlib
import subprocess
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle.signature import ed25519_trust_anchor_weakness, verify_ed25519
from proofbundle._wire_b64 import decode_b64

from _pb_verify_rs import binary_or_skip

FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures" / "ed25519_small_order_inband"

# ── the oracle: curve arithmetic of RFC 8032, kept to this file ──────────────────────────────────────
_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)
_O = (0, 1)


def _add(a, b):
    (x1, y1), (x2, y2) = a, b
    t = _D * x1 * x2 * y1 * y2 % _P
    return ((x1 * y2 + x2 * y1) * pow(1 + t, _P - 2, _P) % _P,
            (y1 * y2 + x1 * x2) * pow(1 - t, _P - 2, _P) % _P)


def _mul(n, a):
    r = _O
    while n:
        if n & 1:
            r = _add(r, a)
        a = _add(a, a)
        n >>= 1
    return r


def _point_with_y(y):
    u, v = (y * y - 1) % _P, (_D * y * y + 1) % _P
    x2 = u * pow(v, _P - 2, _P) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P:
        return None
    return (x, y)


def _torsion_points():
    found = {_O}
    y = 2
    while len(found) < 8 and y < 1000:
        q = _point_with_y(y)
        y += 1
        if q is None:
            continue
        t = _mul(_L, q)
        for k in range(8):
            found.add(_mul(k, t))
    return found


def _encodings(points):
    out = set()
    for x, y in points:
        for yy in (y, y + _P):
            if yy >= 2 ** 255:
                continue
            for s in ((0, 1) if x == 0 else (x & 1,)):
                out.add((yy | (s << 255)).to_bytes(32, "little"))
    return out


TORSION = _torsion_points()
ENCODINGS = _encodings(TORSION)


def _cli(*args):
    from proofbundle.cli import main
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = main(list(args))
    return rc, out.getvalue(), err.getvalue()


def _key_of(path):
    return decode_b64(json.loads(path.read_text(encoding="utf-8"))["signature"]["public_key_b64"])


def _forgeries():
    return sorted(FIXTURES.glob("ord*_bundle.json"))


class TheOracle(unittest.TestCase):

    def test_it_derives_eight_points_of_small_order_and_fourteen_spellings(self):
        self.assertEqual(len(TORSION), 8)
        for p in TORSION:
            self.assertEqual(_mul(8, p), _O, p)
        self.assertEqual(len([p for p in TORSION if _mul(4, p) != _O]), 4, "four points of order 8")
        self.assertEqual(len(ENCODINGS), 14)

    def test_the_rule_refuses_every_spelling_and_no_ordinary_key(self):
        for enc in ENCODINGS:
            with self.subTest(key=enc.hex()):
                self.assertIn(ed25519_trust_anchor_weakness(enc), ("low-order", "non-canonical"))
        for _ in range(16):
            key = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
            self.assertIsNone(ed25519_trust_anchor_weakness(key), key.hex())


class TheFixtures(unittest.TestCase):

    def test_they_are_the_fourteen_spellings_and_real_forgeries(self):
        """Counter-direction: each forgery passes the bare section 4a check, so its refusal below is the
        rule's doing and not a broken fixture."""
        forged = _forgeries()
        self.assertEqual({_key_of(p) for p in forged}, ENCODINGS)
        for path in forged:
            b = json.loads(path.read_text(encoding="utf-8"))
            with self.subTest(fixture=path.name):
                self.assertTrue(verify_ed25519(decode_b64(b["signature"]["public_key_b64"]),
                                               decode_b64(b["signature"]["sig_b64"]),
                                               decode_b64(b["payload_b64"])))


class PythonVerify(unittest.TestCase):

    def test_each_forgery_fails_the_signature_check_with_the_reason(self):
        for path in _forgeries():
            weakness = ed25519_trust_anchor_weakness(_key_of(path))
            with self.subTest(fixture=path.name):
                rc, out, err = _cli("verify", str(path))
                self.assertEqual(rc, 1, out + err)
                self.assertIn(f"ed25519-signature: public key refused ({weakness})", out)
                self.assertNotIn("payload signed by stated key", out)

    def test_an_ordinary_key_is_judged_as_before(self):
        rc, out, err = _cli("verify", str(FIXTURES / "kontrolle_gewoehnlich_richtige_signatur_bundle.json"))
        self.assertEqual(rc, 0, out + err)
        self.assertIn("payload signed by stated key", out)
        rc, out, err = _cli("verify", str(FIXTURES / "gegenfall_gewoehnlich_falsche_signatur_bundle.json"))
        self.assertEqual(rc, 1, out + err)
        self.assertIn("ed25519-signature: invalid signature", out)


class RustVerifyBundle(unittest.TestCase):

    def _run(self, path):
        p = subprocess.run([str(binary_or_skip()), "verify-bundle", str(path)],
                           capture_output=True, text=True, timeout=120)
        return p.returncode, p.stdout.strip()

    def test_each_forgery_fails(self):
        for path in _forgeries():
            with self.subTest(fixture=path.name):
                self.assertEqual(self._run(path), (1, "FAIL"))

    def test_an_ordinary_key_is_judged_as_before(self):
        self.assertEqual(self._run(FIXTURES / "kontrolle_gewoehnlich_richtige_signatur_bundle.json"), (0, "OK"))
        self.assertEqual(self._run(FIXTURES / "gegenfall_gewoehnlich_falsche_signatur_bundle.json"), (1, "FAIL"))


if __name__ == "__main__":
    unittest.main()
