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
import hashlib
import io
import json
import base64
import pathlib
import subprocess
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle.budget import DEFAULT_BUDGET
from proofbundle.signature import TRUST_ANCHOR_REFUSAL, ed25519_trust_anchor_weakness, verify_ed25519
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
        # Exactly fourteen files with fourteen different keys, and nothing else in the folder but the two
        # ordinary bundles (Codex on this change, round r1c: a set of keys allowed a duplicate file).
        self.assertEqual(len(forged), 14)
        self.assertEqual({_key_of(p) for p in forged}, ENCODINGS)
        self.assertEqual(sorted(p.name for p in FIXTURES.iterdir()),
                         sorted([p.name for p in forged] + ["gegenfall_gewoehnlich_falsche_signatur_bundle.json",
                                                            "kontrolle_gewoehnlich_richtige_signatur_bundle.json"]))
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
                self.assertIn(f"ed25519-signature: public key refused ({weakness}): "
                              f"{TRUST_ANCHOR_REFUSAL[weakness]}", out)
                self.assertNotIn("payload signed by stated key", out)

    def test_an_ordinary_key_is_judged_as_before(self):
        from proofbundle.bundle import verify_bundle
        kontrolle = json.loads((FIXTURES / "kontrolle_gewoehnlich_richtige_signatur_bundle.json").read_text(encoding="utf-8"))
        res = verify_bundle(kontrolle)
        self.assertIs(res.ok, True)
        self.assertEqual(res.verified_signer_pub, decode_b64(kontrolle["signature"]["public_key_b64"]))
        self.assertEqual(res.verified_payload_digest,
                         hashlib.sha256(decode_b64(kontrolle["payload_b64"])).hexdigest())
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


def _altered(target: pathlib.Path) -> dict:
    """The cases with the exit Python gives each. Measured 2026-11-19 at 803ada665ed0 with kreis_probe_paritaet_2.sh: six
    bundles altered at the signature block and two unchanged controls, the first eight cases. A base64 error in the key or
    the signature is malformed input (2); every defect after decoding is a signature that does not verify (1), whether
    the key is ordinary or weak. Measured 2026-11-20 at bab98cc30c27 with kreis_probe_paritaet_3.sh (review of this
    change, round r2b): the wrong signature and the weak key, each without `merkle.leaf_index`. Python records the failed
    check and reads on, so the defect is malformed input (2). The two cases with an `sd_jwt_vc` that is no object were
    not in that probe; they follow from `_require_dict` in bundle.py, and the test below runs them at both verifiers.
    Measured 2026-11-20 at main 11507531ada6 and at f50ea5ca6827, each with its own pb_verify_rs, with
    kreis_probe_paritaet_4.sh to _6.sh (round r3b): each value of `read_on`, once with the signature as it is and once
    with a wrong one, except `false` as the issuer key, which follows from `if sd.get(...)` in bundle.py. With a wrong
    signature, ten of them gave 1 in both on main and 2 in Rust after the read-on of this change."""
    control = json.loads((FIXTURES / "kontrolle_gewoehnlich_richtige_signatur_bundle.json").read_text(encoding="utf-8"))
    weak = json.loads((FIXTURES / "ord1_010000_bundle.json").read_text(encoding="utf-8"))
    b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731
    pk = decode_b64(control["signature"]["public_key_b64"])
    sig = decode_b64(control["signature"]["sig_b64"])
    wsig = decode_b64(weak["signature"]["sig_b64"])
    no_point = next(enc for enc in (y.to_bytes(32, "little") for y in range(2, 1000))
                    if _point_with_y(int.from_bytes(enc, "little")) is None)

    def wrong_signature(b):
        s = bytearray(decode_b64(b["signature"]["sig_b64"]))
        s[0] ^= 1
        b["signature"]["sig_b64"] = b64(bytes(s))

    def without_leaf_index(b):
        del b["merkle"]["leaf_index"]

    def failing_inclusion(b):
        b["merkle"]["tree_size"] += 1

    def sd_jwt_not_an_object(b):
        b["sd_jwt_vc"] = 5

    def merkle(field, value):
        def change(b):
            b["merkle"][field] = value
        return change

    def steps(n, last):
        return merkle("inclusion_proof_b64", [b64(bytes(32))] * (n - 1) + [last])

    url = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")  # noqa: E731
    head_and_body = url(json.dumps({"alg": "EdDSA"}).encode()) + "." + url(b"{}")
    jwt = lambda sig: f"{head_and_body}.{sig}"  # noqa: E731

    def sd_jwt(compact, key):
        def change(b):
            b["sd_jwt_vc"] = {"compact": compact, "issuer_public_key_b64": key}
        return change

    def sd_jwt_null(b):
        b["sd_jwt_vc"] = None

    budget = DEFAULT_BUDGET.merkle_path
    # Round r3b: what Python reads after a failed check and records as one more failed check. Each case with the
    # signature as it is and with a wrong one; with a wrong one 6.6.0 gave 1 and 1, the read-on of this change 1 and 2.
    read_on = {
        "negative_leaf_index": ((merkle("leaf_index", -1),), 1),
        "negative_tree_size": ((merkle("tree_size", -1),), 1),
        "proof_over_the_budget_with_a_step_not_base64": ((steps(budget + 1, "@@@@"),), 1),
        "proof_over_the_budget_with_a_step_no_string": ((steps(budget + 1, 5),), 1),
        "sd_jwt_null": ((sd_jwt_null,), 0),
        "issuer_jwt_not_base64url": ((sd_jwt("@@@.@@@.@@@", control["signature"]["public_key_b64"]),), 1),
        "issuer_key_31_bytes": ((sd_jwt(jwt(url(bytes(64))), b64(bytes(31))),), 1),
        "issuer_key_not_a_point": ((sd_jwt(jwt(url(bytes(64))), b64(no_point)),), 1),
        "issuer_signature_not_base64url": ((sd_jwt(jwt("@@@"), control["signature"]["public_key_b64"]),), 1),
        "issuer_key_empty": ((sd_jwt(jwt(url(bytes(64))), ""),), 1),
        "issuer_key_null": ((sd_jwt(jwt(url(bytes(64))), None),), 1),
        "issuer_key_false": ((sd_jwt(jwt(url(bytes(64))), False),), 1),
        # THE COUNTER-DIRECTION: what Python raises on stays malformed.
        "proof_at_the_budget_with_a_step_not_base64": ((steps(budget, "@@@@"),), 2),
        "issuer_key_not_base64_beside_a_compact_form_of_one_part": ((sd_jwt("x", "@@@@"),), 2),
        "issuer_key_no_string": ((sd_jwt("x", 5),), 2),
    }

    cases = {
        "control_unchanged": (control, {}, (), 0),
        "control_key_31_bytes": (control, {"public_key_b64": b64(pk[:31])}, (), 1),
        "control_key_not_a_point": (control, {"public_key_b64": b64(no_point)}, (), 1),
        "control_signature_63_bytes": (control, {"sig_b64": b64(sig[:63])}, (), 1),
        "control_signature_not_base64": (control, {"sig_b64": "@@@@"}, (), 2),
        "weak_unchanged": (weak, {}, (), 1),
        "weak_signature_63_bytes": (weak, {"sig_b64": b64(wsig[:63])}, (), 1),
        "weak_signature_not_base64": (weak, {"sig_b64": "@@@@"}, (), 2),
        "control_wrong_signature_without_leaf_index": (control, {}, (wrong_signature, without_leaf_index), 2),
        "weak_without_leaf_index": (weak, {}, (without_leaf_index,), 2),
        "control_wrong_signature_sd_jwt_not_an_object": (control, {}, (wrong_signature, sd_jwt_not_an_object), 2),
        "control_failing_inclusion_sd_jwt_not_an_object": (control, {}, (failing_inclusion, sd_jwt_not_an_object), 2),
        # The other arm of the inclusion check (cloud circle at 40a4d5f9, 2026-11-20): a proof that is never
        # computed, for a negative index or size or a path over the budget, followed by a structural defect. The
        # case above reaches only a proof that does not reach the root, so an early return in this arm passed.
        "control_negative_leaf_index_sd_jwt_not_an_object":
            (control, {}, (merkle("leaf_index", -1), sd_jwt_not_an_object), 2),
        "control_negative_tree_size_sd_jwt_not_an_object":
            (control, {}, (merkle("tree_size", -1), sd_jwt_not_an_object), 2),
        "control_proof_over_the_budget_sd_jwt_not_an_object":
            (control, {}, (steps(budget + 1, b64(bytes(32))), sd_jwt_not_an_object), 2),
    }
    for name, (changes, rc) in read_on.items():
        cases[f"control_{name}"] = (control, {}, changes, rc)
        cases[f"control_wrong_signature_{name}"] = (control, {}, (wrong_signature,) + changes, 2 if rc == 2 else 1)
    out = {}
    for name, (base, fields, changes, rc) in cases.items():
        b = json.loads(json.dumps(base))
        b["signature"].update(fields)
        for change in changes:
            change(b)
        path = target / f"{name}.json"
        path.write_text(json.dumps(b), encoding="utf-8")
        out[name] = (path, rc)
    return out


class PythonAndRustGiveTheSameExit(unittest.TestCase):
    """The review of this change (round r1c) measured four bundles where the two verifiers parted: Rust gave exit 2 for a
    key or a signature of another length and for a key that is not a point, where Python gives 1, and the first version of
    this change refused a weak key in Rust before decoding the signature, so a weak key beside a signature that is not
    base64 gave 1 where Python gives 2. Each case is held at both verifiers, with the exit Python was measured to give.

    Round r2b found the second shape, measured on 6.6.0 as well: Rust stopped at the first check that did not hold, while
    Python reads the rest of the bundle, so a structural defect after a failed signature or inclusion proof was exit 1
    there and 2 here. A weak own key with such a defect joined that shape with this change (2 and 2 on 6.6.0). Four
    cases of `_altered` carry it.

    Round r3b found that reading on reached values Rust refused as malformed where Python records a failed check, a
    negative merkle integer, a proof over the path budget, `sd_jwt_vc: null` and defects of the SD-JWT issuer part. Each
    is a case here with both signatures, and so are the values Python refuses as malformed in the same places.

    The mutants of the merged head (cloud circle at 40a4d5f9) found an arm of the inclusion check that no case reached
    with a defect after it, a proof that is never computed for a negative index or size or a path over the budget. Three
    cases carry it."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.cases = _altered(pathlib.Path(cls.tmp.name))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_python_gives_the_measured_exit(self):
        for name, (path, rc) in self.cases.items():
            with self.subTest(case=name):
                got, out, err = _cli("verify", str(path))
                self.assertEqual(got, rc, out + err)

    def test_rust_gives_the_exit_python_gives(self):
        binary = binary_or_skip()
        for name, (path, rc) in self.cases.items():
            with self.subTest(case=name):
                p = subprocess.run([str(binary), "verify-bundle", str(path)], capture_output=True, text=True, timeout=120)
                self.assertEqual(p.returncode, rc, p.stdout + p.stderr)


if __name__ == "__main__":
    unittest.main()
