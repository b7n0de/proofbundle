"""Second-implementation conformance test for MarkovianProtocol's rootcommit vectors (v1 + v2-sig).

proofbundle's OWN `anchors_rootcommit` verifier reproduces the upstream expected outcomes over the 9
vendored vectors, fully offline (no calendar, no Bitcoin node), by independently rebuilding the
domain-separated preimage from each checkpoint's own (origin, size, root) plus the wallet in the anchor
line, recomputing SHA-256(preimage), and reusing proofbundle's OpenTimestamps binding verifier.

Dependency split: the v1 verify and the v2-sig BINDING checks need only proofbundle[anchors]
(opentimestamps); the v2-sig SIGNATURE checks (EIP-191 recovery) additionally need a secp256k1+keccak
backend and skip cleanly if none is installed (never a silent pass). Vendored data + provenance pins are
covered by tests/test_anchors_markovian.py::TestRootcommitVectorsManifest.
"""
from __future__ import annotations

import pathlib
import unittest

try:
    import opentimestamps  # noqa: F401
    _HAS_OTS = True
except ImportError:
    _HAS_OTS = False

from proofbundle import anchors_rootcommit as rc

_FIXDIR = pathlib.Path(__file__).parent / "fixtures" / "anchors" / "tlog_bitcoin_anchor" / "rootcommit"
_COMMITMENT = "4d1cc236c3872701bb27f9e27fad315e153eeb43a767a2cae958a3bb4014e771"
_WALLET = "0xdaE76a3C848CafD453dB5EBF8cEb0DbBA7610273"


def _read(rel: str) -> str:
    return (_FIXDIR / rel).read_text()


def _has_sig_backend() -> bool:
    # r = 1, s = 1, v = 27: inside every range eip191 checks before recovery, so the call reaches the
    # backend import. The earlier probe, 65 zero bytes, stopped reaching it once s = 0 was refused
    # up front (finding D1), and would then have reported a backend that is not installed.
    probe = (1).to_bytes(32, "big") + (1).to_bytes(32, "big") + bytes([27])
    try:
        rc.eip191_recover_address("probe", probe)   # returns an address or None if a backend exists
        return True
    except rc._NoSigLib:
        return False


_HAS_SIG = _has_sig_backend()


@unittest.skipUnless(_HAS_OTS, "needs proofbundle[anchors] (opentimestamps)")
class TestRootcommitV1(unittest.TestCase):
    def test_01_valid_binds_through_our_preimage(self):
        res = rc.verify_rootcommit_v1(_read("vectors/rootcommit-01-valid.txt"))
        self.assertEqual(res["known_anchors"], 1)
        # SECOND-IMPLEMENTATION: our independently rebuilt preimage hashes to the upstream committed value
        self.assertEqual(res["commitment"], _COMMITMENT)
        self.assertEqual(res["wallet"].lower(), _WALLET.lower())
        self.assertTrue(res["binding"], res["detail"])     # OTS proof commits exactly our commitment
        self.assertFalse(res["reject"])

    def test_02_tampered_root_rejects(self):
        res = rc.verify_rootcommit_v1(_read("vectors/rootcommit-02-tampered-root.txt"))
        self.assertEqual(res["known_anchors"], 1)
        self.assertNotEqual(res["commitment"], _COMMITMENT)  # altered root → different preimage
        self.assertFalse(res["binding"])
        self.assertTrue(res["reject"])
        self.assertEqual(res["status"], "unbound")

    def test_03_tampered_wallet_rejects(self):
        # the property ots/v1 does NOT have: mutating the wallet (in the opaque) breaks the binding
        res = rc.verify_rootcommit_v1(_read("vectors/rootcommit-03-tampered-wallet.txt"))
        self.assertEqual(res["known_anchors"], 1)
        self.assertNotEqual(res["commitment"], _COMMITMENT)
        self.assertFalse(res["binding"])
        self.assertTrue(res["reject"])
        self.assertEqual(res["status"], "unbound")

    def test_04_tampered_proof_rejects(self):
        res = rc.verify_rootcommit_v1(_read("vectors/rootcommit-04-tampered-proof.txt"))
        self.assertEqual(res["known_anchors"], 1)
        self.assertFalse(res["binding"])
        self.assertTrue(res["reject"])
        self.assertIn(res["status"], ("unbound", "malformed"))

    def test_multiple_anchors_rejected_fail_closed(self):
        # adversarial-deep-gate MEDIUM (wf_391ec78f): the anchor is a 0xff signed-note signature that does NOT sign the
        # note body, so an attacker can PREPEND a forged rootcommit anchor carrying THEIR wallet without
        # invalidating the genuine witness cosignatures. The verifier must count ALL anchors and fail closed,
        # never silently pick opaques[0] and report known_anchors=1. (The 9 vendored vectors carry exactly one
        # anchor each, so this multiplicity is only exercised here.)
        import base64
        text = _read("vectors/rootcommit-01-valid.txt")
        id_v1 = rc.ID_V1.encode()
        attacker = b"0xATTACKERwa11etAAAAAAAAAAAAAAAAAAAAAAAAAA"
        opaque = b"\x01" + bytes([len(attacker)]) + attacker + b"\x00\x00\x00"   # well-formed line, junk ots
        payload = rc.expected_key_id(id_v1) + bytes([rc.SIG_TYPE]) + bytes([len(id_v1)]) + id_v1 + opaque
        forged = f"— {rc.KEY_NAME} " + base64.b64encode(payload).decode()
        body, sigs = text.split("\n\n", 1)
        tampered = body + "\n\n" + forged + "\n" + sigs   # prepend the forged anchor before the genuine one
        res = rc.verify_rootcommit_v1(tampered)
        self.assertEqual(res["known_anchors"], 2)          # the REAL count, not a hardcoded 1
        self.assertTrue(res["reject"])
        self.assertEqual(res["status"], "multiple_anchors")
        self.assertFalse(res["binding"])
        self.assertNotIn("wallet", res)                    # no single-wallet attribution on multiplicity


class TestRootcommitNeverRaise(unittest.TestCase):
    """adversarial-deep-gate learned class RT-04 (never-raise), caught by the canonical self-learning pre-sweep (the ad-hoc
    gate missed it): the public verify surfaces return a stable dict carrying the core verdict keys on ANY
    untrusted input (incl. non-str), never a raw exception. No OTS needed (malformed inputs return early)."""
    _CORE = {"known_anchors", "binding", "reject", "status"}

    def test_verify_surfaces_never_raise_on_untrusted_input(self):
        bad_inputs = ["", "no separator", "a\n\nb", "\n\n\n", "x" * 50000,
                      "a.b.c\n\n— markovianprotocol.com/bitcoin-anchor !!notb64!!",
                      b"bytes", None, 123, ["list"], {"d": 1}]
        for fn in (rc.verify_rootcommit_v1, rc.verify_rootcommit_v2sig):
            for bad in bad_inputs:
                res = fn(bad)
                self.assertIsInstance(res, dict)
                self.assertTrue(self._CORE <= set(res),
                                f"{fn.__name__}({bad!r:.20}) missing core verdict keys: {set(res)}")


@unittest.skipUnless(_HAS_OTS, "needs proofbundle[anchors] (opentimestamps)")
class TestRootcommitV2SigBinding(unittest.TestCase):
    """The BINDING half of v2-sig is dep-free (same OTS commit check as v1). The three tamper-of-binding
    vectors reject on binding alone, no signature backend needed."""

    def test_01_valid_binds(self):
        res = rc.verify_rootcommit_v2sig(_read("vectors_sig/v2sig-01-valid.txt"))
        self.assertEqual(res["known_anchors"], 1)
        self.assertEqual(res["commitment"], _COMMITMENT)
        self.assertTrue(res["binding"], res.get("detail"))

    def test_02_tampered_root_rejects_on_binding(self):
        res = rc.verify_rootcommit_v2sig(_read("vectors_sig/v2sig-02-tampered-root.txt"))
        self.assertFalse(res["binding"])
        self.assertTrue(res["reject"])

    def test_03_tampered_wallet_rejects_on_binding(self):
        res = rc.verify_rootcommit_v2sig(_read("vectors_sig/v2sig-03-tampered-wallet.txt"))
        self.assertFalse(res["binding"])
        self.assertTrue(res["reject"])

    def test_05_tampered_proof_rejects_on_binding(self):
        res = rc.verify_rootcommit_v2sig(_read("vectors_sig/v2sig-05-tampered-proof.txt"))
        self.assertFalse(res["binding"])
        self.assertTrue(res["reject"])

    def test_no_silent_pass_without_sig_backend(self):
        # honest degradation: without a secp256k1+keccak backend, sig_ok is None (never a silent True)
        res = rc.verify_rootcommit_v2sig(_read("vectors_sig/v2sig-01-valid.txt"))
        if not _HAS_SIG:
            self.assertIsNone(res["sig_ok"])
            self.assertEqual(res["sig_status"], "no_sig_lib")


@unittest.skipUnless(_HAS_OTS and _HAS_SIG, "needs proofbundle[anchors] + a secp256k1/keccak backend")
class TestRootcommitV2SigSignature(unittest.TestCase):
    """The SIGNATURE half of v2-sig: EIP-191 recovery to the bound wallet. Needs a secp256k1+keccak backend."""

    def test_01_valid_signature_recovers_to_wallet(self):
        res = rc.verify_rootcommit_v2sig(_read("vectors_sig/v2sig-01-valid.txt"))
        self.assertTrue(res["binding"])
        self.assertTrue(res["sig_ok"])
        self.assertFalse(res["reject"])

    def test_04_tampered_signature_rejects(self):
        # binding still holds (root/wallet intact) but the corrupted signature no longer recovers the wallet
        res = rc.verify_rootcommit_v2sig(_read("vectors_sig/v2sig-04-tampered-sig.txt"))
        self.assertTrue(res["binding"])
        self.assertFalse(res["sig_ok"])
        self.assertTrue(res["reject"])


# secp256k1 group order (SEC 2), written out rather than imported from the module under test.
_SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def _twin_text(text: str) -> "tuple[str, bytes, bytes]":
    """The checkpoint with the v2-sig anchor signature (r, s, v) replaced by (r, n - s, v') where v'
    flips the recovery id: the second spelling anyone can write without the wallet key. Returns the
    new text, the original signature and the twin signature."""
    import base64
    body, sigs = text.rsplit("\n\n", 1)
    out, original, twin = [], b"", b""
    for line in sigs.splitlines():
        if line.startswith(f"— {rc.KEY_NAME} "):
            head = line.split(" ", 2)
            payload = base64.b64decode(head[2])
            idlen = payload[5]
            opaque = payload[6 + idlen:]
            wlen = opaque[1]
            at = 2 + wlen + 1                                 # 0x02 || wlen || wallet || 0x41 || sig
            original = opaque[at:at + 65]
            s, v = int.from_bytes(original[32:64], "big"), original[64]
            flipped = 55 - v if v in (27, 28) else v ^ 1      # 27 <-> 28, or raw 0 <-> 1
            twin = original[:32] + (_SECP256K1_N - s).to_bytes(32, "big") + bytes([flipped])
            opaque = opaque[:at] + twin + opaque[at + 65:]
            line = f"{head[0]} {head[1]} " + base64.b64encode(payload[:6 + idlen] + opaque).decode()
        out.append(line)
    return body + "\n\n" + "\n".join(out) + ("\n" if sigs.endswith("\n") else ""), original, twin


@unittest.skipUnless(_HAS_OTS and _HAS_SIG, "needs proofbundle[anchors] + a secp256k1/keccak backend")
class TestRootcommitV2SigRefusesAHighS(unittest.TestCase):
    """Finding D1 (owner decision 2026-09-26): eip191 refuses a signature whose s lies in the upper
    half, as OpenZeppelin's ECDSA.recover does (EIP-2). Measured on 126ed1dc: the twin of the valid
    vector recovered the same wallet and the whole checkpoint verified with sig_ok True."""

    def test_every_vendored_signature_carries_a_low_s(self):
        # the fixture fact that makes the refusal free of interop cost; green before and after the fix
        for name in ("v2sig-01-valid", "v2sig-02-tampered-root", "v2sig-03-tampered-wallet",
                     "v2sig-04-tampered-sig", "v2sig-05-tampered-proof"):
            _text, original, _twin = _twin_text(_read(f"vectors_sig/{name}.txt"))
            self.assertLessEqual(int.from_bytes(original[32:64], "big"), _SECP256K1_N // 2, name)

    def test_the_twin_of_the_valid_signature_is_refused(self):
        text = _read("vectors_sig/v2sig-01-valid.txt")
        twin_text, original, twin = _twin_text(text)
        self.assertNotEqual(twin_text, text)
        message = f"{rc.V2SIG_MESSAGE_TAG}\n{_COMMITMENT}"
        self.assertEqual(rc.eip191_recover_address(message, original), _WALLET.lower())
        self.assertIsNone(rc.eip191_recover_address(message, twin))
        res = rc.verify_rootcommit_v2sig(twin_text)
        self.assertTrue(res["binding"])                   # root and wallet are untouched
        self.assertIs(res["sig_ok"], False)
        self.assertTrue(res["reject"])
        self.assertTrue(rc.verify_rootcommit_v2sig(text)["sig_ok"])   # the genuine line still verifies

    def test_the_boundary_is_n_over_two(self):
        """GREEN on f536af50, RED on 126ed1dc: s = n // 2 still reaches recovery, n // 2 + 1 does not.
        OpenZeppelin's bound is the same number (0x7FFF...20A0)."""
        _text, original, _twin = _twin_text(_read("vectors_sig/v2sig-01-valid.txt"))
        message = f"{rc.V2SIG_MESSAGE_TAG}\n{_COMMITMENT}"
        self.assertEqual(_SECP256K1_N // 2,
                         0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0)
        for v in (27, 28):
            at_bound = original[:32] + (_SECP256K1_N // 2).to_bytes(32, "big") + bytes([v])
            above = original[:32] + (_SECP256K1_N // 2 + 1).to_bytes(32, "big") + bytes([v])
            self.assertIsNotNone(rc.eip191_recover_address(message, at_bound), v)
            self.assertIsNone(rc.eip191_recover_address(message, above), v)


def _with_signature(text: str, make) -> "tuple[str, bytes, bytes]":
    """The checkpoint with its v2-sig anchor signature replaced by ``make(original)``; every other
    byte is kept. Returns the new text, the original signature and the new one."""
    import base64
    body, sigs = text.rsplit("\n\n", 1)
    out, original, new = [], b"", b""
    for line in sigs.splitlines():
        if line.startswith(f"— {rc.KEY_NAME} "):
            head = line.split(" ", 2)
            payload = base64.b64decode(head[2])
            idlen = payload[5]
            opaque = payload[6 + idlen:]
            at = 2 + opaque[1] + 1                            # 0x02 || wlen || wallet || 0x41 || sig
            original = opaque[at:at + 65]
            new = make(original)
            opaque = opaque[:at] + new + opaque[at + 65:]
            line = f"{head[0]} {head[1]} " + base64.b64encode(payload[:6 + idlen] + opaque).decode()
        out.append(line)
    return body + "\n\n" + "\n".join(out) + ("\n" if sigs.endswith("\n") else ""), original, new


@unittest.skipUnless(_HAS_OTS and _HAS_SIG, "needs proofbundle[anchors] + a secp256k1/keccak backend")
class TestEip191OneSignatureTwoTextsOneIdentity(unittest.TestCase):
    """Finding D1, addendum 11 (owner decision 2026-09-26). Some signers, hardware wallets among them,
    write ``v`` as the raw recovery id 0/1 instead of 27/28, so eip191 accepts ``v`` in {0, 1, 27, 28}
    and refuses every other value, EIP-155 values from 35 included (personal_sign has no chain id).
    ``v = 0`` and ``v = 27`` are one signature in two texts: the checkpoint bytes are never rewritten,
    and every identity, dedup, replay or log key is computed over ``v`` written as 27/28 and a low s
    (``eip191_signature_identity``). A high s stays refused. Measured on f536af50 with
    ``probe_eip191.py``: the v twin of ``v2sig-01-valid`` recovered the same wallet and both
    checkpoints reported sig_ok True, with different text."""

    def setUp(self):
        self.text = _read("vectors_sig/v2sig-01-valid.txt")
        _same, self.original, _new = _with_signature(self.text, lambda sig: sig)
        self.message = f"{rc.V2SIG_MESSAGE_TAG}\n{_COMMITMENT}"

    def test_the_v_twin_verifies_alike_and_has_one_identity(self):
        """RED on f536af50 and on 126ed1dc, where ``eip191_signature_identity`` did not exist. The
        verdicts of the two texts were equal there already."""
        self.assertEqual(self.original[64], 27)
        twin_text, _original, twin = _with_signature(self.text, lambda sig: sig[:64] + bytes([0]))
        self.assertNotEqual(twin_text, self.text, "two texts")
        genuine, other = rc.verify_rootcommit_v2sig(self.text), rc.verify_rootcommit_v2sig(twin_text)
        self.assertTrue(genuine["sig_ok"])
        self.assertFalse(genuine["reject"])
        self.assertEqual(other, genuine, "one verdict, field for field")
        self.assertEqual(rc.eip191_recover_address(self.message, twin), _WALLET.lower())
        identity = rc.eip191_signature_identity(self.original)
        self.assertEqual(identity, self.original, "v = 27 with a low s is the canonical form")
        self.assertEqual(rc.eip191_signature_identity(twin), identity, "one identity")
        self.assertEqual(twin[64], 0, "the caller's bytes are not rewritten")
        # 28 against 1, the other recovery id: the same rule, and another signature than the one above
        as28, as1 = self.original[:64] + bytes([28]), self.original[:64] + bytes([1])
        self.assertEqual(rc.eip191_signature_identity(as1), as28)
        self.assertEqual(rc.eip191_signature_identity(as28), as28)
        self.assertIsNotNone(rc.eip191_recover_address(self.message, as28))
        self.assertEqual(rc.eip191_recover_address(self.message, as1),
                         rc.eip191_recover_address(self.message, as28))
        self.assertNotEqual(as28, identity)

    def test_v_outside_the_personal_sign_set_is_refused(self):
        """GREEN on f536af50 and on 126ed1dc: the accepted set was {0, 1, 27, 28} there already
        (measured over all 256 values). A guard that it stays so."""
        for v in (2, 3, 26, 29, 35, 36, 37, 38, 255):
            self.assertIsNone(rc.eip191_recover_address(self.message, self.original[:64] + bytes([v])), v)
        for v in (2, 35):
            text, _original, _new = _with_signature(self.text, lambda sig, v=v: sig[:64] + bytes([v]))
            res = rc.verify_rootcommit_v2sig(text)
            self.assertIs(res["sig_ok"], False, v)
            self.assertTrue(res["reject"], v)

    def test_a_signature_eip191_refuses_has_no_identity(self):
        """RED on f536af50 and on 126ed1dc, where ``eip191_signature_identity`` did not exist. A high
        s, s = 0, r outside (0, n), v outside {0, 1, 27, 28} and anything that is not 65 bytes get
        None, so no key can be formed over a signature that never verifies here."""
        r, s = self.original[:32], int.from_bytes(self.original[32:64], "big")
        refused = [self.original[:64] + bytes([v]) for v in (2, 3, 26, 29, 35, 36, 255)]
        refused += [r + (_SECP256K1_N - s).to_bytes(32, "big") + bytes([v]) for v in (27, 28, 0, 1)]
        refused += [r + bytes(32) + bytes([27]), bytes(32) + self.original[32:],
                    _SECP256K1_N.to_bytes(32, "big") + self.original[32:],
                    self.original[:64], self.original + b"\x00", None, 65, "x" * 65, [0] * 65]
        for sig in refused:
            self.assertIsNone(rc.eip191_signature_identity(sig), repr(sig)[:40])
        self.assertEqual(rc.eip191_signature_identity(bytearray(self.original)), self.original)


class TestEip191RefusesWhatEcrecoverRefuses(unittest.TestCase):
    """Finding D1, lens P3 on f536af50. No ECDSA signature has s = 0 or r outside (0, n) (SEC 1
    requires both in [1, n - 1]), and ``ecrecover`` gives the zero address for them, so refusing them
    costs no interop. The owner's reference to OpenZeppelin's ``ECDSA.recover`` is for the high s
    (addendum 11). These refusals happen before any recovery, so no backend is needed to see them.
    The ``v`` rule is in ``TestEip191OneSignatureTwoTextsOneIdentity``."""

    def setUp(self):
        _text, self.original, _twin = _twin_text(_read("vectors_sig/v2sig-01-valid.txt"))
        self.message = f"{rc.V2SIG_MESSAGE_TAG}\n{_COMMITMENT}"

    def test_s_zero_is_refused(self):
        """RED on f536af50: s = 0 recovered an address, the same one for every v."""
        for v in (27, 28, 0, 1):
            sig = self.original[:32] + bytes(32) + bytes([v])
            self.assertIsNone(rc.eip191_recover_address(self.message, sig), v)

    def test_r_outside_the_group_is_refused(self):
        """RED on f536af50: the ``ecdsa`` backend recovered an address from r >= n whenever r (reduced
        mod p) was the x-coordinate of a curve point, as for r = 2**256 - 1; only r = 0 and the r that
        lift to no point gave None."""
        for r in [0, 2 ** 256 - 1] + [_SECP256K1_N + k for k in range(40)]:
            for v in (27, 28):
                sig = r.to_bytes(32, "big") + self.original[32:64] + bytes([v])
                self.assertIsNone(rc.eip191_recover_address(self.message, sig), (r, v))

    def test_a_non_bytes_signature_or_a_non_str_message_is_refused_without_raising(self):
        """RED on f536af50: None and an int raised a raw TypeError from ``len()``, because the new
        ``isinstance`` check sat after it; a non-str message raised a raw AttributeError."""
        for bad in (None, 65, 1.5, True, "x" * 65, [0] * 65, {"s": 1}):
            self.assertIsNone(rc.eip191_recover_address(self.message, bad), repr(bad)[:20])
        for bad in (None, b"message", 5, ["m"]):
            self.assertIsNone(rc.eip191_recover_address(bad, self.original), repr(bad)[:20])
        self.assertIsNone(rc.eip191_recover_address(self.message, bytearray(self.original[:64])))


if __name__ == "__main__":
    unittest.main()
