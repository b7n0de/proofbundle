"""A key the caller trusts is never a low-order or non-canonical Ed25519 key, on any surface.

WHERE THIS COMES FROM. Deep gate Z195 (run wf_39d3cc11-d1b against main 5b53ab3e) confirmed two
findings of one class and reproduced a third:

* L1-Z195-02 (P2, 3 of 3 jurors): two witness vkeys carrying the identity point, one canonical and
  one with the x-sign bit set, met a 2-of-2 witness quorum on a checkpoint neither witness saw.
* L1-Z195-03 (P3, 2 of 3): `decision verify --pub <identity>` printed CRYPTO: OK and exited 0 for a
  receipt nobody signed.
* L1-Z195-01 (0 of 3, refuted for SCOPE, not for mechanism): a trust pack met its root threshold and
  a rotation vouch with the same forgery.

The mechanism is one fact. The core verifier keeps the SPEC section 4a profile, which accepts
small-order components, so under a low-order key the fixed signature R = identity, S = 0 verifies
for EVERY message and no private key exists. The trust policy refused such keys since the fix-review
of 2026-07; no other place that takes a trusted key did. The class is "a trust-anchor rule that
landed on one driver while its siblings kept the old shape".

WHAT IS PINNED HERE. The rule itself (`signature.ed25519_trust_anchor_weakness`), then each surface
with a real forgery made by nobody next to a positive control made by a real key, so a refusal
cannot come from a fixture that fails for any reason at all. The last class is the sweep: every
Ed25519 verification in the package goes through the rule, except the two in-band keys named with
their reason. A new verification in any spelling the sweep models (a call, an import alias, a
`getattr` string, the `cryptography` key class) turns this file red; `_sweep_source` names the
spellings it cannot see. The same sweep runs over the Rust verifier's key constructions.

WHAT THE RULE LEAVES OPEN, also pinned: one secret still meets a 2-of-2 quorum under two distinct
points, as SPEC section 4b says.

WHAT IS NOT CHANGED, on purpose. `verify_ed25519` keeps the SPEC section 4a profile: a bundle's own
key is in-band, its trust comes from a policy pin, and switching that profile is a versioned change.
"""
from __future__ import annotations

import ast
import base64
import hashlib
import json
import re
import subprocess
import sys
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src" / "proofbundle"

from proofbundle import checkpoint as cp  # noqa: E402
from proofbundle import dsse  # noqa: E402
from proofbundle.emit import generate_signer  # noqa: E402
from proofbundle.errors import BundleFormatError  # noqa: E402
from proofbundle.signature import (  # noqa: E402
    ed25519_trust_anchor_weakness,
    verify_ed25519,
    verify_ed25519_pinned,
)

P = (1 << 255) - 19
I1 = b"\x01" + b"\x00" * 31                  # identity, canonical
I2 = b"\x01" + b"\x00" * 30 + b"\x80"        # identity, x-sign bit set
I3 = (P + 1).to_bytes(32, "little")          # identity, y = p + 1 (non-canonical)
UNIV = I1 + b"\x00" * 32                     # R = identity, S = 0: valid under I1..I3 for any message

# Every encoding the rule must refuse, with the reason it must give.
WEAK = [
    (I1, "low-order"),
    (I2, "low-order"),
    (I3, "non-canonical"),
    (P.to_bytes(32, "little"), "non-canonical"),                       # y = p, i.e. 0
    (b"\x00" * 32, "low-order"),                                       # y = 0, order 4
    ((P - 1).to_bytes(32, "little"), "low-order"),                     # y = p - 1, order 2
    (bytes.fromhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), "low-order"),
    (bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"), "low-order"),
    (bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"), "low-order"),
    (bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"), "low-order"),
    (bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"), "low-order"),
    ((P + 18).to_bytes(32, "little"), "non-canonical"),                # the largest y below 2**255
]


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _raw(k) -> bytes:
    return k.public_key().public_bytes_raw()


class _Nobody:
    """A 'signer' that holds no key. Every signature it makes is R = identity, S = 0."""

    def __init__(self, pub: bytes = I1):
        self._pub = pub

    def sign(self, _msg: bytes) -> bytes:
        return UNIV

    def public_key(self):
        return self

    def public_bytes_raw(self) -> bytes:
        return self._pub

    def public_bytes(self, *_args, **_kwargs) -> bytes:
        return self._pub


class TheRule(unittest.TestCase):

    def test_precondition_the_forgery_is_live_against_the_bare_profile(self):
        """Without this, every refusal below could come from a forgery that never worked."""
        for key in (I1, I2, I3):
            for msg in (b"x", b"another message", b""):
                self.assertIs(verify_ed25519(key, UNIV, msg), True, key.hex())

    def test_every_weak_encoding_is_named_with_its_reason(self):
        for key, reason in WEAK:
            with self.subTest(key=key.hex()):
                self.assertEqual(ed25519_trust_anchor_weakness(key), reason)
                self.assertIs(verify_ed25519_pinned(key, UNIV, b"x"), False)

    def test_honest_keys_pass_and_verify(self):
        for _ in range(64):
            k = Ed25519PrivateKey.generate()
            self.assertIsNone(ed25519_trust_anchor_weakness(_raw(k)))
            self.assertIs(verify_ed25519_pinned(_raw(k), k.sign(b"m"), b"m"), True)

    def test_malformed_input_is_named_and_never_raises(self):
        for bad in (b"", b"\x01" * 31, b"\x01" * 33, None, "a" * 32, 5):
            self.assertEqual(ed25519_trust_anchor_weakness(bad), "malformed")
            self.assertIs(verify_ed25519_pinned(bad, UNIV, b"x"), False)

    def test_a_bytearray_key_is_judged_like_bytes(self):
        k = Ed25519PrivateKey.generate()
        self.assertIs(verify_ed25519_pinned(bytearray(_raw(k)), k.sign(b"m"), b"m"), True)
        self.assertEqual(ed25519_trust_anchor_weakness(bytearray(I1)), "low-order")

    def test_the_policy_loader_keeps_its_messages(self):
        from proofbundle.policy import PolicyError, load_policy
        for key, reason in ((I1, "low-order Ed25519 point"), (I3, "non-canonical Ed25519 encoding")):
            with self.assertRaises(PolicyError) as ctx:
                load_policy({"schema": "proofbundle/trust-policy/v0.1", "policy_id": "x",
                             "allowed_issuers": [{"public_key_b64": _b64(key)}]})
            self.assertIn(reason, str(ctx.exception))


class Checkpoints(unittest.TestCase):
    """L1-Z195-02: the witness quorum, the cosignature and the log key."""

    ORIGIN = "example.com/log"

    def setUp(self):
        self.log = generate_signer()
        self.note = cp.sign_checkpoint(self.ORIGIN, 5, b"\x11" * 32, self.log, "log")
        self.log_vkey = cp.vkey("log", _raw(self.log))

    def _forged(self):
        lines = [self.note.rstrip("\n")]
        for name, key in (("w1", I1), ("w2", I2)):
            blob = cp.cosign_key_id(name, key)[:4] + (1_700_000_000).to_bytes(8, "big") + UNIV
            lines.append(f"— {name} {_b64(blob)}")
        return "\n".join(lines) + "\n"

    def test_positive_control_two_real_witnesses_meet_the_quorum(self):
        a, b = generate_signer(), generate_signer()
        note = cp.cosign_checkpoint(self.note, a, "wa", 1_700_000_000)
        note = cp.cosign_checkpoint(note, b, "wb", 1_700_000_001)
        r = cp.verify_witnessed_checkpoint(note, self.log_vkey,
                                           [cp.cosign_vkey("wa", _raw(a)), cp.cosign_vkey("wb", _raw(b))],
                                           threshold=2)
        self.assertIs(r["ok"], True)

    def test_two_encodings_of_the_identity_no_longer_meet_a_quorum(self):
        forged = self._forged()
        roster = [cp.cosign_vkey("w1", I1), cp.cosign_vkey("w2", I2)]
        with self.assertRaises(BundleFormatError) as ctx:
            cp.verify_witnessed_checkpoint(forged, self.log_vkey, roster, threshold=2)
        self.assertIn("low-order", str(ctx.exception))

    def test_a_single_weak_witness_is_refused_by_verify_cosignature(self):
        for name, key in (("w1", I1), ("w2", I2)):
            with self.subTest(witness=name), self.assertRaises(BundleFormatError):
                cp.verify_cosignature(self._forged(), cp.cosign_vkey(name, key))

    def test_a_weak_log_key_is_refused(self):
        forged = cp.sign_checkpoint(self.ORIGIN, 5, b"\x11" * 32, _Nobody(), "log")
        with self.assertRaises(BundleFormatError) as ctx:
            cp.verify_checkpoint(forged, cp.vkey("log", I1))
        self.assertIn("low-order", str(ctx.exception))

    def test_every_weak_encoding_is_refused_as_a_witness_and_as_a_log_key(self):
        for key, _reason in WEAK:
            with self.subTest(key=key.hex()):
                with self.assertRaises(BundleFormatError):
                    cp._parse_witness_vkey(cp.cosign_vkey("w", key))
                with self.assertRaises(BundleFormatError):
                    cp._parse_vkey(cp.vkey("log", key))


_L = (1 << 252) + 27742317777372353535851937790883648493    # the prime order of the base point


def _clamped(seed: bytes) -> int:
    """RFC 8032 secret scalar of a seed; `cryptography` derives the same public key [a]B from it."""
    h = bytearray(hashlib.sha512(seed).digest()[:32])
    h[0] &= 248
    h[31] = (h[31] & 127) | 64
    return int.from_bytes(h, "little")


def _plus_order_two(pub: bytes) -> bytes:
    """A + T2 for the order-2 point T2 = (0, -1), which is the point (-x, -y): y becomes p - y and the
    x sign flips (x is never 0 for a key the rule lets through). No decompression needed."""
    v = int.from_bytes(pub, "little")
    y, sign = v & ((1 << 255) - 1), v >> 255
    return ((P - y) | ((1 - sign) << 255)).to_bytes(32, "little")


class _SameSecretSecondPoint:
    """Signs under A + T2 with the secret of A, as RFC 8032 does, grinding the nonce until [k]T2 is the
    identity, i.e. k is even: one try in two on average. R = [r]B comes from `cryptography` itself."""

    def __init__(self, seed: bytes):
        self._a = _clamped(seed)
        self._pub = _plus_order_two(Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw())
        self.tries: list = []

    def public_key(self):
        return self

    def public_bytes(self, *_args, **_kwargs) -> bytes:
        return self._pub

    def public_bytes_raw(self) -> bytes:
        return self._pub

    def sign(self, msg: bytes) -> bytes:
        for i in range(1, 129):
            seed_r = hashlib.sha256(b"nonce" + i.to_bytes(2, "big") + msg).digest()
            big_r = Ed25519PrivateKey.from_private_bytes(seed_r).public_key().public_bytes_raw()
            k = int.from_bytes(hashlib.sha512(big_r + self._pub + msg).digest(), "little") % _L
            sig = big_r + ((_clamped(seed_r) + k * self._a) % _L).to_bytes(32, "little")
            if verify_ed25519(self._pub, sig, msg):
                self.tries.append(i)
                return sig
        raise AssertionError("128 nonces without an even k")


class DistinctPointsAreNotDistinctParties(unittest.TestCase):
    """SPEC section 4b: the rule refuses no mixed-order key, and one secret meets a 2-of-2 quorum under
    two distinct points. Gate iteration 2, lens C (C2-01): the claim stood in the docstring and SPEC
    with no test behind it. If the rule ever refuses mixed-order keys, this turns red, and 4b changes
    with it."""

    def test_one_secret_meets_a_two_of_two_witness_quorum(self):
        log = generate_signer()
        note = cp.sign_checkpoint("example.com/log", 5, b"\x11" * 32, log, "log")
        seed = hashlib.sha256(b"one secret").digest()
        first = Ed25519PrivateKey.from_private_bytes(seed)
        second = _SameSecretSecondPoint(seed)
        self.assertNotEqual(_raw(first), second.public_bytes_raw())
        self.assertIsNone(ed25519_trust_anchor_weakness(second.public_bytes_raw()))
        note = cp.cosign_checkpoint(note, first, "wa", 1_700_000_000)
        note = cp.cosign_checkpoint(note, second, "wb", 1_700_000_001)
        roster = [cp.cosign_vkey("wa", _raw(first)), cp.cosign_vkey("wb", second.public_bytes_raw())]
        r = cp.verify_witnessed_checkpoint(note, cp.vkey("log", _raw(log)), roster, threshold=2)
        self.assertIs(r["ok"], True, r)
        self.assertIs(r["witnesses_ok"], True, r)
        self.assertEqual(len(second.tries), 1)

    def test_the_second_point_signs_only_when_k_is_even(self):
        """The mechanism, not just the outcome: under A + T2 a signature made with the secret of A
        verifies exactly when [k]T2 is the identity."""
        seed = hashlib.sha256(b"one secret").digest()
        signer = _SameSecretSecondPoint(seed)
        pub, seen = signer.public_bytes_raw(), set()
        for i in range(1, 65):
            msg = b"message %d" % i
            seed_r = hashlib.sha256(b"r" + msg).digest()
            big_r = Ed25519PrivateKey.from_private_bytes(seed_r).public_key().public_bytes_raw()
            k = int.from_bytes(hashlib.sha512(big_r + pub + msg).digest(), "little") % _L
            sig = big_r + ((_clamped(seed_r) + k * signer._a) % _L).to_bytes(32, "little")
            self.assertIs(verify_ed25519(pub, sig, msg), k % 2 == 0, i)
            seen.add(k % 2)
        self.assertEqual(seen, {0, 1}, "64 messages must show both parities, or this measured one side")


class Dsse(unittest.TestCase):
    """L1-Z195-03: every DSSE verify path funnels through dsse.verify_envelope."""

    def test_positive_control(self):
        k = generate_signer()
        env = dsse.sign_envelope(b'{"a":1}', k, payload_type="application/vnd.test")
        self.assertIs(dsse.verify_envelope(env, _raw(k)), True)

    def test_a_weak_key_verifies_no_envelope(self):
        env = dsse.sign_envelope(b'{"a":1}', _Nobody(), payload_type="application/vnd.test")
        for key, _reason in WEAK:
            with self.subTest(key=key.hex()):
                self.assertIs(dsse.verify_envelope(env, key), False)

    def _forged_decision(self, tmp: Path):
        sys.path.insert(0, str(REPO))
        from tests.test_decision_verify import _pred
        from proofbundle import decision
        env = decision.emit_decision_receipt({**_pred("allow"), "decisionId": "made-by-nobody"},
                                             generate_signer(), strict=True)
        env["signatures"] = [{"sig": _b64(UNIV)}]
        path = tmp / "forged.json"
        path.write_text(json.dumps(env), encoding="utf-8")
        return env, path

    def test_the_decision_verifier_and_its_cli_refuse_a_weak_pub(self):
        import tempfile
        from proofbundle import decision
        with tempfile.TemporaryDirectory() as d:
            env, path = self._forged_decision(Path(d))
            r = decision.verify_decision_receipt(env, I1)
            self.assertIs(r["ok"], False)
            self.assertIs(r["crypto_ok"], False)
            out = subprocess.run(
                [sys.executable, "-c",
                 "import sys; sys.path.insert(0, %r); from proofbundle.cli import main; "
                 "sys.exit(main(sys.argv[1:]))" % str(REPO / "src"),
                 "decision", "verify", str(path), "--pub", _b64(I1)],
                capture_output=True, text=True, timeout=120)
            self.assertNotEqual(out.returncode, 0, out.stdout)
            self.assertNotIn("CRYPTO: OK", out.stdout)


class Statuslist(unittest.TestCase):

    def test_a_weak_status_issuer_key_verifies_no_list(self):
        from proofbundle.statuslist import issue_status_list_token, verify_status_snapshot
        uri = "https://example.com/status/1"
        real = generate_signer()
        good = issue_status_list_token([0, 1], uri=uri, signer=real, iat=1_700_000_000)
        self.assertIs(verify_status_snapshot(good, expected_uri=uri, index=0,
                                             issuer_pubkey=_raw(real))["ok"], True)
        forged = issue_status_list_token([0, 0], uri=uri, signer=_Nobody(), iat=1_700_000_000)
        r = verify_status_snapshot(forged, expected_uri=uri, index=1, issuer_pubkey=I1)
        self.assertIs(r["ok"], False)
        self.assertIn("signature invalid", r["detail"])


class Enclave(unittest.TestCase):

    def test_a_weak_verifier_key_attests_nothing(self):
        from proofbundle.experimental.enclave import issue_enclave_attestation, verify_enclave_attestation
        binding = "b" * 43
        real = generate_signer()
        good = issue_enclave_attestation(binding, real, profile="p", tier="affirming")
        self.assertIs(verify_enclave_attestation(good, verifier_pubkey=_raw(real),
                                                 expected_binding=binding)["ok"], True)
        forged = issue_enclave_attestation(binding, _Nobody(), profile="p", tier="affirming")
        self.assertIs(verify_enclave_attestation(forged, verifier_pubkey=I1,
                                                 expected_binding=binding)["ok"], False)


class Renewal(unittest.TestCase):

    def test_a_weak_time_authority_key_anchors_nothing(self):
        from proofbundle.renewal import build_initial_sequence, verify_sequence
        data = ["ab" * 32]
        real = generate_signer()
        good = build_initial_sequence(data, hash_alg="sha256", time=1, sig_alg="ed25519",
                                      signers={"ed25519": real})
        self.assertIs(verify_sequence(good, data, authority_keys={"ed25519": _raw(real)}).ok, True)
        forged = build_initial_sequence(data, hash_alg="sha256", time=1, sig_alg="ed25519",
                                        signers={"ed25519": _Nobody()})
        r = verify_sequence(forged, data, authority_keys={"ed25519": I1})
        self.assertIs(r.ok, False)
        self.assertIn("renewal:last_anchor", [c.name for c in r.checks if not c.ok])


class Hybrid(unittest.TestCase):

    def test_a_weak_classical_leg_does_not_leave_the_hybrid_on_ml_dsa_alone(self):
        from proofbundle.pqsig import PQUnavailable, generate_mldsa, sign_mldsa, verify_hybrid
        try:
            pq = generate_mldsa("mldsa65")
        except PQUnavailable:
            self.skipTest("NOT MEASURABLE: this cryptography build has no FIPS-204 ML-DSA; the hybrid "
                          "case did NOT run (canonical interpreter: ~/proofbundle/.venv)")
        msg = b"renewal content"
        pq_pub = pq.public_key().public_bytes_raw()
        real = generate_signer()
        self.assertIs(verify_hybrid(classical_pub=_raw(real), classical_sig=real.sign(msg),
                                    pq_pub=pq_pub, pq_sig=sign_mldsa(pq, msg), message=msg), True)
        self.assertIs(verify_hybrid(classical_pub=I1, classical_sig=UNIV, pq_pub=pq_pub,
                                    pq_sig=sign_mldsa(pq, msg), message=msg), False)


class TrustPack(unittest.TestCase):
    """L1-Z195-01: refuted for scope by the jury, the mechanism reproduced by all three jurors."""

    def _pred(self, keys: dict, threshold: int) -> dict:
        return {"schemaVersion": "0.1.0", "trustPackId": "tp", "version": 1,
                "expires": "2099-01-01T00:00:00Z", "prevVersionDigest": None,
                "roles": {"root": {"keyIds": list(keys), "threshold": threshold}},
                "keys": {k: {"publicKey": _b64(v)} for k, v in keys.items()},
                "nonClaims": ["does not assert the key holders are honest"]}

    def test_the_validator_names_a_weak_key(self):
        from proofbundle.trust_pack import validate_trust_pack_predicate
        errs = validate_trust_pack_predicate(self._pred({"a": I1, "b": I3}, 1))
        self.assertTrue(any("keys['a']" in e and "low-order" in e for e in errs), errs)
        self.assertTrue(any("keys['b']" in e and "non-canonical" in e for e in errs), errs)

    def test_forged_root_signatures_under_weak_keys_meet_no_threshold(self):
        from proofbundle.trust_pack import (INTOTO_STATEMENT_PAYLOAD_TYPE, _rfc8785_bytes,
                                            verify_trust_pack)
        pred = self._pred({"l1": I1, "l2": I2}, 2)
        stmt = {"_type": "https://in-toto.io/Statement/v1",
                "subject": [{"name": "trust-pack:tp:v1", "digest": {"sha256": "a" * 64}}],
                "predicateType": "https://b7n0de.com/proofbundle/predicates/trust-pack/v0.1",
                "predicate": pred}
        env = {"payload": _b64(_rfc8785_bytes(stmt)), "payloadType": INTOTO_STATEMENT_PAYLOAD_TYPE,
               "signatures": [{"keyid": "l1", "sig": _b64(UNIV)}, {"keyid": "l2", "sig": _b64(UNIV)}]}
        r = verify_trust_pack(env)
        self.assertIs(r["ok"], False)
        self.assertIs(r["structure_ok"], False)
        self.assertTrue(any("low-order" in e for e in r["errors"]), r["errors"])
        self.assertEqual(r["root_signers"], [])

    def test_the_threshold_loop_refuses_a_weak_key_on_its_own(self):
        """The validator stops a weak pack key first; the loop's own refusal is what guards the
        caller-supplied prev_root_keys, which no validator sees. Measured here without the validator."""
        from proofbundle.trust_pack import _verify_signature_for_alg
        entry = {"keyid": "k", "sig": _b64(UNIV)}
        for key, _reason in WEAK:
            with self.subTest(key=key.hex()):
                self.assertIs(_verify_signature_for_alg("ed25519", key, None, entry, b"pae"), False)
        real = generate_signer()
        self.assertIs(_verify_signature_for_alg("ed25519", _raw(real), None,
                                                {"keyid": "k", "sig": _b64(real.sign(b"pae"))}, b"pae"),
                      True)

    def test_a_rotation_is_not_vouched_by_weak_old_root_keys(self):
        from proofbundle.trust_pack import sign_trust_pack, verify_trust_pack
        owner = generate_signer()
        pred = self._pred({"n": _raw(owner)}, 1)
        pred["version"] = 2
        pred["prevVersionDigest"] = {"sha256": "a" * 64}
        env = sign_trust_pack(pred, {"n": owner})
        env["signatures"] += [{"keyid": "old1", "sig": _b64(UNIV)}, {"keyid": "old2", "sig": _b64(UNIV)}]
        r = verify_trust_pack(env, prev_version=1, prev_version_digest="a" * 64,
                              prev_root_keys={"old1": _b64(I1), "old2": _b64(I2)}, prev_root_threshold=2)
        self.assertIs(r["rotation_authorized"], False)
        self.assertEqual(r["old_root_signers"], [])
        # positive control: the same rotation vouched by two real old keys
        o1, o2 = generate_signer(), generate_signer()
        env2 = sign_trust_pack(pred, {"n": owner})
        env2["signatures"] += [{"keyid": "old1", "sig": sign_trust_pack(pred, {"n": o1})["signatures"][0]["sig"]},
                               {"keyid": "old2", "sig": sign_trust_pack(pred, {"n": o2})["signatures"][0]["sig"]}]
        r2 = verify_trust_pack(env2, prev_version=1, prev_version_digest="a" * 64,
                               prev_root_keys={"old1": _b64(_raw(o1)), "old2": _b64(_raw(o2))},
                               prev_root_threshold=2)
        self.assertIs(r2["rotation_authorized"], True, r2["errors"])


class SdJwtAndKeyBinding(unittest.TestCase):

    def _issued(self, holder_pub: bytes):
        from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt
        from proofbundle.sdjwt_issue import issue_sd_jwt
        issuer = generate_signer()
        ev, _ = build_eval_claim(suite="s", suite_version="1", metric="acc", comparator=">=",
                                 threshold="0.80", score="0.9", n=10, model_id="m", dataset_id="d",
                                 issuer="placeholder", timestamp="2026-07-09T10:00:00Z",
                                 assurance_level="reproduced")
        plain = emit_eval_receipt(ev, issuer)
        pc = json.loads(base64.b64decode(plain["payload_b64"]))
        claim = {"passed": True, "threshold": "0.80", "comparator": ">=", "suite": "s",
                 "issuer": pc["issuer"]}
        compact = issue_sd_jwt(claim, issuer, root_b64=plain["merkle"]["root_b64"],
                               holder_public_key=holder_pub)
        return compact, issuer

    def test_a_weak_issuer_key_authenticates_no_disclosure(self):
        from proofbundle.sdjwt import verify_sd_jwt
        compact, issuer = self._issued(_raw(generate_signer()))
        self.assertIs(verify_sd_jwt(compact, _raw(issuer))["sig_ok"], True)
        jwt, rest = compact.split("~", 1)
        h, p, _s = jwt.split(".")
        forged = f"{h}.{p}.{_b64url(UNIV)}~{rest}"
        self.assertIs(verify_sd_jwt(forged, I1)["sig_ok"], False)

    def test_a_weak_holder_key_proves_no_possession(self):
        from proofbundle.kbjwt import verify_key_binding
        from proofbundle.sdjwt_issue import present_with_key_binding
        holder = generate_signer()
        compact, _ = self._issued(_raw(holder))
        good = present_with_key_binding(compact, holder, aud="v", nonce="n", iat=1_780_000_000)
        self.assertIs(verify_key_binding(good)["ok"], True)
        compact_w, _ = self._issued(I1)                        # the issuer bound a key nobody holds
        forged = present_with_key_binding(compact_w, _Nobody(), aud="v", nonce="n", iat=1_780_000_000)
        r = verify_key_binding(forged)
        self.assertIs(r["ok"], False)
        self.assertIn("signature invalid", r["detail"])


class AgtAdapter(unittest.TestCase):

    def _vector(self) -> dict:
        path = REPO / "tests" / "vektoren" / "agt_receipts" / "03_extern_autorisiert.json"
        return json.loads(path.read_text(encoding="utf-8"))

    def test_positive_control_the_real_vector_is_authorized(self):
        from proofbundle.adapters.agt_receipt import verify_agt_receipt
        r = self._vector()
        self.assertIs(verify_agt_receipt(r, trusted_authorizer_keys=[r["authorizer_public_key"]]).ok, True)

    def test_a_weak_authorizer_key_authorizes_nothing(self):
        from proofbundle.adapters.agt_receipt import verify_agt_receipt
        r = self._vector()
        r["authorizer_public_key"] = I1.hex()
        r["authorization_signature"] = UNIV.hex()
        e = verify_agt_receipt(r, trusted_authorizer_keys=[I1.hex()])
        self.assertIs(e.ok, False)
        sig = [c for c in e.checks if c.name == "external-authorization-signature"]
        self.assertEqual([c.ok for c in sig], [False])

    def test_the_signer_in_capitals_is_not_a_second_party(self):
        from proofbundle.adapters.agt_receipt import (canonical_authorization_payload,
                                                      canonical_payload, verify_agt_receipt)
        k = Ed25519PrivateKey.generate()
        r = self._vector()
        r["signer_public_key"] = _raw(k).hex()
        r["signature"] = k.sign(canonical_payload(r)).hex()
        r["authorizer_public_key"] = _raw(k).hex().upper()
        r["authorization_signature"] = k.sign(canonical_authorization_payload(r)).hex()
        e = verify_agt_receipt(r, trusted_authorizer_keys=[r["authorizer_public_key"]])
        self.assertIs(e.ok, False)
        distinct = [c for c in e.checks if c.name == "authorizer-key-distinct"]
        self.assertEqual([c.ok for c in distinct], [False])


RUST_DIR = REPO / "tools" / "pb_verify_rs"
RUST_BIN = RUST_DIR / "target" / "release" / "pb_verify_rs"


def _rust_binary():
    """Same lookup as tests/test_lauf11_l1_l4_rust_strukturbudget_und_kreuzvergleich.py: the built
    binary, else a release build, else None (and the class says it did not run)."""
    import shutil
    if RUST_BIN.exists():
        return RUST_BIN
    if not RUST_DIR.is_dir() or shutil.which("cargo") is None:
        return None
    b = subprocess.run(["cargo", "build", "--release"], cwd=RUST_DIR,  # noqa: S603,S607
                       capture_output=True, text=True, timeout=1800)
    return RUST_BIN if b.returncode == 0 and RUST_BIN.exists() else None


class RustParity(unittest.TestCase):
    """The second verifier refuses the same keys. A rule on one side only is a new differential."""

    @classmethod
    def setUpClass(cls):
        cls.rust = _rust_binary()
        if cls.rust is None:
            raise unittest.SkipTest("NOT MEASURABLE: tools/pb_verify_rs is missing or cargo is absent — "
                                    "the parity cases did NOT run (env_blocked, never green)")

    def _run(self, *args):
        return subprocess.run([str(self.rust), *args], capture_output=True, text=True, timeout=120)

    def test_verify_dsse_agrees_on_every_weak_key_and_on_a_real_one(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            forged = Path(d) / "forged.json"
            env = dsse.sign_envelope(b'{"a":1}', _Nobody(), payload_type="application/vnd.test")
            forged.write_text(json.dumps(env), encoding="utf-8")
            for key, _reason in WEAK:
                with self.subTest(key=key.hex()):
                    out = self._run("verify-dsse", str(forged), _b64(key))
                    self.assertEqual((out.returncode, out.stdout.strip()), (1, "FAIL"), out.stderr)
                    self.assertIs(dsse.verify_envelope(env, key), False)
            real = generate_signer()
            good = Path(d) / "good.json"
            good.write_text(json.dumps(dsse.sign_envelope(b'{"a":1}', real,
                                                          payload_type="application/vnd.test")),
                            encoding="utf-8")
            out = self._run("verify-dsse", str(good), _b64(_raw(real)))
            self.assertEqual((out.returncode, out.stdout.strip()), (0, "OK"), out.stderr)

    def test_verify_bundle_agrees_on_a_weak_sd_jwt_issuer_key(self):
        """End to end through the subcommand, as gate iteration 2, lens B measured it: an EdDSA SD-JWT
        VC block signed by nobody under the identity point, next to one signed by a real issuer."""
        import tempfile
        from proofbundle.bundle import verify_bundle
        from proofbundle.emit import emit_bundle
        hdr = _b64url(b'{"alg":"EdDSA"}')
        pl = _b64url(b'{"vct":"https://example.test/vct"}')
        issuer = generate_signer()
        cases = {"weak": (f"{hdr}.{pl}.{_b64url(UNIV)}~", I1, False, 1),
                 "real": (f"{hdr}.{pl}.{_b64url(issuer.sign(f'{hdr}.{pl}'.encode()))}~", _raw(issuer), True, 0)}
        for label, (compact, key, py_ok, rust_rc) in cases.items():
            with self.subTest(issuer=label), tempfile.TemporaryDirectory() as d:
                bundle = emit_bundle(b'{"hello":1}', generate_signer(),
                                     sd_jwt_vc={"compact": compact, "issuer_public_key_b64": _b64(key)})
                self.assertIs(verify_bundle(bundle).ok, py_ok)
                path = Path(d) / "b.json"
                path.write_text(json.dumps(bundle), encoding="utf-8")
                out = self._run("verify-bundle", str(path))
                self.assertEqual(out.returncode, rust_rc, out.stdout + out.stderr)

    def test_the_trust_pack_threshold_agrees(self):
        import tempfile
        from proofbundle.trust_pack import INTOTO_STATEMENT_PAYLOAD_TYPE
        stmt = {"predicate": {"keys": {"l1": {"publicKey": _b64(I1)}, "l2": {"publicKey": _b64(I2)}},
                              "roles": {"root": {"keyIds": ["l1", "l2"], "threshold": 2}}}}
        env = {"payload": _b64(json.dumps(stmt).encode()), "payloadType": INTOTO_STATEMENT_PAYLOAD_TYPE,
               "signatures": [{"keyid": "l1", "sig": _b64(UNIV)}, {"keyid": "l2", "sig": _b64(UNIV)}]}
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "pack.json"
            path.write_text(json.dumps(env), encoding="utf-8")
            out = self._run("verify-trust-pack-threshold", str(path))
        # Refused as malformed before any signature is counted, as Python's validator refuses the pack.
        self.assertEqual(out.returncode, 2, out.stdout + out.stderr)
        self.assertIn("keys['l1'].publicKey is a low-order", out.stdout)

    def test_a_weak_key_in_another_role_gets_the_same_verdict_on_both_sides(self):
        """Gate lens 2 (L2-PK-01): real root signatures and a weak `decisionMakers` key. Python's
        validator refused the pack while the Rust slice, reading only the root role, said OK."""
        import tempfile
        from proofbundle.trust_pack import (INTOTO_STATEMENT_PAYLOAD_TYPE, _rfc8785_bytes,
                                            verify_trust_pack)
        r1, r2 = generate_signer(), generate_signer()
        pred = {"schemaVersion": "0.1.0", "trustPackId": "tp", "version": 1,
                "expires": "2099-01-01T00:00:00Z", "prevVersionDigest": None,
                "roles": {"root": {"keyIds": ["r1", "r2"], "threshold": 2},
                          "decisionMakers": {"keyIds": ["dm1"], "threshold": 1}},
                "keys": {"r1": {"publicKey": _b64(_raw(r1))}, "r2": {"publicKey": _b64(_raw(r2))},
                         "dm1": {"publicKey": _b64(b"\x00" * 32)}},
                "nonClaims": ["does not assert the key holders are honest"]}
        stmt = {"_type": "https://in-toto.io/Statement/v1",
                "subject": [{"name": "trust-pack:tp:v1", "digest": {"sha256": "a" * 64}}],
                "predicateType": "https://b7n0de.com/proofbundle/predicates/trust-pack/v0.1",
                "predicate": pred}
        body = _rfc8785_bytes(stmt)
        msg = dsse.pae(INTOTO_STATEMENT_PAYLOAD_TYPE, body)
        env = {"payload": _b64(body), "payloadType": INTOTO_STATEMENT_PAYLOAD_TYPE,
               "signatures": [{"keyid": "r1", "sig": _b64(r1.sign(msg))},
                              {"keyid": "r2", "sig": _b64(r2.sign(msg))}]}
        py = verify_trust_pack(env)
        self.assertIs(py["ok"], False)
        self.assertTrue(any("keys['dm1']" in e and "low-order" in e for e in py["errors"]), py["errors"])
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "pack.json"
            path.write_text(json.dumps(env), encoding="utf-8")
            out = self._run("verify-trust-pack-threshold", str(path))
        self.assertEqual(out.returncode, 2, out.stdout + out.stderr)
        self.assertIn("keys['dm1'].publicKey is a low-order", out.stdout)
        # positive control: the same pack with a real decisionMakers key is accepted by both
        dm = generate_signer()
        pred["keys"]["dm1"] = {"publicKey": _b64(_raw(dm))}
        body = _rfc8785_bytes(stmt)
        msg = dsse.pae(INTOTO_STATEMENT_PAYLOAD_TYPE, body)
        env = {"payload": _b64(body), "payloadType": INTOTO_STATEMENT_PAYLOAD_TYPE,
               "signatures": [{"keyid": "r1", "sig": _b64(r1.sign(msg))},
                              {"keyid": "r2", "sig": _b64(r2.sign(msg))}]}
        self.assertIs(verify_trust_pack(env)["root_threshold_met"], True)
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "pack.json"
            path.write_text(json.dumps(env), encoding="utf-8")
            out = self._run("verify-trust-pack-threshold", str(path))
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)


# The two keys that stay on the bare SPEC section 4a profile, with their reason. Nothing else may.
IN_BAND = {
    "bundle.py": "the bundle's own signature.public_key_b64 arrives in the bundle; SPEC section 4a pins "
                 "its verification profile, and trust in it comes from a policy pin, which has the rule",
    "adapters/agt_receipt.py": "the AGT receipt's signer_public_key arrives in the receipt, like a "
                               "bundle's key; the authorizer key, the one a relying party trusts, "
                               "goes through verify_ed25519_pinned",
}


_BARE = "verify_ed25519"
_KEY_CLASS = "Ed25519PublicKey"


def _sweep_source(rel: str, text: str) -> list:
    """Every way a module in the package reaches the bare Ed25519 profile, as (rel, line, spelling).

    Lens 3 of the gate on this change planted four spellings of a bypass in a new module and the
    first version of this sweep, which matched only the names `verify_ed25519` and
    `from_public_bytes`, missed two of them: an import alias (`import verify_ed25519 as v; v(...)`)
    and `getattr(signature, "verify_ed25519")`. It now follows the module's own imports of the bare
    primitive under any alias, counts the name as a string (the `getattr` form), and counts every
    reference to the `cryptography` key class, since constructing an Ed25519 public key outside
    `signature.py` is a second path to the same arithmetic. What it cannot see, said here so it is not
    read into it: a name built at run time ("verify_" + "ed25519"), whether it goes to `getattr` or
    to a module `importlib` returned, and code run from a string by `exec` or `eval`. A module from
    `importlib` read with the literal name (`m.verify_ed25519`) is seen, as an attribute (gate iteration
    2, lens C, C2-03: an earlier version of this sentence listed `importlib` as unseen outright)."""
    tree = ast.parse(text)
    names = {_BARE}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == _BARE:
                    names.add(alias.asname or alias.name)
    found = []
    for node in ast.walk(tree):
        spelling = None
        if isinstance(node, ast.ImportFrom) and any(a.name in (_BARE, _KEY_CLASS) for a in node.names):
            spelling = "import of " + ", ".join(a.name for a in node.names if a.name in (_BARE, _KEY_CLASS))
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in names | {_KEY_CLASS}:
            spelling = f"name {node.id}"
        elif isinstance(node, ast.Attribute) and node.attr in (_BARE, _KEY_CLASS):
            spelling = f"attribute {node.attr}"
        elif isinstance(node, ast.Constant) and node.value in (_BARE, _KEY_CLASS):
            spelling = f"string {node.value!r}"
        if spelling:
            found.append((rel, node.lineno, spelling))
    return found


_SIGNATURE_OWN = ("verify_ed25519", "verify_ed25519_pinned")


def _signature_py_stray(text: str) -> list:
    """What `_sweep_source` finds in signature.py OUTSIDE the two places the bare primitive belongs.

    Gate iteration 2, lens A (A2-01): the first sweep left signature.py out wholesale, so a helper
    added there under a third name (`verify_ed25519_v2`, calling the bare primitive) and every caller
    of it were invisible; the lens planted exactly that and the universal forgery went through. The
    module is swept now, and the bare primitive and the key class may appear only inside the
    definitions of `verify_ed25519` and `verify_ed25519_pinned`, in `__all__` and in the import of the
    key class."""
    tree = ast.parse(text)
    allowed: set = set()
    for node in tree.body:
        own_def = isinstance(node, ast.FunctionDef) and node.name in _SIGNATURE_OWN
        key_import = (isinstance(node, (ast.Import, ast.ImportFrom))
                      and any(a.name == _KEY_CLASS for a in node.names))
        dunder_all = isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets)
        if own_def or key_import or dunder_all:
            allowed |= set(range(node.lineno, node.end_lineno + 1))
    return [f for f in _sweep_source("signature.py", text) if f[1] not in allowed]


class TheSweep(unittest.TestCase):
    """Generator, not fixture: every Ed25519 verification in the package is classified."""

    def _uses(self):
        found = []
        for path in sorted(SRC.rglob("*.py")):
            rel = path.relative_to(SRC).as_posix()
            text = path.read_text(encoding="utf-8")
            found += _signature_py_stray(text) if rel == "signature.py" else _sweep_source(rel, text)
        return found

    def test_no_verification_bypasses_the_rule_outside_the_named_in_band_keys(self):
        stray = [f"{rel}:{line} {spelling}" for rel, line, spelling in self._uses()
                 if rel not in IN_BAND or _KEY_CLASS in spelling]
        self.assertEqual(stray, [], "a trusted key reaches the bare SPEC 4a profile; route it through "
                                    "verify_ed25519_pinned or name it in IN_BAND with its reason")

    def test_the_sweep_sees_the_named_in_band_uses(self):
        """Counter-direction: a sweep that finds nothing proves nothing."""
        seen = {rel for rel, _l, spelling in self._uses() if _BARE in spelling}
        self.assertEqual(seen, set(IN_BAND))

    def test_the_sweep_catches_every_spelling_lens_3_planted(self):
        planted = {
            "a bare call": "from .signature import verify_ed25519\nverify_ed25519(k, s, m)\n",
            "an import alias": "from .signature import verify_ed25519 as v\nv(k, s, m)\n",
            "getattr on the module": "from . import signature\ngetattr(signature, 'verify_ed25519')(k, s, m)\n",
            "the cryptography class": ("from cryptography.hazmat.primitives.asymmetric.ed25519 import "
                                       "Ed25519PublicKey\nEd25519PublicKey.from_public_bytes(k).verify(s, m)\n"),
            "the class under an alias": ("from cryptography.hazmat.primitives.asymmetric.ed25519 import "
                                         "Ed25519PublicKey as K\nK.from_public_bytes(k)\n"),
            "the class through its module": ("from cryptography.hazmat.primitives.asymmetric import ed25519\n"
                                             "ed25519.Ed25519PublicKey.from_public_bytes(k)\n"),
        }
        for label, text in planted.items():
            with self.subTest(spelling=label):
                self.assertNotEqual(_sweep_source("planted.py", text), [], label)
        clean = "from .signature import verify_ed25519_pinned\nverify_ed25519_pinned(k, s, m)\n"
        self.assertEqual(_sweep_source("clean.py", clean), [])

    def test_a_third_name_inside_signature_py_is_caught(self):
        """Lens A of iteration 2: a new helper in signature.py itself reaching the bare primitive."""
        real = (SRC / "signature.py").read_text(encoding="utf-8")
        self.assertEqual(_signature_py_stray(real), [], "signature.py as it stands must be clean")
        planted = real + ("\n\ndef verify_ed25519_v2(public_key, signature, message):\n"
                          "    return verify_ed25519(public_key, signature, message)\n")
        self.assertNotEqual(_signature_py_stray(planted), [])
        planted_class = real + ("\n\ndef _raw_check(k, s, m):\n"
                                "    Ed25519PublicKey.from_public_bytes(k).verify(s, m)\n")
        self.assertNotEqual(_signature_py_stray(planted_class), [])

    def test_the_named_limits_are_the_real_ones(self):
        """C2-03: what the docstring says the sweep cannot see is unseen, and what it no longer lists
        as unseen is seen. A limit stated wider than it is hides nothing, but it is still wrong."""
        seen = {
            "importlib, literal name": ("import importlib\nm = importlib.import_module('.signature', "
                                        "'proofbundle')\nm.verify_ed25519(k, s, m)\n"),
            "importlib, literal class": ("import importlib\nimportlib.import_module('cryptography.hazmat."
                                         "primitives.asymmetric.ed25519').Ed25519PublicKey\n"),
        }
        unseen = {
            "a built name through getattr": ("from . import signature\n"
                                             "getattr(signature, 'verify_' + 'ed25519')(k, s, m)\n"),
            "exec": "exec('from proofbundle.signature import verify_ed25519 as v')\n",
            "eval": "f = eval('__import__(\"proofbundle.signature\").signature.verify_ed25519')\n",
        }
        for label, text in seen.items():
            with self.subTest(seen=label):
                self.assertNotEqual(_sweep_source("x.py", text), [])
        for label, text in unseen.items():
            with self.subTest(unseen=label):
                self.assertEqual(_sweep_source("x.py", text), [])


# The Rust verifier builds an Ed25519 key in these functions. Each one asks the trust-anchor rule
# (`schwaeche_eines_vertrauensankers`) in its own body, except the bundle's own in-band key.
RUST_MAIN = RUST_DIR / "src" / "main.rs"
RUST_KEY_SITES_WITH_RULE = {"verify_dsse", "ed25519_schluessel", "verify_sdjwt_issuer",
                            "verify_trust_pack_threshold"}
RUST_IN_BAND = {"verify_bundle": "the bundle's own signature.public_key_b64, as bundle.py in IN_BAND"}
_RUST_KEY_CONSTRUCTION = re.compile(r"\bVerifyingKey::\w+\s*\(")
_RUST_FN = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?fn\s+(\w+)", re.M)


def _rust_code_only(text: str) -> str:
    """Line comments removed, line numbers kept. `//` opens a comment only where the quotes before it
    on its line are balanced, so the `//` of a URL inside a string literal stays code."""
    out = []
    for line in text.split("\n"):
        cut, pos = len(line), 0
        while (i := line.find("//", pos)) >= 0:
            if line[:i].replace('\\"', "").count('"') % 2 == 0:
                cut = i
                break
            pos = i + 2
        out.append(line[:cut])
    return "\n".join(out)


def _rust_key_sites(text: str) -> list:
    """(function, line, code before it) for every `VerifyingKey::<constructor>(` outside the test
    module; "code before it" runs from the function's `fn` to the construction, comments removed.

    What it cannot see, said here so it is not read into it: a key built by type inference
    (`let vk: VerifyingKey = arr.try_into()?`), through a trait not named `VerifyingKey::`, or by
    another crate; a block comment (main.rs has none today) or a line comment inside a multi-line
    string. It reads text, not a parse tree, names a function by the nearest `fn` above, and asks
    whether the rule is CALLED before the key is built, not whether its answer is obeyed."""
    cut = text.find("#[cfg(test)]\nmod tests")
    prod = _rust_code_only(text if cut < 0 else text[:cut])
    fns = [(m.start(), m.group(1)) for m in _RUST_FN.finditer(prod)]
    sites = []
    for m in _RUST_KEY_CONSTRUCTION.finditer(prod):
        start, name = max((f for f in fns if f[0] < m.start()), default=(0, "<top level>"))
        sites.append((name, prod.count("\n", 0, m.start()) + 1, prod[start:m.start()]))
    return sites


def _rust_stray(text: str) -> list:
    return [f"main.rs:{line} in {name}" for name, line, before in _rust_key_sites(text)
            if name not in RUST_IN_BAND
            and (name not in RUST_KEY_SITES_WITH_RULE or "schwaeche_eines_vertrauensankers(" not in before)]


class TheRustSweep(unittest.TestCase):
    """Gate iteration 2, lens C and the Fix-the-class step: the Python sweep had no Rust sibling, and
    the rule landing on one verifier while the other kept the old shape is this change's own class."""

    def setUp(self):
        if not RUST_MAIN.is_file():
            self.skipTest("NOT MEASURABLE: tools/pb_verify_rs/src/main.rs is not in this tree; the Rust "
                          "sweep did NOT run")
        self.text = RUST_MAIN.read_text(encoding="utf-8")

    def test_every_key_construction_asks_the_rule_or_is_named_in_band(self):
        self.assertEqual(_rust_stray(self.text), [],
                         "a Rust key reaches ed25519-dalek without the trust-anchor rule; ask "
                         "schwaeche_eines_vertrauensankers or name it in RUST_IN_BAND")

    def test_the_sweep_sees_every_named_site(self):
        """Counter-direction: each named function holds a construction, so none of the names is stale."""
        self.assertEqual({name for name, _l, _b in _rust_key_sites(self.text)},
                         RUST_KEY_SITES_WITH_RULE | set(RUST_IN_BAND))

    def test_a_planted_construction_without_the_rule_is_caught(self):
        planted = self.text.replace(
            "#[cfg(test)]\nmod tests",
            "fn neuer_pfad(b: &[u8; 32]) -> bool {\n    VerifyingKey::from_bytes(b).is_ok()\n}\n\n"
            "#[cfg(test)]\nmod tests", 1)
        self.assertNotEqual(planted, self.text)
        self.assertEqual([s.split(" in ")[1] for s in _rust_stray(planted)], ["neuer_pfad"])
        dropped = self.text.replace("if schwaeche_eines_vertrauensankers(&pk_arr).is_some() {\n"
                                    "        return Ok(false);\n    }\n    let vk = VerifyingKey::from_bytes"
                                    "(&pk_arr).map_err(|e| format!(\"bad issuer key", "let vk = VerifyingKey"
                                    "::from_bytes(&pk_arr).map_err(|e| format!(\"bad issuer key", 1)
        self.assertNotEqual(dropped, self.text, "the plant must hit verify_sdjwt_issuer's rule")
        self.assertEqual([s.split(" in ")[1] for s in _rust_stray(dropped)], ["verify_sdjwt_issuer"])

    def test_the_rule_in_a_comment_or_after_the_key_does_not_count(self):
        """Found on the sweep's first version by reading it: it matched the rule's name anywhere in the
        function's text, so a comment naming it, or a call after the key was built, satisfied it."""
        block = ("    if schwaeche_eines_vertrauensankers(&pk_arr).is_some() {\n        return Ok(false);\n    }\n")
        build = "    let vk = VerifyingKey::from_bytes(&pk_arr).map_err(|e| format!(\"bad issuer key: {e}\"))?;\n"
        self.assertEqual(self.text.count(block + build), 1)
        commented = self.text.replace(block + build,
                                      "    // schwaeche_eines_vertrauensankers(&pk_arr) was asked by the caller\n"
                                      + build, 1)
        after = self.text.replace(block + build, build + block, 1)
        for label, text in (("in a comment", commented), ("after the key", after)):
            with self.subTest(rule=label):
                self.assertNotEqual(text, self.text)
                self.assertEqual([s.split(" in ")[1] for s in _rust_stray(text)], ["verify_sdjwt_issuer"])
        url = 'let u = "https://example.test/x"; // VerifyingKey::from_bytes(k) in a comment\n'
        self.assertEqual(_rust_code_only(url), 'let u = "https://example.test/x"; \n')


if __name__ == "__main__":
    unittest.main()
