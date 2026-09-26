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
their reason, and a new call site that bypasses it turns this file red.

WHAT IS NOT CHANGED, on purpose. `verify_ed25519` keeps the SPEC section 4a profile: a bundle's own
key is in-band, its trust comes from a policy pin, and switching that profile is a versioned change.
"""
from __future__ import annotations

import ast
import base64
import json
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
        self.assertEqual(out.returncode, 1, out.stdout + out.stderr)
        self.assertIn("root_threshold_met=false signers=0", out.stdout)


# The two keys that stay on the bare SPEC section 4a profile, with their reason. Nothing else may.
IN_BAND = {
    "bundle.py": "the bundle's own signature.public_key_b64 arrives in the bundle; SPEC section 4a pins "
                 "its verification profile, and trust in it comes from a policy pin, which has the rule",
    "adapters/agt_receipt.py": "the AGT receipt's signer_public_key arrives in the receipt, like a "
                               "bundle's key; the authorizer key, the one a relying party trusts, "
                               "goes through verify_ed25519_pinned",
}


class TheSweep(unittest.TestCase):
    """Generator, not fixture: every Ed25519 verification in the package is classified."""

    def _uses(self):
        found = []
        for path in sorted(SRC.rglob("*.py")):
            rel = path.relative_to(SRC).as_posix()
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                name = None
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                    name = node.id
                elif isinstance(node, ast.Attribute):
                    name = node.attr
                if name in ("verify_ed25519", "from_public_bytes") and rel != "signature.py":
                    found.append((rel, node.lineno, name))
        return found

    def test_no_verification_bypasses_the_rule_outside_the_named_in_band_keys(self):
        stray = []
        for rel, line, name in self._uses():
            if name == "from_public_bytes":
                src = (SRC / rel).read_text(encoding="utf-8").splitlines()[line - 1]
                if "MLDSA" in src or "pub_cls" in src:
                    continue          # ML-DSA keys, not Ed25519
                stray.append(f"{rel}:{line} constructs an Ed25519 key outside signature.py")
            elif rel not in IN_BAND:
                stray.append(f"{rel}:{line} uses bare verify_ed25519")
        self.assertEqual(stray, [], "a trusted key reaches the bare SPEC 4a profile; route it through "
                                    "verify_ed25519_pinned or name it in IN_BAND with its reason")

    def test_the_sweep_sees_the_named_in_band_uses(self):
        """Counter-direction: a sweep that finds nothing proves nothing."""
        seen = {rel for rel, _l, name in self._uses() if name == "verify_ed25519"}
        self.assertEqual(seen, set(IN_BAND))


if __name__ == "__main__":
    unittest.main()
