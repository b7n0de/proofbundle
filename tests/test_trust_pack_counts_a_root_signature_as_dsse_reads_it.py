"""A trust pack counts a root signature in the alphabets the DSSE envelope allows, as dsse.verify_envelope does.

Measured at 65bd4b7a and again at 121cd089: the threshold loop of `verify_trust_pack` decoded `signatures[].sig`
with the standard alphabet only, while the same function reads the `payload` of the same envelope in both alphabets
(`dsse.load_payload`), `dsse.verify_envelope` accepts the signature in both, and the Rust verifier
(`verify-trust-pack-threshold`, `b64_dsse`) counted it. A pack whose one root signature was written URL-safe missed
its threshold in Python and met it in Rust. Each alphabet is read padded and canonical: an unpadded, mixed or foreign
spelling stays refused.

The rule holds for every algorithm of a root key: `ed25519`, `mldsa65` and `hybrid-ed25519-mldsa65`, and for the
second signature field of a hybrid root, `sigPq`, which stands next to `sig` in the same DSSE signature entry. The
keys themselves (`publicKey`, `publicKeyPq`) are fields of the predicate and stay standard base64.
"""
from __future__ import annotations

import base64
import copy
import unittest
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle import dsse
from proofbundle.trust_pack import (
    INTOTO_STATEMENT_PAYLOAD_TYPE,
    _rfc8785_bytes,
    build_trust_pack_statement,
    sign_trust_pack,
    verify_trust_pack,
)

try:
    from cryptography.hazmat.primitives.asymmetric import mldsa  # noqa: F401
    from proofbundle.pqsig import generate_mldsa
    _HAS_MLDSA = True
except ImportError:  # pragma: no cover - depends on the installed cryptography
    _HAS_MLDSA = False

NOW = datetime(2026, 11, 25, tzinfo=timezone.utc)


def _url(s: str) -> str:
    return s.translate(str.maketrans("+/", "-_"))


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _has_both(sig: str) -> bool:
    # Without `+` and `/` the URL-safe spelling would equal the standard one and a case would hold nothing.
    return "+" in sig and "/" in sig


def _forms(sig: str) -> dict:
    """The spellings of one signature field and whether a reader of DSSE accepts each. A signature whose length is
    a multiple of three carries no padding (ML-DSA-65, 3309 bytes); for it the unpadded spellings equal the padded
    ones and are left out, since they would hold nothing."""
    out = {
        "standard, padded": (sig, True),
        "url-safe, padded": (_url(sig), True),
        "both alphabets mixed": (sig.replace("+", "-", 1), False),
        "a foreign character": (sig[:5] + "!" + sig[6:], False),
    }
    if sig.endswith("="):
        out["standard, unpadded"] = (sig.rstrip("="), False)
        out["url-safe, unpadded"] = (_url(sig).rstrip("="), False)
    return out


def _predicate(i: int, keys: dict) -> dict:
    return {"schemaVersion": "0.1.0", "trustPackId": f"tp-alphabet-{i}", "version": 1, "prevVersionDigest": None,
            "expires": "2027-01-01T00:00:00Z", "roles": {"root": {"keyIds": ["k-0"], "threshold": 1}},
            "keys": keys, "nonClaims": ["alphabet case"]}


def _ed25519_pack():
    sk = Ed25519PrivateKey.generate()
    pub_b64 = _b64(sk.public_key().public_bytes_raw())
    for i in range(400):
        env = sign_trust_pack(_predicate(i, {"k-0": {"publicKey": pub_b64, "scheme": "ed25519"}}), {"k-0": sk})
        if _has_both(env["signatures"][0]["sig"]):
            return env, sk.public_key().public_bytes_raw(), pub_b64
    raise AssertionError("no signature with + and / in 400 packs")


def _mldsa_pack():
    for i in range(20):
        sk = generate_mldsa("mldsa65")
        keys = {"k-0": {"publicKey": _b64(sk.public_key().public_bytes_raw()), "alg": "mldsa65"}}
        env = sign_trust_pack(_predicate(i, keys), {"k-0": sk})
        if _has_both(env["signatures"][0]["sig"]):
            return env
    raise AssertionError("no ML-DSA-65 signature with + and / in 20 packs")


def _hybrid_pack():
    """`sign_trust_pack` writes one leg and refuses a hybrid signer, so the two legs are signed here over the PAE of
    the statement, as tests/test_trust_pack_crypto_agility.py does."""
    for i in range(400):
        ed_sk, m_sk = Ed25519PrivateKey.generate(), generate_mldsa("mldsa65")
        keys = {"k-0": {"publicKey": _b64(ed_sk.public_key().public_bytes_raw()),
                        "publicKeyPq": _b64(m_sk.public_key().public_bytes_raw()),
                        "alg": "hybrid-ed25519-mldsa65"}}
        body = _rfc8785_bytes(build_trust_pack_statement(_predicate(i, keys)))
        msg = dsse.pae(INTOTO_STATEMENT_PAYLOAD_TYPE, body)
        entry = {"keyid": "k-0", "sig": _b64(bytes(ed_sk.sign(msg))), "sigPq": _b64(bytes(m_sk.sign(msg)))}
        if _has_both(entry["sig"]) and _has_both(entry["sigPq"]):
            return {"payload": _b64(body), "payloadType": INTOTO_STATEMENT_PAYLOAD_TYPE, "signatures": [entry]}
    raise AssertionError("no hybrid signature pair with + and / in both legs in 400 packs")


def _with(env: dict, field: str, value: str) -> dict:
    env = copy.deepcopy(env)
    env["signatures"][0][field] = value
    return env


class Ed25519RootSignatureAlphabets(unittest.TestCase):
    def setUp(self):
        self.env, self.pub, self.pub_b64 = _ed25519_pack()
        self.forms = _forms(self.env["signatures"][0]["sig"])

    def test_the_root_threshold_counts_what_the_dsse_envelope_accepts(self):
        self.assertIn("url-safe, unpadded", self.forms)
        for name, (sig, expected) in self.forms.items():
            with self.subTest(form=name):
                env = _with(self.env, "sig", sig)
                self.assertIs(dsse.verify_envelope(env, self.pub), expected, "the DSSE reading of this form changed")
                r = verify_trust_pack(env, now=NOW)
                self.assertIs(r["root_threshold_met"], expected, r["errors"])
                self.assertIs(r["ok"], expected, r["errors"])

    def test_a_rotation_counts_an_old_root_signature_in_the_same_alphabets(self):
        for name, (sig, expected) in self.forms.items():
            with self.subTest(form=name):
                r = verify_trust_pack(_with(self.env, "sig", sig), now=NOW, prev_version=0,
                                      prev_root_keys={"k-0": self.pub_b64}, prev_root_threshold=1)
                self.assertEqual(r["old_root_signers"], ["k-0"] if expected else [], r["errors"])


@unittest.skipUnless(_HAS_MLDSA, "this cryptography has no ML-DSA-65 (pip install proofbundle[pq])")
class Mldsa65RootSignatureAlphabets(unittest.TestCase):
    def test_the_root_threshold_counts_both_alphabets(self):
        env = _mldsa_pack()
        for name, (sig, expected) in _forms(env["signatures"][0]["sig"]).items():
            with self.subTest(form=name):
                r = verify_trust_pack(_with(env, "sig", sig), now=NOW)
                self.assertIs(r["root_threshold_met"], expected, r["errors"])
                self.assertIs(r["ok"], expected, r["errors"])


@unittest.skipUnless(_HAS_MLDSA, "this cryptography has no ML-DSA-65 (pip install proofbundle[pq])")
class HybridRootSignatureAlphabets(unittest.TestCase):
    def setUp(self):
        self.env = _hybrid_pack()

    def test_the_intact_hybrid_root_meets_its_threshold(self):
        r = verify_trust_pack(self.env, now=NOW)
        self.assertIs(r["root_threshold_met"], True, r["errors"])

    def test_the_ed25519_leg_counts_in_both_alphabets(self):
        for name, (sig, expected) in _forms(self.env["signatures"][0]["sig"]).items():
            with self.subTest(form=name):
                r = verify_trust_pack(_with(self.env, "sig", sig), now=NOW)
                self.assertIs(r["root_threshold_met"], expected, r["errors"])

    def test_the_pq_leg_sigpq_counts_in_both_alphabets(self):
        for name, (sig_pq, expected) in _forms(self.env["signatures"][0]["sigPq"]).items():
            with self.subTest(form=name):
                r = verify_trust_pack(_with(self.env, "sigPq", sig_pq), now=NOW)
                self.assertIs(r["root_threshold_met"], expected, r["errors"])

    def test_both_legs_url_safe_count(self):
        entry = self.env["signatures"][0]
        env = _with(_with(self.env, "sig", _url(entry["sig"])), "sigPq", _url(entry["sigPq"]))
        r = verify_trust_pack(env, now=NOW)
        self.assertIs(r["root_threshold_met"], True, r["errors"])


if __name__ == "__main__":
    unittest.main()
