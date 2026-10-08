"""Z309 review round 6a, F4 group 2, at the merged head: a KB-JWT presentation that is fresh or old, under an
issuer that is pinned or not, for a matching or a wrong audience, plus the two data swaps of R6a-1 and R6a-2.

Matrix through verify_bundle (the one evaluation time ``now`` judges the KB-JWT iat, 49b) and evaluate_policy:
only pinned + matching audience + fresh is positive. On that positive cell, a copy with one changed KB-JWT
signature character (R6a-1) and a copy relabelled to a pinned foreign merkle root (R6a-2) must not keep the
policy positive under the old result.
"""
from __future__ import annotations

import base64
import copy
import itertools
import json
import unittest
from datetime import datetime, timezone

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import emit_bundle, generate_signer, verify_bundle
from proofbundle.policy import evaluate_policy
from proofbundle.sdjwt_issue import _b64url, present_with_key_binding

_IAT = 1_780_000_000
_AUD = "v.example"
_NONCE = "n-f4-g2"
_FRESH = _IAT + 10
_OLD = _IAT + 100_000


def _at(posix: int) -> datetime:
    """The same instant for evaluate_policy, which takes its ``now`` as a datetime (verify_bundle takes POSIX)."""
    return datetime.fromtimestamp(posix, tz=timezone.utc)


def _raw_pub(key) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _bundle(content: bytes = b'{"generic":"vc"}'):
    """A generic SD-JWT with a cnf holder key and a KB-JWT for _AUD/_NONCE at _IAT. Returns (bundle, issuer pin)."""
    issuer, holder = generate_signer(), generate_signer()
    payload = {"iss": "https://issuer.example", "vct": "https://issuer.example/vct/v1", "iat": _IAT,
               "cnf": {"jwk": {"kty": "OKP", "crv": "Ed25519", "x": _b64url(_raw_pub(holder))}}}
    header = {"alg": "EdDSA", "typ": "dc+sd-jwt"}
    signing_input = _b64url(json.dumps(header).encode()) + "." + _b64url(json.dumps(payload).encode())
    compact = signing_input + "." + _b64url(issuer.sign(signing_input.encode("ascii"))) + "~"
    presented = present_with_key_binding(compact, holder, aud=_AUD, nonce=_NONCE, iat=_IAT)
    pub_b64 = base64.b64encode(_raw_pub(issuer)).decode("ascii")
    bundle = emit_bundle(content, issuer, sd_jwt_vc={"compact": presented, "issuer_public_key_b64": pub_b64})
    return bundle, "ed25519:" + pub_b64


def _sd_policy(pin, extra=None, *, with_aud: bool = True) -> dict:
    sd = {"require_key_binding_when_cnf_present": True, "require_nonce": True}
    if with_aud:
        sd["expected_aud"] = _AUD
    if pin is not None:
        sd["issuer_key_pin"] = pin
    return {"schema": "proofbundle/trust-policy/v0.2", "policy_id": "z309-f4-g2", "sd_jwt": sd, **(extra or {})}


def _tamper_kb_signature(bundle: dict) -> dict:
    b2 = copy.deepcopy(bundle)
    head, sep, kb = b2["sd_jwt_vc"]["compact"].rpartition("~")
    h, p, s = kb.split(".")
    b2["sd_jwt_vc"]["compact"] = head + sep + h + "." + p + "." + ("A" if s[0] != "A" else "B") + s[1:]
    return b2


class PresentationTimesIssuerTimesAudience(unittest.TestCase):

    def test_every_cell(self):
        bundle, pin = _bundle()
        for pinned, aud, now in itertools.product((True, False), (_AUD, "other.example"), (_FRESH, _OLD)):
            with self.subTest(pinned=pinned, aud=aud, fresh=(now == _FRESH)):
                use_pin = pin if pinned else None
                result = verify_bundle(bundle, expected_aud=aud, expected_nonce=_NONCE,
                                       sd_jwt_issuer_key_pin=use_pin, now=now)
                expected = pinned and aud == _AUD and now == _FRESH
                self.assertIs(result.ok, expected, [(c.name, c.ok, c.detail) for c in result.checks if c.ok is not True])
                out = evaluate_policy(bundle, result, _sd_policy(use_pin), now=_at(now))
                if expected:
                    self.assertIs(out.get("policy_ok"), True, out.get("reason"))
                else:
                    self.assertIsNot(out.get("policy_ok"), True, "only the pinned, matching, fresh cell is positive")


class TheDataSwapsOfR6aOnThePositiveCell(unittest.TestCase):

    def setUp(self):
        self.bundle, self.pin = _bundle()
        self.result = verify_bundle(self.bundle, expected_aud=_AUD, expected_nonce=_NONCE,
                                    sd_jwt_issuer_key_pin=self.pin, now=_FRESH)
        self.assertTrue(self.result.ok, "precondition: the positive cell verifies")

    def test_r6a_1_a_changed_kb_signature_does_not_inherit_the_old_result(self):
        swapped = _tamper_kb_signature(self.bundle)
        # The reviewer's two rules only: expected_aud re-verifies the copy's KB-JWT itself and would hide the case.
        out = evaluate_policy(swapped, self.result, _sd_policy(self.pin, with_aud=False), now=_at(_FRESH))
        self.assertIsNot(out.get("policy_ok"), True, out)
        self.assertFalse(verify_bundle(swapped, expected_aud=_AUD, expected_nonce=_NONCE,
                                       sd_jwt_issuer_key_pin=self.pin, now=_FRESH).ok,
                         "control: a fresh verify of the copy fails")

    def test_r6a_2_a_pinned_foreign_root_does_not_inherit_the_old_result(self):
        foreign, _ = _bundle(b'{"generic":"other"}')
        root = foreign["merkle"]["root_b64"]
        self.assertNotEqual(root, self.bundle["merkle"]["root_b64"], "precondition: a different payload, a different root")
        swapped = copy.deepcopy(self.bundle)
        swapped["merkle"]["root_b64"] = root
        out = evaluate_policy(swapped, self.result, _sd_policy(self.pin, {"merkle": {"trusted_roots": [root]}}),
                              now=_at(_FRESH))
        self.assertIsNot(out.get("policy_ok"), True, out)
        self.assertIsNot(out.get("root_authenticated"), True)

    def test_control_the_own_root_pinned_stays_positive(self):
        root = self.bundle["merkle"]["root_b64"]
        out = evaluate_policy(self.bundle, self.result, _sd_policy(self.pin, {"merkle": {"trusted_roots": [root]}}),
                              now=_at(_FRESH))
        self.assertIs(out.get("policy_ok"), True, out.get("reason"))
        self.assertIs(out.get("root_authenticated"), True)


if __name__ == "__main__":
    unittest.main()
