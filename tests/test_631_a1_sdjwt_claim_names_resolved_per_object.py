"""A1 of the class search for 6.3.1 at f6ea5cc3: a claim name stands once in each object of an SD-JWT.

`_collect_committed_digests` collected the commitments over the whole payload and `verify_sd_jwt` checked that
every presented disclosure is committed, never that the names land once in their object. Two disclosures
``[salt0, "passed", false]`` and ``[salt1, "passed", true]``, both committed in the signed ``_sd``, verified
``ok=True`` in either order, with and without a key binding, and `verify_bundle` with external anchors did as
well; a disclosure beside a claim in clear with the same name is the same class. A reader that merges the
disclosures reads ``passed`` from whichever comes last.

The disclosures are now placed in the object or array the signed payload refers to them from, and a name that
stands twice in one object makes the structure verdict, and with it the profile and bundle verdicts, False.
Every form here comes from the report's contract tests: the test seed ``bytes(range(32))``, the policy, the
generic bundle payload ``{"generic":"vc"}`` with its one-leaf root.
"""
from __future__ import annotations

import base64
import hashlib
import json
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import emit_bundle, verify_bundle
from proofbundle.sdjwt import verify_sd_jwt
from proofbundle.sdjwt_issue import present_with_key_binding
from proofbundle.sdjwt_vc import verify_sdjwt_vc

VCT = "https://b7n0de.com/vct/eval-credential/v1"
AUD, NONCE, IAT = "verifier.example", "n-1", 1_700_000_000
ISSUER = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
HOLDER = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
OTHER = Ed25519PrivateKey.from_private_bytes(bytes(range(64, 96)))
GENERIC_PAYLOAD = b'{"generic":"vc"}'


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _raw(key) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _disclosure(*array) -> tuple[str, str]:
    """(disclosure, digest) for one JSON array, the digest over the ASCII of the encoded disclosure."""
    encoded = _b64url(json.dumps(list(array)).encode("utf-8"))
    return encoded, _b64url(hashlib.sha256(encoded.encode("ascii")).digest())


PASSED_FALSE = _disclosure("c2FsdDA", "passed", False)
PASSED_TRUE = _disclosure("c2FsdDE", "passed", True)


def _compact(payload: dict, disclosures, *, holder: bool = False, signer=ISSUER) -> str:
    """An issuer-signed compact SD-JWT over ``payload`` with ``disclosures`` presented in the given order."""
    body = {"vct": VCT, **payload}
    if holder:
        body["cnf"] = {"jwk": {"kty": "OKP", "crv": "Ed25519", "x": _b64url(_raw(HOLDER))}}
    header = {"alg": "EdDSA", "typ": "dc+sd-jwt"}
    signing_input = _b64url(json.dumps(header).encode()) + "." + _b64url(json.dumps(body).encode())
    jwt = signing_input + "." + _b64url(signer.sign(signing_input.encode("ascii")))
    return jwt + "~" + "".join(d + "~" for d in disclosures)


def _two_passed(order, *, holder: bool = False) -> str:
    return _compact({"_sd": [PASSED_FALSE[1], PASSED_TRUE[1]], "_sd_alg": "sha-256"},
                    [d for d, _ in order], holder=holder)


BOTH_ORDERS = ((PASSED_FALSE, PASSED_TRUE), (PASSED_TRUE, PASSED_FALSE))
NO_BINDING = {"vctAllowlist": [VCT], "requireKeyBinding": False}


def _bundle(presented: str) -> dict:
    vc = {"compact": presented, "issuer_public_key_b64": base64.b64encode(_raw(ISSUER)).decode("ascii")}
    return emit_bundle(GENERIC_PAYLOAD, ISSUER, sd_jwt_vc=vc)


def _verify_bundle_with_anchors(bundle: dict):
    root = base64.b64encode(hashlib.sha256(b"\x00" + GENERIC_PAYLOAD).digest()).decode("ascii")
    pin = "ed25519:" + base64.b64encode(_raw(ISSUER)).decode("ascii")
    return verify_bundle(bundle, expected_root_b64=root, expected_tree_size=1, sd_jwt_issuer_key_pin=pin,
                         expected_aud=AUD, expected_nonce=NONCE)


class TwoDisclosuresNamingOneClaim(unittest.TestCase):
    """The report's contract test: both orders refused, the issuer signature itself stays valid."""

    def test_refused_in_either_order_without_a_key_binding(self):
        for order in BOTH_ORDERS:
            with self.subTest(first=json.loads(base64.urlsafe_b64decode(order[0][0] + "==").decode())[2]):
                r = verify_sdjwt_vc(_two_passed(order), NO_BINDING, issuer_pubkey=_raw(ISSUER))
                self.assertIs(r["ok"], False)
                self.assertIs(r["issuer"]["sig_ok"], True)
                self.assertIs(r["issuer"]["structure_ok"], False)
                self.assertIn("stands twice in one object", r["issuer"]["detail"])

    def test_refused_in_either_order_with_the_key_binding_required_by_default(self):
        for order in BOTH_ORDERS:
            with self.subTest(order=[d[1][:8] for d in order]):
                presented = present_with_key_binding(_two_passed(order, holder=True), HOLDER,
                                                     aud=AUD, nonce=NONCE, iat=IAT)
                r = verify_sdjwt_vc(presented, {"vctAllowlist": [VCT]}, issuer_pubkey=_raw(ISSUER),
                                    expected_aud=AUD, expected_nonce=NONCE)
                self.assertIs(r["binding"]["ok"], True)
                self.assertIs(r["issuer"]["structure_ok"], False)
                self.assertIs(r["ok"], False)

    def test_refused_on_the_bundle_path_with_external_anchors(self):
        for order in BOTH_ORDERS:
            with self.subTest(order=[d[1][:8] for d in order]):
                presented = present_with_key_binding(_two_passed(order, holder=True), HOLDER,
                                                     aud=AUD, nonce=NONCE, iat=IAT)
                r = _verify_bundle_with_anchors(_bundle(presented))
                checks = {c.name: c.ok for c in r.checks}
                self.assertIs(checks["sd-jwt-disclosures"], False)
                self.assertIs(checks["sd-jwt-issuer-signature"], True)
                self.assertIs(r.ok, False)

    def test_a_disclosure_beside_a_claim_in_clear_with_the_same_name_is_refused(self):
        compact = _compact({"passed": False, "_sd": [PASSED_TRUE[1]], "_sd_alg": "sha-256"}, [PASSED_TRUE[0]])
        r = verify_sdjwt_vc(compact, NO_BINDING, issuer_pubkey=_raw(ISSUER))
        self.assertIs(r["issuer"]["structure_ok"], False)
        self.assertIs(r["ok"], False)


class ControlsOfTheReport(unittest.TestCase):
    """What must keep verifying, and the two refusals the report checked beside it."""

    def test_one_disclosure_verifies_on_the_profile_and_the_bundle_path(self):
        compact = _compact({"_sd": [PASSED_TRUE[1]], "_sd_alg": "sha-256"}, [PASSED_TRUE[0]], holder=True)
        presented = present_with_key_binding(compact, HOLDER, aud=AUD, nonce=NONCE, iat=IAT)
        r = verify_sdjwt_vc(presented, {"vctAllowlist": [VCT]}, issuer_pubkey=_raw(ISSUER),
                            expected_aud=AUD, expected_nonce=NONCE)
        self.assertIs(r["ok"], True, r)
        self.assertIs(_verify_bundle_with_anchors(_bundle(presented)).ok, True)

    def test_the_same_name_in_two_different_objects_is_two_claims(self):
        compact = _compact({"a": {"_sd": [PASSED_FALSE[1]]}, "b": {"_sd": [PASSED_TRUE[1]]}, "_sd_alg": "sha-256"},
                           [PASSED_TRUE[0], PASSED_FALSE[0]])
        r = verify_sdjwt_vc(compact, NO_BINDING, issuer_pubkey=_raw(ISSUER))
        self.assertIs(r["ok"], True, r)

    def test_a_missing_commitment_still_fails_the_structure(self):
        compact = _compact({"_sd": [PASSED_FALSE[1]], "_sd_alg": "sha-256"}, [PASSED_FALSE[0], PASSED_TRUE[0]])
        r = verify_sdjwt_vc(compact, NO_BINDING, issuer_pubkey=_raw(ISSUER))
        self.assertIs(r["issuer"]["structure_ok"], False)
        self.assertIs(r["ok"], False)

    def test_a_foreign_issuer_anchor_still_fails_the_signature(self):
        compact = _compact({"_sd": [PASSED_TRUE[1]], "_sd_alg": "sha-256"}, [PASSED_TRUE[0]])
        r = verify_sdjwt_vc(compact, NO_BINDING, issuer_pubkey=_raw(OTHER))
        self.assertIs(r["issuer"]["sig_ok"], False)
        self.assertIs(r["ok"], False)


class EachDisclosureHasOnePlaceThatFitsIt(unittest.TestCase):
    """The other branches of the placement: each refusal with a control that verifies."""

    def _structure(self, payload: dict, disclosures) -> dict:
        return verify_sd_jwt(_compact({**payload, "_sd_alg": "sha-256"}, disclosures), _raw(ISSUER))

    def test_an_array_element_disclosure_in_its_array_verifies(self):
        element = _disclosure("c2FsdDI", "x")
        r = self._structure({"items": [{"...": element[1]}, "y"]}, [element[0]])
        self.assertIs(r["structure_ok"], True, r)

    def test_a_disclosure_referred_to_from_two_places_is_refused(self):
        r = self._structure({"a": {"_sd": [PASSED_TRUE[1]]}, "b": {"_sd": [PASSED_TRUE[1]]}}, [PASSED_TRUE[0]])
        self.assertIs(r["structure_ok"], False)
        self.assertIn("two places", r["detail"])

    def test_an_array_element_disclosure_in_an_object_is_refused(self):
        element = _disclosure("c2FsdDI", "x")
        r = self._structure({"_sd": [element[1]]}, [element[0]])
        self.assertIs(r["structure_ok"], False)

    def test_an_object_property_disclosure_as_an_array_element_is_refused(self):
        r = self._structure({"items": [{"...": PASSED_TRUE[1]}]}, [PASSED_TRUE[0]])
        self.assertIs(r["structure_ok"], False)

    def test_a_claim_name_that_is_not_a_string_is_refused(self):
        numbered = _disclosure("c2FsdDM", 1, True)
        r = self._structure({"_sd": [numbered[1]]}, [numbered[0]])
        self.assertIs(r["structure_ok"], False)

    def test_a_disclosure_named_after_the_structure_is_refused(self):
        for name in ("_sd", "..."):
            with self.subTest(name=name):
                structural = _disclosure("c2FsdDQ", name, ["x"])
                r = self._structure({"_sd": [structural[1]]}, [structural[0]])
                self.assertIs(r["structure_ok"], False)


if __name__ == "__main__":
    unittest.main()
