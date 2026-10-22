"""A disclosure the signed payload commits only from where no disclosure can stand has no place, and is refused.

Measured on main 07b6122c with the disclosure differential of pull request 373 (`tools/pb_verify_rs/crosscheck.py`,
`_disclosure_bundle_differential`): two of its 46 vectors verified in Python with exit 0 while the vector pins 1 and
the Rust verifier refused them, "marker with an extra member" (``{"...": digest, "x": 1}`` in an array) and "a marker
inside an _sd that is not an array" (``{"_sd": {"x": [{"...": digest}]}}``). `_collect_committed_digests` counts the
digest as committed wherever a ``...`` member stands, and `_placement_problem` places a disclosure only at an
``_sd`` array or at an array element that is exactly ``{"...": digest}``, so such a disclosure was committed, never
placed, and nothing refused it. RFC 9901 section 7.1 gives a disclosure those two places only.

The control: the same array element without the extra member verifies.
"""
from __future__ import annotations

import base64
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle.sdjwt import verify_sd_jwt
from proofbundle.sdjwt_vc import verify_sdjwt_vc

VCT = "https://b7n0de.com/vct/eval-credential/v1"
POLICY = {"vctAllowlist": [VCT], "requireKeyBinding": False}
ISSUER = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))          # the repository's test seed


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _raw(key) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _disclosure(*items) -> tuple[str, str]:
    encoded = _b64url(json.dumps(list(items)).encode())
    return encoded, _b64url(hashlib.sha256(encoded.encode("ascii")).digest())


def _compact(payload: dict, disclosures: list[str]) -> str:
    header = {"alg": "EdDSA", "typ": "dc+sd-jwt"}
    signing_input = _b64url(json.dumps(header).encode()) + "." + _b64url(json.dumps(payload).encode())
    return signing_input + "." + _b64url(ISSUER.sign(signing_input.encode("ascii"))) + "~" + \
        "".join(d + "~" for d in disclosures)


ELEMENT = _disclosure("c2FsdDI", "an element")


def _verdicts(where: dict) -> tuple[dict, dict]:
    compact = _compact({"vct": VCT, "_sd_alg": "sha-256", **where}, [ELEMENT[0]])
    return verify_sd_jwt(compact, issuer_pubkey=_raw(ISSUER)), verify_sdjwt_vc(compact, POLICY,
                                                                               issuer_pubkey=_raw(ISSUER))


def test_a_marker_with_an_extra_member_gives_its_disclosure_no_place():
    sd, vc = _verdicts({"list": [{"...": ELEMENT[1], "x": 1}]})
    assert sd["sig_ok"] is True and sd["structure_ok"] is False, sd
    assert "no disclosure can stand" in sd["detail"], sd["detail"]
    assert vc["ok"] is False, vc


def test_a_marker_inside_an_sd_that_is_not_an_array_gives_its_disclosure_no_place():
    sd, vc = _verdicts({"obj": {"_sd": {"x": [{"...": ELEMENT[1]}]}}})
    assert sd["sig_ok"] is True and sd["structure_ok"] is False, sd
    assert "no disclosure can stand" in sd["detail"], sd["detail"]
    assert vc["ok"] is False, vc


def test_control_the_same_element_as_a_marker_alone_verifies():
    sd, vc = _verdicts({"list": [{"...": ELEMENT[1]}]})
    assert sd["sig_ok"] is True and sd["structure_ok"] is True, sd
    assert vc["ok"] is True, vc
