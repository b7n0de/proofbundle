"""6.2.1 T2-2: check_vc_profile reads the issuer JWS header and must apply RFC 7515 §4.1.11 to it.

PROPERTY: a protected header that names a critical extension proofbundle does not understand makes the
JWS invalid, on every surface that reads that header and returns a verdict. Measured at 419e07f2:
`check_vc_profile` returns ok=True for `crit: ["future"]` and for every malformed `crit` form, and
`verify_sdjwt_vc` returns ok=True with that header when the issuer signature is opted out (with and
without key binding). The full path with the issuer signature already fails closed (control below),
because `sdjwt.verify_sd_jwt` applies `_reject_jws_crit`.
"""
from __future__ import annotations

import base64
import json

import pytest

from proofbundle.emit import generate_signer
from proofbundle.sdjwt_issue import issue_sd_jwt, present_with_key_binding
from proofbundle.sdjwt_vc import SD_JWT_VC_TYP, check_vc_profile, verify_sdjwt_vc

from test_sdjwt_vc import _AUD, _IAT, _NONCE, _VCT, _b64url, _claim, _raw_pub

POLICY = {"vctAllowlist": [_VCT]}
OPT_OUT = {"vctAllowlist": [_VCT], "requireIssuerSignature": False, "requireKeyBinding": False}

CRIT_FORMS = {
    "well_formed": {"crit": ["future"], "future": 1},
    "empty": {"crit": [], "future": 1},
    "not_array": {"crit": "future", "future": 1},
    "base_spec": {"crit": ["alg"]},
    "absent_param": {"crit": ["absent"]},
    "duplicate": {"crit": ["future", "future"], "future": 1},
}


def _hand(extra: dict) -> str:
    header = {"alg": "EdDSA", "typ": SD_JWT_VC_TYP, **extra}
    return (_b64url(json.dumps(header).encode()) + "." + _b64url(json.dumps({"vct": _VCT}).encode())
            + "." + _b64url(b"sig") + "~")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _resigned(extra: dict):
    """A real issued credential whose issuer header gains `extra`, re-signed by the same issuer, then
    presented with a fresh KB-JWT (sd_hash covers the new issuer JWT)."""
    issuer, holder = generate_signer(), generate_signer()
    compact = issue_sd_jwt(_claim(issuer), issuer, root_b64="cm9vdA==", exact_score="0.9",
                           holder_public_key=_raw_pub(holder), vct=_VCT)
    jwt, rest = compact.split("~", 1)
    h, p, _ = jwt.split(".")
    header = json.loads(_b64d(h))
    header.update(extra)
    h2 = _b64url(json.dumps(header, separators=(",", ":")).encode())
    sig = issuer.sign(f"{h2}.{p}".encode("ascii"))
    presented = present_with_key_binding(f"{h2}.{p}.{_b64url(sig)}~{rest}", holder,
                                         aud=_AUD, nonce=_NONCE, iat=_IAT)
    return presented, issuer, holder


@pytest.mark.parametrize("form", sorted(CRIT_FORMS))
def test_check_vc_profile_rejects_crit(form):
    r = check_vc_profile(_hand(CRIT_FORMS[form]), POLICY)
    assert r["ok"] is False, r
    assert any("crit" in e for e in r["errors"]), r["errors"]


def test_issuer_opt_out_without_binding_rejects_crit():
    assert verify_sdjwt_vc(_hand(CRIT_FORMS["well_formed"]), OPT_OUT)["ok"] is False


def test_issuer_opt_out_with_binding_rejects_crit():
    presented, _, holder = _resigned(CRIT_FORMS["well_formed"])
    r = verify_sdjwt_vc(presented, {"vctAllowlist": [_VCT], "requireIssuerSignature": False},
                        holder_pubkey=_raw_pub(holder), expected_aud=_AUD, expected_nonce=_NONCE)
    assert r["ok"] is False, r
    assert r["profile"]["ok"] is False


def test_control_full_path_already_fails_closed_on_crit():
    presented, issuer, holder = _resigned(CRIT_FORMS["well_formed"])
    r = verify_sdjwt_vc(presented, POLICY, issuer_pubkey=_raw_pub(issuer), holder_pubkey=_raw_pub(holder),
                        expected_aud=_AUD, expected_nonce=_NONCE)
    assert r["ok"] is False
    assert r["issuer"]["sig_ok"] is False


def test_control_no_crit_profile_ok():
    assert check_vc_profile(_hand({}), POLICY)["ok"] is True
    assert verify_sdjwt_vc(_hand({}), OPT_OUT)["ok"] is True


def test_control_no_crit_full_path_ok():
    presented, issuer, holder = _resigned({})
    r = verify_sdjwt_vc(presented, POLICY, issuer_pubkey=_raw_pub(issuer), holder_pubkey=_raw_pub(holder),
                        expected_aud=_AUD, expected_nonce=_NONCE)
    assert r["ok"] is True, r
