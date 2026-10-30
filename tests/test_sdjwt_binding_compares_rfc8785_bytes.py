"""OQ-22 (owner answer of 2026-10-27): sd-jwt-bundle-binding binds a field only when it stands on both sides and the
RFC 8785 bytes of both values are equal.

Before this, check_binds_bundle compared passed, threshold, comparator, suite and issuer with Python's `!=`: an SD-JWT
carrying `passed: 1` bound to a claim with `passed: true` (and `0` to `false`), and an SD-JWT without `issuer` bound to a
claim whose `issuer` is `null`, because an absent field was read as None. `1` and `1.0` stay one value, as RFC 8785
writes both `1`; `"0.5"` and `0.5` stay two.

check_binds_bundle reads only the issuer-signed payload of the compact (the part before the first `~`); the issuer
signature is checked by verify_bundle before it. Each case therefore hands it a compact whose payload is built here.
"""
import base64
import copy
import json

import pytest

from proofbundle.sdjwt_issue import check_binds_bundle

ROOT = base64.b64encode(b"\x07" * 32).decode()
CLAIM = {"schema": "proofbundle/eval-claim/v0.1", "passed": True, "threshold": "0.5", "comparator": ">=", "suite": "s",
         "issuer": "ed25519:abc", "metric": "accuracy"}
SD = {"passed": True, "threshold": "0.5", "comparator": ">=", "suite": "s", "issuer": "ed25519:abc",
      "receipt": {"root_b64": ROOT}, "_sd": [], "_sd_alg": "sha-256"}
ABSENT = object()


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _compact(payload: dict) -> str:
    head = _b64u(json.dumps({"alg": "EdDSA", "typ": "vc+sd-jwt"}).encode())
    return f"{head}.{_b64u(json.dumps(payload).encode())}.{_b64u(b'sig')}~"


def _with(d: dict, **members) -> dict:
    d = copy.deepcopy(d)
    for k, v in members.items():
        if v is ABSENT:
            d.pop(k, None)
        else:
            d[k] = v
    return d


NOT_BOUND_ANY_MORE = {
    "passed 1 against true": (_with(SD, passed=1), CLAIM),
    "passed 0 against false": (_with(SD, passed=0), _with(CLAIM, passed=False)),
    "passed true against 1": (SD, _with(CLAIM, passed=1)),
    "issuer absent against null": (_with(SD, issuer=ABSENT), _with(CLAIM, issuer=None)),
    "suite absent against null": (_with(SD, suite=ABSENT), _with(CLAIM, suite=None)),
}

STILL_BOUND = {
    "equal": (SD, CLAIM),
    "threshold 1 against 1.0": (_with(SD, threshold=1.0), _with(CLAIM, threshold=1)),
    "issuer null on both sides": (_with(SD, issuer=None), _with(CLAIM, issuer=None)),
}

STILL_NOT_BOUND = {
    "threshold \"0.5\" against 0.5": (_with(SD, threshold=0.5), CLAIM),
    "threshold \"0.5\" against \"0.50\"": (_with(SD, threshold="0.50"), CLAIM),
    "suite absent in the claim": (SD, _with(CLAIM, suite=ABSENT)),
    "suite absent on both sides": (_with(SD, suite=ABSENT), _with(CLAIM, suite=ABSENT)),
    "another root": (_with(SD, receipt={"root_b64": base64.b64encode(b"\x08" * 32).decode()}), CLAIM),
}


@pytest.mark.parametrize("case", sorted(NOT_BOUND_ANY_MORE))
def test_a_field_binds_only_by_equal_rfc8785_bytes_on_both_sides(case):
    sd, claim = NOT_BOUND_ANY_MORE[case]
    assert check_binds_bundle(_compact(sd), claim, ROOT) is False


@pytest.mark.parametrize("case", sorted(STILL_BOUND))
def test_control_equal_bytes_still_bind(case):
    sd, claim = STILL_BOUND[case]
    assert check_binds_bundle(_compact(sd), claim, ROOT) is True


@pytest.mark.parametrize("case", sorted(STILL_NOT_BOUND))
def test_control_what_did_not_bind_still_does_not(case):
    sd, claim = STILL_NOT_BOUND[case]
    assert check_binds_bundle(_compact(sd), claim, ROOT) is False
